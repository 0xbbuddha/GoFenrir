package enumeration

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/dcerpc/dtyp"
	winreg "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0"
	winregfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0/functions"
	winregstructs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// LSASettings holds security-relevant registry values from LSA and related keys.
type LSASettings struct {
	RunAsPPL            *uint32 // HKLM\SYSTEM\...\Lsa -> RunAsPPL
	LmCompatLevel       *uint32 // HKLM\SYSTEM\...\Lsa -> LmCompatibilityLevel
	NoLMHash            *uint32 // HKLM\SYSTEM\...\Lsa -> NoLMHash
	RestrictAnonymous   *uint32 // HKLM\SYSTEM\...\Lsa -> RestrictAnonymous
	RestrictAnonymousSAM *uint32 // HKLM\SYSTEM\...\Lsa -> RestrictAnonymousSAM
	WDigestEnabled      *uint32 // HKLM\SYSTEM\...\WDigest -> UseLogonCredential
}

const (
	lsaKey     = `SYSTEM\CurrentControlSet\Control\Lsa`
	wdigestKey = `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
)

// GetLSASettings reads LSA and WDigest security settings from the registry via MS-RRP.
func GetLSASettings(session *gofenrirsmb.Session) (*LSASettings, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(winreg.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open winreg pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(winreg.SyntaxID()); err != nil {
		return nil, fmt.Errorf("winreg bind: %w", err)
	}
	defer rpc.Close()

	hklm, err := winregfunctions.OpenLocalMachine(rpc, nil, ndr.DWORD(winreg.KeyRead))
	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine: %w", err)
	}
	defer winregfunctions.BaseRegCloseKey(rpc, hklm)

	result := &LSASettings{}

	// Read HKLM\SYSTEM\CurrentControlSet\Control\Lsa
	if hkey, err := openKey(rpc, hklm, lsaKey); err == nil {
		defer winregfunctions.BaseRegCloseKey(rpc, hkey)
		result.RunAsPPL = queryDWORD(rpc, hkey, "RunAsPPL")
		result.LmCompatLevel = queryDWORD(rpc, hkey, "LmCompatibilityLevel")
		result.NoLMHash = queryDWORD(rpc, hkey, "NoLMHash")
		result.RestrictAnonymous = queryDWORD(rpc, hkey, "RestrictAnonymous")
		result.RestrictAnonymousSAM = queryDWORD(rpc, hkey, "RestrictAnonymousSAM")
	}

	// Read HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
	if hkey, err := openKey(rpc, hklm, wdigestKey); err == nil {
		defer winregfunctions.BaseRegCloseKey(rpc, hkey)
		result.WDigestEnabled = queryDWORD(rpc, hkey, "UseLogonCredential")
	}

	return result, nil
}

// LmCompatLevelString returns a human-readable description of the LmCompatibilityLevel.
func LmCompatLevelString(level uint32) string {
	switch level {
	case 0:
		return "0 (LM+NTLM, no extended session security)"
	case 1:
		return "1 (LM+NTLM with extended session security if negotiated)"
	case 2:
		return "2 (NTLM only)"
	case 3:
		return "3 (NTLMv2 only)"
	case 4:
		return "4 (NTLMv2 only, refuse LM)"
	case 5:
		return "5 (NTLMv2 only, refuse LM+NTLM)"
	default:
		return fmt.Sprintf("%d", level)
	}
}

func openKey(rpc *dcerpcclient.Client, parent winregstructs.RPC_HKEY, path string) (winregstructs.RPC_HKEY, error) {
	return winregfunctions.BaseRegOpenKey(rpc, parent,
		dtyp.NewUnicodeString(path+"\x00"),
		0, ndr.DWORD(winreg.KeyRead))
}

func queryDWORD(rpc *dcerpcclient.Client, hkey winregstructs.RPC_HKEY, name string) *uint32 {
	dataType := ndr.DWORD(0)
	bufSize := ndr.DWORD(4)
	buf := make([]uint8, 4)
	dataLen := ndr.DWORD(0)

	_, data, lpcbData, _, err := winregfunctions.BaseRegQueryValue(
		rpc, hkey,
		dtyp.NewUnicodeString(name+"\x00"),
		&dataType, buf, &bufSize, &dataLen,
	)
	if err != nil {
		return nil
	}

	n := 4
	if lpcbData != nil && int(*lpcbData) < n {
		n = int(*lpcbData)
	}
	if len(data) < 4 {
		return nil
	}
	v := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	return &v
}
