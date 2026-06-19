package exec

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	svcctl "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/367abb81-9844-35f1-ad32-98f038001003/2.0"
	svcctlfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/367abb81-9844-35f1-ad32-98f038001003/2.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/windows/fileflags"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// Exec runs cmd on the remote host via smbexec (MS-SCMR service + C$ file read).
// It creates a temporary service, starts it to run cmd.exe, reads the output from
// C$\Windows\Temp\<random>.tmp, then cleans up the service and the file.
// Returns the command output as a string.
func Exec(session *gofenrirsmb.Session, cmd string) (string, error) {
	svcName := randomName("GF")
	outFile := randomName("gf") + ".tmp"
	outPath := `C:\Windows\Temp\` + outFile

	binaryPath := fmt.Sprintf(`%%COMSPEC%% /Q /c %s 1> %s 2>&1`, cmd, outPath)

	if err := execViaService(session, svcName, binaryPath); err != nil {
		return "", err
	}

	// Give the service a moment to run and write output.
	time.Sleep(1 * time.Second)

	output, readErr := readOutputFile(session, `Windows\Temp\`+outFile)

	// Always attempt cleanup; don't let a read error suppress it.
	_ = deleteOutputFile(session, `Windows\Temp\`+outFile)

	if readErr != nil {
		return "", fmt.Errorf("read output: %w", readErr)
	}
	return output, nil
}

// execViaService creates a transient Windows service, starts it, waits for it to
// stop (or timeout), then deletes it. The service binary path is binaryPath which
// should invoke cmd.exe and redirect output to a file.
func execViaService(session *gofenrirsmb.Session, svcName, binaryPath string) error {
	if err := session.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(svcctl.PipeName)
	if err != nil {
		return fmt.Errorf("open svcctl pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(svcctl.SyntaxID()); err != nil {
		rpc.Close()
		return fmt.Errorf("svcctl bind: %w", err)
	}
	defer rpc.Close()

	scm, err := svcctlfunctions.ROpenSCManagerW(rpc, nil, nil,
		ndr.DWORD(svcctl.ScManagerAllAccess))
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer svcctlfunctions.RCloseServiceHandle(rpc, scm)

	displayName := ndr.WSTR(svcName)
	_, hSvc, err := svcctlfunctions.RCreateServiceW(rpc, scm,
		ndr.WSTR(svcName), &displayName,
		ndr.DWORD(svcctl.ServiceAllAccess),
		ndr.DWORD(svcctl.ServiceWin32OwnProcess),
		ndr.DWORD(svcctl.ServiceDemandStart),
		ndr.DWORD(svcctl.ServiceErrorIgnore),
		ndr.WSTR(binaryPath),
		nil, nil,
		[]uint8{}, 0,
		nil, []uint8{}, 0,
	)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}

	startErr := svcctlfunctions.RStartServiceW(rpc, hSvc, 0, nil)
	if startErr != nil && !strings.Contains(startErr.Error(), "1053") {
		// 1053 = ERROR_SERVICE_REQUEST_TIMEOUT: cmd.exe exited before SCM
		// could confirm it's running — this is normal for transient services.
		_ = svcctlfunctions.RDeleteService(rpc, hSvc)
		svcctlfunctions.RCloseServiceHandle(rpc, hSvc)
		return fmt.Errorf("StartService: %w", startErr)
	}

	// Wait up to 10s for the service to stop (cmd finishes and exits).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, pollErr := svcctlfunctions.RQueryServiceStatus(rpc, hSvc)
		if pollErr != nil {
			break
		}
		if uint32(status.DwCurrentState) == svcctl.ServiceStopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	_ = svcctlfunctions.RDeleteService(rpc, hSvc)
	svcctlfunctions.RCloseServiceHandle(rpc, hSvc)
	return nil
}

// readOutputFile reads the command output file from C$\path.
func readOutputFile(session *gofenrirsmb.Session, sharePath string) (string, error) {
	if err := session.Client.TreeConnect("C$"); err != nil {
		return "", fmt.Errorf("C$: %w", err)
	}

	h, err := session.Client.OpenFile(sharePath, smbclient.OpenOptions{
		DesiredAccess:     fileflags.GENERIC_READ,
		ShareAccess:       fileflags.FILE_SHARE_READ | fileflags.FILE_SHARE_WRITE | fileflags.FILE_SHARE_DELETE,
		CreateDisposition: fileflags.FILE_OPEN,
	})
	if err != nil {
		return "", fmt.Errorf("open %s: %w", sharePath, err)
	}
	defer session.Client.CloseFile(h)

	var buf strings.Builder
	var off uint64
	const chunk = 65535
	for {
		data, err := session.Client.ReadFile(h, off, chunk)
		if len(data) > 0 {
			buf.Write(data)
			off += uint64(len(data))
		}
		if err != nil {
			break
		}
		if len(data) < chunk {
			break
		}
	}
	return buf.String(), nil
}

// deleteOutputFile removes the temp output file from C$.
func deleteOutputFile(session *gofenrirsmb.Session, sharePath string) error {
	return session.Client.DeleteFile(sharePath)
}

// randomName returns a random uppercase name with the given prefix (6 random hex chars).
func randomName(prefix string) string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%s%06X", prefix, b)
}
