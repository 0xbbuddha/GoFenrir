package exec

import (
	"fmt"
	"strings"
	"time"

	tsch "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/86d35949-83c9-4044-b424-db363231fd0c/1.0"
	tschfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/86d35949-83c9-4044-b424-db363231fd0c/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

const (
	// taskCreate is TASK_CREATE (register a new task).
	taskCreate = 0x2
	// taskLogonNone registers the task without stored credentials; it runs as the
	// principal declared in the XML (S-1-5-18, LocalSystem).
	taskLogonNone = 0x0
)

// AtExec runs cmd on the remote host via the Task Scheduler (MS-TSCH / atexec).
// It registers a transient scheduled task running as SYSTEM that writes command
// output to C$\Windows\Temp\<random>.tmp, triggers it, reads the output, then
// deletes the task and the file. It is an alternative to smbexec (Exec) that does
// not create a Windows service. Returns the command output.
func AtExec(session *gofenrirsmb.Session, cmd string) (string, error) {
	taskName := randomName("GF")
	taskPath := `\` + taskName
	outFile := randomName("gf") + ".tmp"
	outPath := `C:\Windows\Temp\` + outFile

	command := fmt.Sprintf(`/C %s > %s 2>&1`, cmd, outPath)
	xml := taskXML("cmd.exe", command)

	if err := session.TreeConnect("IPC$"); err != nil {
		return "", fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(`\atsvc`)
	if err != nil {
		return "", fmt.Errorf("open atsvc pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(tsch.SyntaxID()); err != nil {
		rpc.Close()
		return "", fmt.Errorf("tsch bind: %w", err)
	}
	defer rpc.Close()

	// Register the task.
	pathArg := ndr.WSTR(taskPath)
	if _, _, err := tschfunctions.SchRpcRegisterTask(rpc, &pathArg, ndr.WSTR(xml),
		ndr.DWORD(taskCreate), nil, ndr.DWORD(taskLogonNone), 0, nil); err != nil {
		return "", fmt.Errorf("SchRpcRegisterTask: %w", err)
	}

	// Run it on demand.
	if _, err := tschfunctions.SchRpcRun(rpc, ndr.WSTR(taskPath), 0, nil, 0, 0, nil); err != nil {
		_ = tschfunctions.SchRpcDelete(rpc, ndr.WSTR(taskPath), 0)
		return "", fmt.Errorf("SchRpcRun: %w", err)
	}

	// Wait for it to complete (up to 10s), then always delete the task.
	waitForTask(rpc, taskPath, 10*time.Second)
	_ = tschfunctions.SchRpcDelete(rpc, ndr.WSTR(taskPath), 0)

	output, readErr := readOutputFile(session, `Windows\Temp\`+outFile)
	_ = deleteOutputFile(session, `Windows\Temp\`+outFile)
	if readErr != nil {
		return "", fmt.Errorf("read output: %w", readErr)
	}
	return output, nil
}

// waitForTask polls SchRpcGetLastRunInfo until the task has run (a non-zero last
// runtime) or the deadline elapses.
func waitForTask(rpc *dcerpcclient.Client, taskPath string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rt, _, err := tschfunctions.SchRpcGetLastRunInfo(rpc, ndr.WSTR(taskPath)); err == nil {
			if rt.WYear != 0 { // task has executed at least once
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// taskXML builds a Task Scheduler 1.2 definition that runs command as LocalSystem
// on demand.
func taskXML(program, arguments string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers></Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>` + xmlEscape(program) + `</Command>
      <Arguments>` + xmlEscape(arguments) + `</Arguments>
    </Exec>
  </Actions>
</Task>`
}

// xmlEscape escapes the five XML predefined entities in text.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
