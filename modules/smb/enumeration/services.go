package enumeration

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	svcctl "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/367abb81-9844-35f1-ad32-98f038001003/2.0"
	svcctlfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/367abb81-9844-35f1-ad32-98f038001003/2.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type ServiceEntry struct {
	Name        string
	DisplayName string
	State       string
	BinaryPath  string
	Account     string
	StartType   string
}

// EnumServices lists services via MS-SCMR (svcctl). filter accepts "running", "stopped", or "" for all.
func EnumServices(session *gofenrirsmb.Session, filter string) ([]ServiceEntry, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(svcctl.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open svcctl pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(svcctl.SyntaxID()); err != nil {
		return nil, fmt.Errorf("svcctl bind: %w", err)
	}
	defer rpc.Close()

	scm, err := svcctlfunctions.ROpenSCManagerW(rpc, nil, nil,
		ndr.DWORD(svcctl.ScManagerConnect|svcctl.ScManagerEnumerateService))
	if err != nil {
		return nil, fmt.Errorf("ROpenSCManagerW: %w", err)
	}
	defer svcctlfunctions.RCloseServiceHandle(rpc, scm)

	serviceTypeMask := ndr.DWORD(svcctl.ServiceWin32OwnProcess | svcctl.ServiceWin32ShareProcess)
	stateFilter := ndr.DWORD(svcctl.ServiceStateAll)

	// probe buffer size
	_, pcb, _, _, _ := svcctlfunctions.REnumServicesStatusW(rpc, scm, serviceTypeMask, stateFilter, 0, nil)
	bufSize := uint32(pcb)
	if bufSize == 0 {
		bufSize = 65536
	}

	buf, _, lpCount, _, err := svcctlfunctions.REnumServicesStatusW(rpc, scm, serviceTypeMask, stateFilter,
		ndr.DWORD(bufSize), nil)
	if err != nil {
		return nil, fmt.Errorf("REnumServicesStatusW: %w", err)
	}

	count := uint32(lpCount)
	svcNames, svcDisplays, svcStates := parseEnumServiceStatusW(buf, count)

	var entries []ServiceEntry
	for i := uint32(0); i < count; i++ {
		state := serviceStateName(svcStates[i])

		if filter == "running" && svcStates[i] != svcctl.ServiceRunning {
			continue
		}
		if filter == "stopped" && svcStates[i] != svcctl.ServiceStopped {
			continue
		}

		entry := ServiceEntry{
			Name:        svcNames[i],
			DisplayName: svcDisplays[i],
			State:       state,
		}

		svcHandle, openErr := svcctlfunctions.ROpenServiceW(rpc, scm,
			ndr.WSTR(svcNames[i]),
			ndr.DWORD(svcctl.ServiceQueryConfig))
		if openErr == nil {
			cfg, _, cfgErr := svcctlfunctions.RQueryServiceConfigW(rpc, svcHandle, 8192)
			if cfgErr == nil {
				if cfg.LpBinaryPathName != nil {
					entry.BinaryPath = string(*cfg.LpBinaryPathName)
				}
				if cfg.LpServiceStartName != nil {
					entry.Account = string(*cfg.LpServiceStartName)
				}
				entry.StartType = startTypeName(uint32(cfg.DwStartType))
			}
			svcctlfunctions.RCloseServiceHandle(rpc, svcHandle)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// enumEntrySize is the flat-buffer size of one ENUM_SERVICE_STATUSW entry in NDR32:
// 4 (nameOffset) + 4 (displayOffset) + 7*4 (SERVICE_STATUS fields) = 36 bytes.
const enumEntrySize = 36

// parseEnumServiceStatusW decodes the flat buffer returned by REnumServicesStatusW.
// Offsets inside each entry point into the same buffer (relative to its start).
func parseEnumServiceStatusW(buf []byte, count uint32) (names, displays []string, states []uint32) {
	names = make([]string, count)
	displays = make([]string, count)
	states = make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		base := i * enumEntrySize
		if int(base+enumEntrySize) > len(buf) {
			break
		}
		nameOff := binary.LittleEndian.Uint32(buf[base:])
		dispOff := binary.LittleEndian.Uint32(buf[base+4:])
		// DwCurrentState is the 2nd field of SERVICE_STATUS (offset 4), SERVICE_STATUS starts at base+8
		states[i] = binary.LittleEndian.Uint32(buf[base+12:])
		names[i] = readUTF16LE(buf, nameOff)
		displays[i] = readUTF16LE(buf, dispOff)
	}
	return
}

func readUTF16LE(buf []byte, off uint32) string {
	if int(off) >= len(buf) {
		return ""
	}
	var r []uint16
	for i := off; int(i+1) < len(buf); i += 2 {
		c := uint16(buf[i]) | uint16(buf[i+1])<<8
		if c == 0 {
			break
		}
		r = append(r, c)
	}
	return string(utf16.Decode(r))
}

func serviceStateName(state uint32) string {
	switch state {
	case svcctl.ServiceStopped:
		return "Stopped"
	case svcctl.ServiceStartPending:
		return "StartPending"
	case svcctl.ServiceStopPending:
		return "StopPending"
	case svcctl.ServiceRunning:
		return "Running"
	case svcctl.ServiceContinuePending:
		return "ContinuePending"
	case svcctl.ServicePausePending:
		return "PausePending"
	case svcctl.ServicePaused:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func startTypeName(t uint32) string {
	switch t {
	case svcctl.ServiceBootStart:
		return "Boot"
	case svcctl.ServiceSystemStart:
		return "System"
	case svcctl.ServiceAutoStart:
		return "Auto"
	case svcctl.ServiceDemandStart:
		return "Manual"
	case svcctl.ServiceDisabled:
		return "Disabled"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}
