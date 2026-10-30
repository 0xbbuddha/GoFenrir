package enumeration

import (
	"fmt"
	"path"
	"strings"

	lsarpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0"
	lsafunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/functions"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	msdtyp "github.com/TheManticoreProject/Manticore/windows/ms-dtyp"
	mslsad "github.com/TheManticoreProject/Manticore/windows/protocols/ms-lsad"
	mslsat "github.com/TheManticoreProject/Manticore/windows/protocols/ms-lsat"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// avProducts maps each AV/EDR product to the Windows service names it registers
// and the named pipes its running processes expose. Services are resolved as SIDs
// via LsarLookupNames (no privilege, exact match => INSTALLED); pipes are matched
// against the IPC$ listing (=> RUNNING). Ported from netexec's enum_av, itself
// based on @tothi's serviceDetector. Wildcard-only service names are dropped (they
// cannot resolve via a SID lookup); such products are detected by pipe only.
var avProducts = []struct {
	name     string
	services []string
	pipes    []string
}{
	{"Acronis Cyber Protect", []string{"AcronisActiveProtectionService"}, nil},
	{"Arctic Wolf", []string{"AwWfpService", "ArcticWolfAgentMgr"}, nil},
	{"Avast/AVG", []string{"AvastWscReporter", "aswbIDSAgent", "AVGWscReporter", "avgbIDSAgent"}, []string{"aswCallbackPipe*", "avgCallbackPipe*"}},
	{"Bitdefender", []string{"bdredline_agent", "BDAuxSrv", "UPDATESRV", "VSSERV", "bdredline", "EPRedline", "EPUpdateService", "EPSecurityService", "EPProtectedService", "EPIntegrationService"}, []string{"etw_sensor_pipe_ppl", `local\msgbus\bdagent*`, `local\msgbus\bd.process.broker.pipe`, `local\msgbus\bdauxsrv`}},
	{"Carbon Black App Control", []string{"Parity"}, nil},
	{"Check Point Endpoint", []string{"CPDA", "vsmon", "CPFileAnlyz", "EPClientUIService"}, nil},
	{"Cortex XDR", []string{"xdrhealth", "cyserver"}, nil},
	{"CrowdStrike Falcon", []string{"CSFalconService"}, []string{`CrowdStrike\{*`}},
	{"Cybereason", []string{"CybereasonActiveProbe", "CybereasonCRS", "CybereasonBlocki"}, []string{"CybereasonAPConsoleMinionHostIpc_*", "CybereasonAPServerProxyIpc_*"}},
	{"Cynet", []string{"CynetLauncher"}, nil},
	{"Elastic EDR", []string{"Elastic Agent", "ElasticEndpoint"}, []string{"ElasticEndpointServiceComms-*", "elastic-agent-system"}},
	{"ESET", []string{"ekm", "epfw", "epfwlwf", "epfwwfp", "EraAgentSvc", "ERAAgent", "efwd", "ehttpsrv"}, []string{"nod_scriptmon_pipe"}},
	{"FortiClient", []string{"FA_Scheduler", "FCT_SecSvr"}, []string{"FortiClient_DBLogDaemon", "FC_*"}},
	{"FortiEDR", []string{"FortiEDR Collector Service"}, nil},
	{"G DATA", []string{"AVKWCtl", "AVKProxy", "GDScan"}, []string{"exploitProtectionIPC"}},
	{"HarfangLab EDR", []string{"hurukai", "Hurukai agent", "HarfangLab Hurukai agent", "hurukai-av", "hurukai-ui"}, []string{"hurukai-control", "hurukai-servicing", "hurukai-amsi"}},
	{"Ivanti/Shavlik", []string{"STAgent$Shavlik Protect", "STDispatch$Shavlik Protect"}, nil},
	{"Kaseya Agent", nil, []string{"kaseyaUserKSA*", "kaseyaAgentKSA*"}},
	{"Kaspersky", []string{"kavfsslp", "KAVFS", "KAVFSGT", "klnagent"}, []string{"Exploit_Blocker"}},
	{"Malwarebytes", []string{"MBAMService", "MBEndpointAgent"}, []string{"MBLG", "MBEA2_R", "MBEA2_W"}},
	{"Panda Adaptive Defense 360", []string{"PandaAetherAgent", "PSUAService", "NanoServiceMain"}, []string{"NNS_API_IPC_SRV_ENDPOINT", "PSANMSrvcPpal"}},
	{"Rapid7 Insight", []string{"ir_agent"}, nil},
	{"SentinelOne", []string{"SentinelAgent", "SentinelStaticEngine", "LogProcessorService"}, []string{"SentinelAgentWorkerCert.*", "DFIScanner.Etw.*", "DFIScanner.Inline.*"}},
	{"Sophos Intercept X", []string{"SntpService", "Sophos Endpoint Defense Service", "Sophos File Scanner Service", "Sophos Health Service", "Sophos Live Query", "Sophos Managed Threat Response", "Sophos MCS Agent", "Sophos MCS Client", "Sophos System Protection Service"}, []string{"SophosUI", "SophosEventStore", "sophos_deviceencryption", "sophoslivequery_*"}},
	{"Symantec Endpoint Protection", []string{"SepMasterService", "SepScanService", "SNAC"}, nil},
	{"Trellix/McAfee EDR", []string{"McAfee Endpoint Security Platform Service", "mfemactl", "mfemms", "mfefire", "masvc", "macmnsvc", "mfetp", "mfewc", "mfeaack"}, []string{"TrellixEDR_Pipe_*", "mfemactl_*", "mfefire_*", "McAfeeAgent_Pipe_*", "mfetp_*"}},
	{"Trend Micro", []string{"Trend Micro Endpoint Basecamp", "TMBMServer", "Trend Micro Web Service Communicator", "TMiACAgentSvc", "CETASvc", "iVPAgent", "ds_agent", "ds_monitor", "ds_notifier"}, []string{"IPC_XBC_XBC_AGENT_PIPE_*", "iacagent_*", "OIPC_LWCS_PIPE_*", "Log_ServerNamePipe", "OIPC_NTRTSCAN_PIPE_*"}},
	{"Wazuh", []string{"WazuhSvc"}, nil},
	{"Windows Defender", []string{"WinDefend", "Sense", "WdNisSvc"}, nil},
	{"WithSecure Elements", []string{"fsdevcon", "fshoster", "fsnethoster", "fsulhoster", "fsulnethoster", "fsulprothoster", "wsulavprohoster"}, []string{"FS_CCFIPC_*"}},
}

// AVHit is a detected product and how it was seen.
type AVHit struct {
	Product   string
	Installed bool // a service SID resolved
	Running   bool // a known named pipe is present
}

// Status renders the detection state the way netexec does.
func (h AVHit) Status() string {
	switch {
	case h.Installed && h.Running:
		return "installed + running"
	case h.Running:
		return "running"
	default:
		return "installed"
	}
}

// DetectAV returns the AV/EDR products detected on the host: INSTALLED via
// LsarLookupNames over \lsarpc (no privilege, exact service-name match), and
// RUNNING via the named pipes exposed on IPC$. Pipe enumeration is best-effort:
// if it fails, detection degrades to installed-only. No hit is not proof of
// absence (driver-only products and unlisted names are missed).
func DetectAV(session *gofenrirsmb.Session) ([]AVHit, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	pipes := listIPCPipes(session) // best-effort; nil on failure

	transport, err := session.Client.RPCTransport(lsarpc.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open lsarpc pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(lsarpc.SyntaxID()); err != nil {
		return nil, fmt.Errorf("lsarpc bind: %w", err)
	}
	defer rpc.Close()

	policy, err := lsafunctions.LsarOpenPolicy2(rpc, lsarpc.PolicyLookupNames)
	if err != nil {
		return nil, fmt.Errorf("LsarOpenPolicy2: %w", err)
	}
	defer lsafunctions.LsarClose(rpc, policy)

	var found []AVHit
	for _, p := range avProducts {
		installed := len(p.services) > 0 && anyServiceResolves(rpc, policy, p.services)
		running := pipeMatches(p.pipes, pipes)
		if installed || running {
			found = append(found, AVHit{Product: p.name, Installed: installed, Running: running})
		}
	}
	return found, nil
}

// listIPCPipes returns the named pipes at the IPC$ root (caller must have
// TreeConnect'd IPC$). Best-effort: returns nil on any error.
func listIPCPipes(session *gofenrirsmb.Session) []string {
	entries, err := session.Client.ListDirectory("", "*")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name != "" && e.Name != "." && e.Name != ".." {
			names = append(names, e.Name)
		}
	}
	return names
}

// anyServiceResolves looks up a product's service SIDs in one call and reports
// whether at least one resolved (MappedCount > 0 means that service is registered).
func anyServiceResolves(rpc *dcerpcclient.Client, policy mslsad.LSAPR_HANDLE, services []string) bool {
	names := make([]msdtyp.RPC_UNICODE_STRING, len(services))
	for i, s := range services {
		names[i] = msdtyp.NewUnicodeString(`NT Service\` + s)
	}
	_, _, mapped, err := lsafunctions.LsarLookupNames(rpc, policy, names, mslsat.LsapLookupWksta)
	return err == nil && mapped > 0
}

// pipeMatches reports whether any of a product's pipe patterns matches a listed
// pipe. Backslashes are normalized to '/' so glob '*' does not cross a namespace
// separator; nested patterns (e.g. `CrowdStrike\{*`) also match when only their
// first component appears in the shallow IPC$ listing.
func pipeMatches(patterns, pipes []string) bool {
	for _, pat := range patterns {
		p := strings.ReplaceAll(strings.ToLower(pat), `\`, "/")
		first := p
		if i := strings.IndexByte(p, '/'); i > 0 {
			first = p[:i]
		}
		for _, name := range pipes {
			n := strings.ReplaceAll(strings.ToLower(name), `\`, "/")
			if ok, _ := path.Match(p, n); ok {
				return true
			}
			if first != p {
				if ok, _ := path.Match(first, n); ok {
					return true
				}
			}
		}
	}
	return false
}
