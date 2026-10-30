package enumeration

import (
	"fmt"

	lsarpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0"
	lsafunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/functions"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	msdtyp "github.com/TheManticoreProject/Manticore/windows/ms-dtyp"
	mslsad "github.com/TheManticoreProject/Manticore/windows/protocols/ms-lsad"
	mslsat "github.com/TheManticoreProject/Manticore/windows/protocols/ms-lsat"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// avProducts maps each AV/EDR product to the Windows service names it registers.
// Detection resolves "NT Service\<name>" to a SID via LsarLookupNames, which needs
// no privilege and matches exactly (ported from netexec's enum_av, itself based on
// @tothi's serviceDetector). Wildcard-only service names are dropped (they cannot
// resolve via a SID lookup).
var avProducts = []struct {
	name     string
	services []string
}{
	{"Acronis Cyber Protect", []string{"AcronisActiveProtectionService"}},
	{"Arctic Wolf", []string{"AwWfpService", "ArcticWolfAgentMgr"}},
	{"Avast/AVG", []string{"AvastWscReporter", "aswbIDSAgent", "AVGWscReporter", "avgbIDSAgent"}},
	{"Bitdefender", []string{"bdredline_agent", "BDAuxSrv", "UPDATESRV", "VSSERV", "bdredline", "EPRedline", "EPUpdateService", "EPSecurityService", "EPProtectedService", "EPIntegrationService"}},
	{"Carbon Black App Control", []string{"Parity"}},
	{"Check Point Endpoint", []string{"CPDA", "vsmon", "CPFileAnlyz", "EPClientUIService"}},
	{"Cortex XDR", []string{"xdrhealth", "cyserver"}},
	{"CrowdStrike Falcon", []string{"CSFalconService"}},
	{"Cybereason", []string{"CybereasonActiveProbe", "CybereasonCRS", "CybereasonBlocki"}},
	{"Cynet", []string{"CynetLauncher"}},
	{"Elastic EDR", []string{"Elastic Agent", "ElasticEndpoint"}},
	{"ESET", []string{"ekm", "epfw", "epfwlwf", "epfwwfp", "EraAgentSvc", "ERAAgent", "efwd", "ehttpsrv"}},
	{"FortiClient", []string{"FA_Scheduler", "FCT_SecSvr"}},
	{"FortiEDR", []string{"FortiEDR Collector Service"}},
	{"G DATA", []string{"AVKWCtl", "AVKProxy", "GDScan"}},
	{"HarfangLab EDR", []string{"hurukai", "Hurukai agent", "HarfangLab Hurukai agent", "hurukai-av", "hurukai-ui"}},
	{"Ivanti/Shavlik", []string{"STAgent$Shavlik Protect", "STDispatch$Shavlik Protect"}},
	{"Kaspersky", []string{"kavfsslp", "KAVFS", "KAVFSGT", "klnagent"}},
	{"Malwarebytes", []string{"MBAMService", "MBEndpointAgent"}},
	{"Panda Adaptive Defense 360", []string{"PandaAetherAgent", "PSUAService", "NanoServiceMain"}},
	{"Rapid7 Insight", []string{"ir_agent"}},
	{"SentinelOne", []string{"SentinelAgent", "SentinelStaticEngine", "LogProcessorService"}},
	{"Sophos Intercept X", []string{"SntpService", "Sophos Endpoint Defense Service", "Sophos File Scanner Service", "Sophos Health Service", "Sophos Live Query", "Sophos Managed Threat Response", "Sophos MCS Agent", "Sophos MCS Client", "Sophos System Protection Service"}},
	{"Symantec Endpoint Protection", []string{"SepMasterService", "SepScanService", "SNAC"}},
	{"Trellix/McAfee EDR", []string{"McAfee Endpoint Security Platform Service", "mfemactl", "mfemms", "mfefire", "masvc", "macmnsvc", "mfetp", "mfewc", "mfeaack"}},
	{"Trend Micro", []string{"Trend Micro Endpoint Basecamp", "TMBMServer", "Trend Micro Web Service Communicator", "TMiACAgentSvc", "CETASvc", "iVPAgent", "ds_agent", "ds_monitor", "ds_notifier"}},
	{"Wazuh", []string{"WazuhSvc"}},
	{"Windows Defender", []string{"WinDefend", "Sense", "WdNisSvc"}},
	{"WithSecure Elements", []string{"fsdevcon", "fshoster", "fsnethoster", "fsulhoster", "fsulnethoster", "fsulprothoster", "wsulavprohoster"}},
}

// DetectAV returns the AV/EDR products whose service names resolve on the host,
// via LsarLookupNames over \lsarpc. Best-effort: no hit is not proof of absence
// (driver-only products and unlisted service names are missed). No privilege needed.
func DetectAV(session *gofenrirsmb.Session) ([]string, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}
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

	var found []string
	for _, p := range avProducts {
		if anyServiceResolves(rpc, policy, p.services) {
			found = append(found, p.name)
		}
	}
	return found, nil
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
