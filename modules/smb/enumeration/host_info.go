package enumeration

import (
	"fmt"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// HostInfo is the connection banner shown on a successful SMB login: what the
// server is, which dialect was negotiated, whether signing is enforced, and
// whether SMB1 / null sessions are still accepted.
type HostInfo struct {
	Name            string
	OS              string
	Dialect         string
	SigningRequired bool
	SMBv1Enabled    bool
	NullSession     bool
}

// GetHostInfo reads the banner facts from an established session, then runs two
// lightweight probes (SMB1 negotiation and a null session). The probes target a
// host already known to be up and authenticating, so they are cheap.
func GetHostInfo(session *gofenrirsmb.Session, host string, port int) HostInfo {
	id := session.Client.ServerIdentity()

	name := id.NetBIOSComputerName
	if name == "" {
		name = id.DNSComputerName
	}

	return HostInfo{
		Name:            name,
		OS:              formatOS(id),
		Dialect:         session.Client.Dialect().String(),
		SigningRequired: session.Client.ConnectionInfo().SigningRequired,
		SMBv1Enabled:    CheckSMBv1(host, port),
		NullSession:     CheckNullSession(host, port),
	}
}

// formatOS renders a short server OS label from the NTLM CHALLENGE version,
// falling back to the SMB1 native-OS string when present. The build number
// pins the exact release, so it is preferred over the ambiguous major.minor
// range; when the build is unknown a compact "Windows M.m (build N)" is used.
func formatOS(id smbclient.ServerIdentity) string {
	if id.OSVersionMajor == 0 && id.OSVersionMinor == 0 && id.OSVersionBuild == 0 {
		return id.OSName
	}
	if name := osFromBuild(id.OSVersionBuild); name != "" {
		return name
	}
	return fmt.Sprintf("Windows %d.%d (build %d)", id.OSVersionMajor, id.OSVersionMinor, id.OSVersionBuild)
}

// osFromBuild maps a Windows build number to a concise release name.
func osFromBuild(build uint16) string {
	switch build {
	case 26100:
		return "Windows Server 2025"
	case 20348:
		return "Windows Server 2022"
	case 17763:
		return "Windows Server 2019"
	case 14393:
		return "Windows Server 2016"
	case 9600:
		return "Windows Server 2012 R2"
	case 9200:
		return "Windows Server 2012"
	case 7601:
		return "Windows Server 2008 R2"
	case 6003:
		return "Windows Server 2008"
	case 3790:
		return "Windows Server 2003"
	case 22000, 22621, 22631, 26200:
		return "Windows 11"
	case 10240, 10586, 15063, 16299, 17134, 18362, 18363, 19041, 19042, 19043, 19044, 19045:
		return "Windows 10"
	case 7600:
		return "Windows 7"
	}
	return ""
}
