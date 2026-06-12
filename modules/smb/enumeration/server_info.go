package enumeration

import (
	"fmt"
	"strings"

	mssrvs "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-srvs"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type ServerInfoResult struct {
	Name    string
	Version string
	OSHint  string
	Roles   []string
	Comment string
}

// GetServerInfo queries the target's server configuration via srvsvc NetrServerGetInfo.
func GetServerInfo(session *gofenrirsmb.Session) (*ServerInfoResult, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	srvs := mssrvs.New(session.Client)
	info, err := srvs.GetServerInfo()
	if err != nil {
		return nil, fmt.Errorf("GetServerInfo: %w", err)
	}

	version := fmt.Sprintf("%d.%d", info.VersionMajor, info.VersionMinor)

	return &ServerInfoResult{
		Name:    info.Name,
		Version: version,
		OSHint:  osHint(info.VersionMajor, info.VersionMinor),
		Roles:   parseServerType(info.Type),
		Comment: info.Comment,
	}, nil
}

func osHint(major, minor uint32) string {
	switch {
	case major == 10 && minor == 0:
		return "Windows 10 / Server 2016/2019/2022"
	case major == 6 && minor == 3:
		return "Windows 8.1 / Server 2012 R2"
	case major == 6 && minor == 2:
		return "Windows 8 / Server 2012"
	case major == 6 && minor == 1:
		return "Windows 7 / Server 2008 R2"
	case major == 6 && minor == 0:
		return "Windows Vista / Server 2008"
	case major == 5 && minor == 2:
		return "Windows Server 2003"
	case major == 5 && minor == 1:
		return "Windows XP"
	case major == 5 && minor == 0:
		return "Windows 2000"
	default:
		return ""
	}
}

// SV_TYPE_* flags from MS-SRVS 2.2.2.4
const (
	svTypeWorkstation    = 0x00000001
	svTypeServer         = 0x00000002
	svTypeDomainCtrl     = 0x00000008
	svTypeDomainBakCtrl  = 0x00000010
	svTypeDomainMember   = 0x00000100
	svTypeNT             = 0x00001000
	svTypeServerNT       = 0x00008000
	svTypeMasterBrowser  = 0x00040000
	svTypeDomainMaster   = 0x00080000
	svTypeWindows        = 0x00400000
	svTypeDFS            = 0x00800000
	svTypeTerminalServer = 0x02000000
)

func parseServerType(t uint32) []string {
	flags := []struct {
		bit  uint32
		name string
	}{
		{svTypeDomainCtrl, "Primary Domain Controller"},
		{svTypeDomainBakCtrl, "Backup Domain Controller"},
		{svTypeDomainMaster, "Domain Master Browser"},
		{svTypeMasterBrowser, "Master Browser"},
		{svTypeTerminalServer, "Terminal Server"},
		{svTypeDFS, "DFS Root"},
		{svTypeServerNT, "Server (NT)"},
		{svTypeWorkstation, "Workstation"},
		{svTypeServer, "Server"},
		{svTypeDomainMember, "Domain Member"},
		{svTypeWindows, "Windows"},
		{svTypeNT, "NT"},
	}

	var roles []string
	for _, f := range flags {
		if t&f.bit != 0 {
			roles = append(roles, f.name)
		}
	}
	if len(roles) == 0 {
		roles = []string{fmt.Sprintf("0x%08x", t)}
	}
	return roles
}

// FormatServerType returns a compact comma-separated role string.
func FormatServerType(roles []string) string {
	return strings.Join(roles, ", ")
}
