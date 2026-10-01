package enumeration

import (
	smb "github.com/TheManticoreProject/Manticore/network/smb"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

func CheckNullSession(host string, port int) bool {
	creds, err := credentials.NewCredentials("", "", "", "")
	if err != nil {
		return false
	}
	c, err := smbclient.Dial(host, port, gofenrirsmb.DialOptions())
	if err != nil {
		return false
	}
	defer c.Disconnect()
	return c.Login(creds) == nil
}

func CheckAnonymousIPCAccess(host string, port int) bool {
	creds, err := credentials.NewCredentials("", "", "", "")
	if err != nil {
		return false
	}
	c, err := smbclient.Dial(host, port, gofenrirsmb.DialOptions())
	if err != nil {
		return false
	}
	defer c.Disconnect()
	if err := c.Login(creds); err != nil {
		return false
	}
	return c.TreeConnect("IPC$") == nil
}

// CheckSMBv1 reports whether the host still speaks SMB1 (CVE-prone, EternalBlue
// surface). It negotiates offering SMB1 only: success means SMB1 is enabled.
func CheckSMBv1(host string, port int) bool {
	opts := gofenrirsmb.DialOptions()
	opts.Preferred = []smb.SMBProtocolVersion{smb.SMB_VERSION_1_0}
	c, err := smbclient.Dial(host, port, opts)
	if err != nil {
		return false
	}
	c.Disconnect()
	return true
}
