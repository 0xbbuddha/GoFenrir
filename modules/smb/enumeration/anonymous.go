package enumeration

import (
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func CheckNullSession(host string, port int) bool {
	creds, err := credentials.NewCredentials("", "", "", "")
	if err != nil {
		return false
	}
	c, err := smbclient.Dial(host, port, smbclient.Options{})
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
	c, err := smbclient.Dial(host, port, smbclient.Options{})
	if err != nil {
		return false
	}
	defer c.Disconnect()
	if err := c.Login(creds); err != nil {
		return false
	}
	return c.TreeConnect("IPC$") == nil
}
