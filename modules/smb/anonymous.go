package smbmodules

import (
	"fmt"
	"net"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

func CheckNullSession(host string, port int) bool {
	ips, err := net.LookupHost(host)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		return false
	}

	creds, err := credentials.NewCredentials("", "", "", "")
	if err != nil {
		return false
	}

	c := smbclient.NewClientUsingTCPTransport(ip, port)
	if err := c.Connect(ip, port); err != nil {
		return false
	}

	err = c.SessionSetup(creds)
	return err == nil
}

func CheckAnonymousIPCAccess(host string, port int) bool {
	ips, err := net.LookupHost(host)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		return false
	}

	creds, err := credentials.NewCredentials("", "", "", "")
	if err != nil {
		return false
	}

	c := smbclient.NewClientUsingTCPTransport(ip, port)
	if err := c.Connect(ip, port); err != nil {
		return false
	}

	if err := c.SessionSetup(creds); err != nil {
		return false
	}

	err = c.TreeConnect(fmt.Sprintf("\\\\%s\\IPC$", host))
	return err == nil
}
