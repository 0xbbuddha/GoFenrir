package smb

import (
	"fmt"
	"net"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

type Session struct {
	Host   string
	Port   int
	Client *smbclient.Client
}

func NewSession(host string, port int, domain, username, password, hash string) (*Session, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve host %s: %w", host, err)
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ips[0])
	}

	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	c := smbclient.NewClientUsingTCPTransport(ip, port)

	if err := c.Connect(ip, port); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	if err := c.SessionSetup(creds); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return &Session{
		Host:   host,
		Port:   port,
		Client: c,
	}, nil
}

func (s *Session) TreeConnect(share string) error {
	return s.Client.TreeConnect(share)
}
