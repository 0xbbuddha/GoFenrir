package smb

import (
	"fmt"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

type Session struct {
	Host   string
	Port   int
	Client *smbclient.Client
}

func NewSession(host string, port int, domain, username, password, hash string) (*Session, error) {
	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	c, err := smbclient.Dial(host, port, smbclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	if err := c.Login(creds); err != nil {
		c.Disconnect()
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

func (s *Session) Close() {
	s.Client.Disconnect()
}
