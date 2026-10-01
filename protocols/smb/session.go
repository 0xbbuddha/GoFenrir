package smb

import (
	"fmt"
	"time"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// DialTimeout bounds every SMB connect/negotiate attempt. Zero keeps the
// manticore default (10s); a negative value disables the bound. It is set once
// from the --timeout flag before any session is opened.
var DialTimeout time.Duration

type Session struct {
	Host   string
	Port   int
	Client *smbclient.Client
}

// DialOptions returns the shared dial options (currently the configured timeout),
// so probes that dial outside NewSession stay consistent with it.
func DialOptions() smbclient.Options {
	return smbclient.Options{DialTimeout: DialTimeout}
}

func NewSession(host string, port int, domain, username, password, hash string) (*Session, error) {
	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	c, err := smbclient.Dial(host, port, DialOptions())
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
