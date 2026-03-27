package ldap

import (
	"fmt"

	manticoreldap "github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

type Session struct {
	Host        string
	Port        int
	Domain      string
	Username    string
	LdapSession *manticoreldap.Session
}

func NewSession(host string, port int, domain, username, password, hash string, useTLS bool) (*Session, error) {
	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	ldapSession, err := manticoreldap.NewSession(host, port, creds, useTLS, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP session: %w", err)
	}

	return &Session{
		Host:        host,
		Port:        port,
		Domain:      domain,
		Username:    username,
		LdapSession: ldapSession,
	}, nil
}

func (s *Session) Connect() error {
	ok, err := s.LdapSession.Connect()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("connection failed")
	}
	return nil
}

func (s *Session) Close() {
	s.LdapSession.Close()
}
