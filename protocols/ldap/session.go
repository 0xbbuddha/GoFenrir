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

// KerberosAuth carries optional Kerberos material for a Kerberos (GSSAPI) bind.
// A TGT is derived from the strongest secret available, in this order: ccache,
// kirbi, keytab, AES key, NT hash, then password. Leave all fields empty to use
// the password/hash passed to the session.
type KerberosAuth struct {
	AESKey string // hex-encoded AES128/AES256 Kerberos key
	CCache string // path to a FILE ccache (KRB5CCNAME) — pass-the-ticket
	Kirbi  string // path to a .kirbi (KRB-CRED) — pass-the-ticket
	Keytab string // path to a keytab file
}

// NewSession creates an LDAP session that authenticates with NTLM (password or
// pass-the-hash), matching the historical behaviour.
func NewSession(host string, port int, domain, username, password, hash string, useTLS bool) (*Session, error) {
	return newSession(host, port, domain, username, password, hash, useTLS, false, nil)
}

// NewKerberosSession creates an LDAP session that authenticates with Kerberos
// (GSSAPI). The TGT is obtained from krb (ccache/kirbi/keytab/AES key) when set,
// otherwise derived from the password or NT hash.
func NewKerberosSession(host string, port int, domain, username, password, hash string, useTLS bool, krb KerberosAuth) (*Session, error) {
	return newSession(host, port, domain, username, password, hash, useTLS, true, &krb)
}

func newSession(host string, port int, domain, username, password, hash string, useTLS, useKerberos bool, krb *KerberosAuth) (*Session, error) {
	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	if krb != nil {
		if krb.CCache != "" {
			if err := creds.SetCCache(krb.CCache); err != nil {
				return nil, fmt.Errorf("ccache: %w", err)
			}
		}
		if krb.Kirbi != "" {
			if err := creds.SetKirbi(krb.Kirbi); err != nil {
				return nil, fmt.Errorf("kirbi: %w", err)
			}
		}
		if krb.Keytab != "" {
			if err := creds.SetKeytab(krb.Keytab); err != nil {
				return nil, fmt.Errorf("keytab: %w", err)
			}
		}
		if krb.AESKey != "" {
			if err := creds.SetAESKey(krb.AESKey); err != nil {
				return nil, fmt.Errorf("aes-key: %w", err)
			}
		}
	}

	ldapSession, err := manticoreldap.NewSession(host, port, creds, useTLS, useKerberos)
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
