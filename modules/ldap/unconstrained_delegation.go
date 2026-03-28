package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type UnconstrainedDelegationEntry struct {
	SAMAccountName string
	DN             string
	ObjectType     string // "computer" or "user"
}

// EnumUnconstrainedDelegation finds computers and users with TRUSTED_FOR_DELEGATION (0x80000) set,
// excluding DCs which have SERVER_TRUST_ACCOUNT (0x2000) and are expected to have it.
func EnumUnconstrainedDelegation(s *ldap.Session) ([]UnconstrainedDelegationEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
		[]string{"sAMAccountName", "distinguishedName", "objectClass"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate unconstrained delegation: %w", err)
	}

	var results []UnconstrainedDelegationEntry
	for _, entry := range entries {
		objType := "user"
		for _, class := range entry.GetAttributeValues("objectClass") {
			if class == "computer" {
				objType = "computer"
				break
			}
		}
		results = append(results, UnconstrainedDelegationEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			ObjectType:     objType,
		})
	}
	return results, nil
}
