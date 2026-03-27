package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type KerberoastableEntry struct {
	SAMAccountName string
	DN             string
	SPNs           []string
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
