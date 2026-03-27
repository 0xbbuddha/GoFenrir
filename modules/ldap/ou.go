package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type OUEntry struct {
	Name string
	DN   string
}

func EnumOUs(s *ldap.Session) ([]OUEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=organizationalUnit)",
		[]string{"name", "distinguishedName"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate OUs: %w", err)
	}

	var results []OUEntry
	for _, entry := range entries {
		results = append(results, OUEntry{
			Name: entry.GetAttributeValue("name"),
			DN:   entry.GetAttributeValue("distinguishedName"),
		})
	}
	return results, nil
}
