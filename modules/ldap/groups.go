package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type GroupEntry struct {
	Name    string
	DN      string
	Members []string
}

func EnumGroups(s *ldap.Session) ([]GroupEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=group)",
		[]string{"sAMAccountName", "distinguishedName", "member"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate groups: %w", err)
	}

	var groups []GroupEntry
	for _, entry := range entries {
		groups = append(groups, GroupEntry{
			Name:    entry.GetAttributeValue("sAMAccountName"),
			DN:      entry.GetAttributeValue("distinguishedName"),
			Members: entry.GetAttributeValues("member"),
		})
	}
	return groups, nil
}
