package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type UserEntry struct {
	SAMAccountName string
	DN             string
	Enabled        bool
}

func EnumUsers(s *ldap.Session) ([]UserEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(&(objectClass=user)(objectCategory=person))",
		[]string{"sAMAccountName", "distinguishedName", "userAccountControl"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %w", err)
	}

	var users []UserEntry
	for _, entry := range entries {
		uac := entry.GetAttributeValue("userAccountControl")
		enabled := uac != "514" && uac != "66050"
		users = append(users, UserEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			Enabled:        enabled,
		})
	}
	return users, nil
}
