package ldapmodules

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type UserEntry struct {
	SAMAccountName string
	DN             string
	UAC            ldap_attributes.UserAccountControl
}

func (u UserEntry) IsEnabled() bool {
	return u.UAC&ldap_attributes.UAF_ACCOUNT_DISABLED == 0
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
		uacVal, _ := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		users = append(users, UserEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			UAC:            ldap_attributes.UserAccountControl(uacVal),
		})
	}
	return users, nil
}
