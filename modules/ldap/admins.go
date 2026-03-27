package ldapmodules

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type AdminEntry struct {
	SAMAccountName string
	DN             string
}

func EnumAdmins(s *ldap.Session) ([]AdminEntry, error) {
	filter := fmt.Sprintf(
		"(&(objectClass=user)(objectCategory=person)(primaryGroupID=%d))",
		ldap_attributes.RID_DOMAIN_GROUP_ADMINS,
	)

	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		filter,
		[]string{"sAMAccountName", "distinguishedName"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate admins: %w", err)
	}

	var results []AdminEntry
	for _, entry := range entries {
		results = append(results, AdminEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
		})
	}
	return results, nil
}
