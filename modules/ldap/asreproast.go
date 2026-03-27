package ldapmodules

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ASREPRoastEntry struct {
	SAMAccountName string
	DN             string
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
