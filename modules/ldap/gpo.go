package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type GPOEntry struct {
	Name        string
	DisplayName string
	DN          string
	FileSysPath string
}

func EnumGPOs(s *ldap.Session) ([]GPOEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=groupPolicyContainer)",
		[]string{"name", "displayName", "distinguishedName", "gPCFileSysPath"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate GPOs: %w", err)
	}

	var results []GPOEntry
	for _, entry := range entries {
		results = append(results, GPOEntry{
			Name:        entry.GetAttributeValue("name"),
			DisplayName: entry.GetAttributeValue("displayName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			FileSysPath: entry.GetAttributeValue("gPCFileSysPath"),
		})
	}
	return results, nil
}
