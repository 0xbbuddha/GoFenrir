package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type AdminCountEntry struct {
	SAMAccountName string
	DN             string
	ObjectType     string // "user", "group", or "computer"
}

// EnumAdminCount finds all objects with adminCount=1, indicating they are or were
// protected by AdminSDHolder. This includes users and groups that are (or were)
// members of privileged groups. Note: adminCount is not reset when an object
// is removed from a privileged group, so stale entries are common and noteworthy.
func EnumAdminCount(s *ldap.Session) ([]AdminCountEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(adminCount=1)",
		[]string{"sAMAccountName", "distinguishedName", "objectClass"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate adminCount objects: %w", err)
	}

	var results []AdminCountEntry
	for _, entry := range entries {
		objType := "user"
		for _, class := range entry.GetAttributeValues("objectClass") {
			switch class {
			case "computer":
				objType = "computer"
			case "group":
				objType = "group"
			}
		}

		results = append(results, AdminCountEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			ObjectType:     objType,
		})
	}
	return results, nil
}
