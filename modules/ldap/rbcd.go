package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type RBCDEntry struct {
	SAMAccountName string
	DN             string
	ObjectType     string // "computer" or "user"
}

// EnumRBCD finds objects with msDS-AllowedToActOnBehalfOfOtherIdentity set,
// meaning another principal has been granted the ability to impersonate any user
// to this object via Resource-Based Constrained Delegation.
func EnumRBCD(s *ldap.Session) ([]RBCDEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
		[]string{"sAMAccountName", "distinguishedName", "objectClass"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate RBCD: %w", err)
	}

	var results []RBCDEntry
	for _, entry := range entries {
		objType := "user"
		for _, class := range entry.GetAttributeValues("objectClass") {
			if class == "computer" {
				objType = "computer"
				break
			}
		}
		results = append(results, RBCDEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			ObjectType:     objType,
		})
	}
	return results, nil
}
