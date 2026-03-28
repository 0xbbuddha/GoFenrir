package ldapmodules

import (
	"fmt"
	"strconv"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ConstrainedDelegationEntry struct {
	SAMAccountName     string
	DN                 string
	AllowedServices    []string
	ProtocolTransition bool // TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) — S4U2Self enabled
}

// EnumConstrainedDelegation finds objects with msDS-AllowedToDelegateTo set.
// ProtocolTransition is true when userAccountControl has the TRUSTED_TO_AUTH_FOR_DELEGATION bit (0x1000000),
// meaning the account can impersonate any user via S4U2Self without requiring a service ticket.
func EnumConstrainedDelegation(s *ldap.Session) ([]ConstrainedDelegationEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(msDS-AllowedToDelegateTo=*)",
		[]string{"sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo", "userAccountControl"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate constrained delegation: %w", err)
	}

	var results []ConstrainedDelegationEntry
	for _, entry := range entries {
		uac, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)
		results = append(results, ConstrainedDelegationEntry{
			SAMAccountName:     entry.GetAttributeValue("sAMAccountName"),
			DN:                 entry.GetAttributeValue("distinguishedName"),
			AllowedServices:    entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
			ProtocolTransition: (uac & 0x1000000) != 0,
		})
	}
	return results, nil
}
