package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type TrustEntry struct {
	Name        string
	TrustType   string
	Direction   string
	Attributes  string
}

func EnumTrusts(s *ldap.Session) ([]TrustEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=trustedDomain)",
		[]string{"name", "trustType", "trustDirection", "trustAttributes"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate trusts: %w", err)
	}

	var results []TrustEntry
	for _, entry := range entries {
		direction := parseTrustDirection(entry.GetAttributeValue("trustDirection"))
		trustType := parseTrustType(entry.GetAttributeValue("trustType"))
		results = append(results, TrustEntry{
			Name:       entry.GetAttributeValue("name"),
			TrustType:  trustType,
			Direction:  direction,
			Attributes: entry.GetAttributeValue("trustAttributes"),
		})
	}
	return results, nil
}

func parseTrustDirection(val string) string {
	switch val {
	case "1":
		return "Inbound"
	case "2":
		return "Outbound"
	case "3":
		return "Bidirectional"
	default:
		return fmt.Sprintf("Unknown (%s)", val)
	}
}

func parseTrustType(val string) string {
	switch val {
	case "1":
		return "Downlevel (NT)"
	case "2":
		return "Uplevel (AD)"
	case "3":
		return "MIT (non-Windows)"
	case "4":
		return "DCE"
	default:
		return fmt.Sprintf("Unknown (%s)", val)
	}
}
