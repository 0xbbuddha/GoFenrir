package privilege

import (
	"fmt"
	"strconv"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type PSOEntry struct {
	Name                string
	Precedence          int
	MinPwdLength        int
	PwdHistoryLength    int
	LockoutThreshold    int
	ComplexityEnabled   bool
	ReversibleEncrypt   bool
	AppliesTo           []string // resolved SAMAccountNames or DNs
}

var psoAttrs = []string{
	"name",
	"msDS-PasswordSettingsPrecedence",
	"msDS-MinimumPasswordLength",
	"msDS-PasswordHistoryLength",
	"msDS-LockoutThreshold",
	"msDS-PasswordComplexityEnabled",
	"msDS-PasswordReversibleEncryptionEnabled",
	"msDS-PSOAppliesTo",
}

// EnumPSO enumerates Fine-Grained Password Policy objects (msDS-PasswordSettings)
// stored under CN=Password Settings Container,CN=System.
// PSOs override the default domain password policy for specific users or groups.
func EnumPSO(s *ldap.Session) ([]PSOEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=msDS-PasswordSettings)",
		psoAttrs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate PSOs: %w", err)
	}

	var results []PSOEntry
	for _, entry := range entries {
		e := PSOEntry{
			Name:              entry.GetAttributeValue("name"),
			Precedence:        parseInt(entry.GetAttributeValue("msDS-PasswordSettingsPrecedence")),
			MinPwdLength:      parseInt(entry.GetAttributeValue("msDS-MinimumPasswordLength")),
			PwdHistoryLength:  parseInt(entry.GetAttributeValue("msDS-PasswordHistoryLength")),
			LockoutThreshold:  parseInt(entry.GetAttributeValue("msDS-LockoutThreshold")),
			ComplexityEnabled: parseBool(entry.GetAttributeValue("msDS-PasswordComplexityEnabled")),
			ReversibleEncrypt: parseBool(entry.GetAttributeValue("msDS-PasswordReversibleEncryptionEnabled")),
		}

		// msDS-PSOAppliesTo is multi-valued: list of DNs pointing to users or groups.
		// Resolve each DN to its SAMAccountName for readability.
		for _, dn := range entry.GetAttributeValues("msDS-PSOAppliesTo") {
			name := resolveDN(s, dn)
			if name == "" {
				name = dn
			}
			e.AppliesTo = append(e.AppliesTo, name)
		}

		results = append(results, e)
	}
	return results, nil
}

// resolveDN fetches the sAMAccountName of an object by its DN.
func resolveDN(s *ldap.Session, dn string) string {
	entries, err := s.LdapSession.QueryBaseObject(dn, "(objectClass=*)", []string{"sAMAccountName"})
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[0].GetAttributeValue("sAMAccountName")
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parseBool(s string) bool {
	return s == "TRUE" || s == "true" || s == "1"
}
