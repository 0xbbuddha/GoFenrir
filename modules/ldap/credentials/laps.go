package credentials

import (
	"encoding/json"
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type LAPSEntry struct {
	ComputerName string
	Password     string
	Expiration   string
	Version      int // 1 = LAPSv1, 2 = LAPSv2
}

// lapsV2Password is the JSON structure stored in msLAPS-Password
type lapsV2Password struct {
	N string `json:"n"` // account name
	T string `json:"t"` // timestamp
	P string `json:"p"` // password
}

// EnumLAPS reads LAPS passwords from computer objects.
// It tries LAPSv2 first (msLAPS-Password), then falls back to LAPSv1 (ms-Mcs-AdmPwd).
func EnumLAPS(s *ldap.Session) ([]LAPSEntry, error) {
	attrs := []string{
		"sAMAccountName",
		"ms-Mcs-AdmPwd",
		"ms-Mcs-AdmPwdExpirationTime",
		"msLAPS-Password",
		"msLAPS-PasswordExpirationTime",
	}

	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(&(objectCategory=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)))",
		attrs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate LAPS: %w", err)
	}

	var results []LAPSEntry
	for _, entry := range entries {
		computer := entry.GetAttributeValue("sAMAccountName")

		// LAPSv2
		if v2 := entry.GetAttributeValue("msLAPS-Password"); v2 != "" {
			password, expiration := parseLAPSv2(v2, entry.GetAttributeValue("msLAPS-PasswordExpirationTime"))
			results = append(results, LAPSEntry{
				ComputerName: computer,
				Password:     password,
				Expiration:   expiration,
				Version:      2,
			})
			continue
		}

		// LAPSv1
		if v1 := entry.GetAttributeValue("ms-Mcs-AdmPwd"); v1 != "" {
			results = append(results, LAPSEntry{
				ComputerName: computer,
				Password:     v1,
				Expiration:   entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"),
				Version:      1,
			})
		}
	}
	return results, nil
}

func parseLAPSv2(raw string, expiration string) (password string, exp string) {
	var v lapsV2Password
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw, expiration
	}
	return v.P, expiration
}
