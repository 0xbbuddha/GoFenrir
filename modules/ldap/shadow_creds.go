package ldapmodules

import (
	"fmt"

	manticoreldap "github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ShadowKey struct {
	Identifier   string
	Usage        string
	Source       string
	CreationTime string
}

type ShadowCredEntry struct {
	SAMAccountName string
	DN             string
	ObjectType     string // "computer" or "user"
	Keys           []ShadowKey
}

// EnumShadowCreds finds objects with msDS-KeyCredentialLink set and parses
// each key using Manticore's KeyCredentialLink parser.
func EnumShadowCreds(s *ldap.Session) ([]ShadowCredEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(msDS-KeyCredentialLink=*)",
		[]string{"sAMAccountName", "distinguishedName", "objectClass", "msDS-KeyCredentialLink"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate shadow credentials: %w", err)
	}

	var results []ShadowCredEntry
	for _, entry := range entries {
		objType := "user"
		for _, class := range entry.GetAttributeValues("objectClass") {
			if class == "computer" {
				objType = "computer"
				break
			}
		}

		rawKeys := entry.GetAttributeValues("msDS-KeyCredentialLink")
		var keys []ShadowKey
		for _, raw := range rawKeys {
			dnwb := manticoreldap.DNWithBinary{}
			if _, err := dnwb.Unmarshal([]byte(raw)); err != nil {
				continue
			}

			kc := keycredentiallink.KeyCredentialLink{}
			if err := kc.ParseDNWithBinary(dnwb); err != nil {
				continue
			}

			key := ShadowKey{
				Identifier: kc.Identifier,
				Usage:      kc.Usage.String(),
			}
			if kc.Source != nil {
				key.Source = kc.Source.String()
			}
			if kc.CreationTime != nil {
				key.CreationTime = kc.CreationTime.ToUniversalTime().Format("2006-01-02 15:04:05")
			}
			keys = append(keys, key)
		}

		results = append(results, ShadowCredEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			ObjectType:     objType,
			Keys:           keys,
		})
	}
	return results, nil
}
