package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ComputerEntry struct {
	Name        string
	DNSHostname string
	DN          string
	OS          string
	OSVersion   string
}

func EnumComputers(s *ldap.Session) ([]ComputerEntry, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=computer)",
		[]string{"sAMAccountName", "dnsHostName", "distinguishedName", "operatingSystem", "operatingSystemVersion"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate computers: %w", err)
	}

	var results []ComputerEntry
	for _, entry := range entries {
		results = append(results, ComputerEntry{
			Name:        entry.GetAttributeValue("sAMAccountName"),
			DNSHostname: entry.GetAttributeValue("dnsHostName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			OS:          entry.GetAttributeValue("operatingSystem"),
			OSVersion:   entry.GetAttributeValue("operatingSystemVersion"),
		})
	}
	return results, nil
}
