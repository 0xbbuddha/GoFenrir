package enumeration

import (
	"fmt"
	"strconv"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

// MachineAccountQuota holds the domain's ms-DS-MachineAccountQuota: the number
// of computer accounts a non-privileged user is allowed to create in the domain.
type MachineAccountQuota struct {
	Quota     int
	IsDefault bool // true when the attribute is unset and AD's default of 10 applies
}

// GetMachineAccountQuota reads ms-DS-MachineAccountQuota from the domain NC head.
// A value > 0 means any authenticated user can join machines to the domain,
// which enables RBCD / noPac-style abuses.
func GetMachineAccountQuota(s *ldap.Session) (*MachineAccountQuota, error) {
	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=domainDNS)",
		[]string{"ms-DS-MachineAccountQuota"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query machine account quota: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("domain object not found")
	}

	val := entries[0].GetAttributeValue("ms-DS-MachineAccountQuota")
	if val == "" {
		// Attribute absent: AD falls back to the built-in default of 10.
		return &MachineAccountQuota{Quota: 10, IsDefault: true}, nil
	}

	q, err := strconv.Atoi(val)
	if err != nil {
		return nil, fmt.Errorf("invalid quota value %q: %w", val, err)
	}
	return &MachineAccountQuota{Quota: q}, nil
}
