package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type DCEntry struct {
	DN       string
	Hostname string
	ReadOnly bool
}

func EnumDCs(s *ldap.Session) ([]DCEntry, error) {
	var dcs []DCEntry

	dcMap, err := s.LdapSession.GetAllDomainControllers()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate DCs: %w", err)
	}
	for dn, hostnames := range dcMap {
		for _, h := range hostnames {
			dcs = append(dcs, DCEntry{DN: dn, Hostname: h, ReadOnly: false})
		}
	}

	rodcMap, err := s.LdapSession.GetAllReadOnlyDomainControllers()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate RODCs: %w", err)
	}
	for dn, hostnames := range rodcMap {
		for _, h := range hostnames {
			dcs = append(dcs, DCEntry{DN: dn, Hostname: h, ReadOnly: true})
		}
	}

	return dcs, nil
}
