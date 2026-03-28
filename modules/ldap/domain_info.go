package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type DomainInfo struct {
	DN              string
	DNSName         string
	NetBIOSName     string
	SID             string
	FunctionalLevel string
	PDC             string
	DNSServers      []string
	NamingContexts  []string
}

// GetDomainInfo retrieves key domain information using Manticore's domain utilities:
// distinguished name, DNS name, NetBIOS name, SID, functional level, PDC, DNS servers,
// and naming contexts.
func GetDomainInfo(s *ldap.Session, domain string) (*DomainInfo, error) {
	domainObj, err := s.LdapSession.GetDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain object: %w", err)
	}

	info := &DomainInfo{
		DN:          domainObj.DistinguishedName,
		DNSName:     domainObj.DNSName,
		NetBIOSName: domainObj.NetBIOSName,
		SID:         domainObj.SID,
	}

	level, err := domainObj.GetDomainFunctionalityLevel()
	if err == nil {
		info.FunctionalLevel = level.String()
	}

	pdc, err := s.LdapSession.GetPrincipalDomainController(domain)
	if err == nil {
		info.PDC = pdc
	}

	dnsServers, err := s.LdapSession.GetDomainDNSServers()
	if err == nil {
		info.DNSServers = dnsServers
	}

	namingContexts, err := s.LdapSession.GetAllNamingContexts()
	if err == nil {
		info.NamingContexts = namingContexts
	}

	return info, nil
}
