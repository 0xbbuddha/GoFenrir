package ldapmodules

import (
	"fmt"

	ldapattrs "github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type PrivilegedGroupEntry struct {
	Name    string
	DN      string
	Members []string
}

// privilegedRIDs maps a human-readable label to its well-known domain RID.
// Using Manticore's RID constants from ldap_attributes.
var privilegedRIDs = []struct {
	Label string
	RID   int
}{
	{"Domain Admins", ldapattrs.RID_DOMAIN_GROUP_ADMINS},
	{"Enterprise Admins", ldapattrs.RID_DOMAIN_GROUP_ENTERPRISE_ADMINS},
	{"Schema Admins", ldapattrs.RID_DOMAIN_GROUP_SCHEMA_ADMINS},
	{"Group Policy Creator Owners", ldapattrs.RID_DOMAIN_GROUP_POLICY_ADMINS},
	{"Protected Users", ldapattrs.RID_DOMAIN_GROUP_PROTECTED_USERS},
	{"Key Admins", ldapattrs.RID_DOMAIN_GROUP_KEY_ADMINS},
	{"Enterprise Key Admins", ldapattrs.RID_DOMAIN_GROUP_ENTERPRISE_KEY_ADMINS},
	{"Cert Publishers", ldapattrs.RID_DOMAIN_GROUP_CERT_PUBLISHERS},
}

// nonRIDGroups are privileged groups not covered by well-known domain RIDs
// but consistently present in AD environments.
var nonRIDGroups = []string{
	"Backup Operators",
	"Account Operators",
	"Server Operators",
	"Print Operators",
	"DnsAdmins",
	"Remote Desktop Users",
}

// EnumPrivilegedGroups enumerates high-value AD groups using Manticore's RID constants
// to locate well-known domain groups, then resolves member SAMAccountNames.
func EnumPrivilegedGroups(s *ldap.Session, domain string) ([]PrivilegedGroupEntry, error) {
	var results []PrivilegedGroupEntry

	// --- RID-based lookup via Manticore's FindObjectSIDByRID ---
	for _, pg := range privilegedRIDs {
		sid, err := s.LdapSession.FindObjectSIDByRID(domain, pg.RID)
		if err != nil || sid == "" {
			continue
		}

		entries, err := s.LdapSession.QueryWholeSubtree(
			"",
			fmt.Sprintf("(objectSid=%s)", sid),
			[]string{"sAMAccountName", "distinguishedName", "member"},
		)
		if err != nil || len(entries) == 0 {
			continue
		}

		group := PrivilegedGroupEntry{
			Name: pg.Label,
			DN:   entries[0].GetAttributeValue("distinguishedName"),
		}

		for _, memberDN := range entries[0].GetAttributeValues("member") {
			memberEntries, err := s.LdapSession.QueryWholeSubtree(
				"",
				fmt.Sprintf("(distinguishedName=%s)", memberDN),
				[]string{"sAMAccountName"},
			)
			if err == nil && len(memberEntries) > 0 {
				group.Members = append(group.Members, memberEntries[0].GetAttributeValue("sAMAccountName"))
			} else {
				// Fallback: show DN if SAMAccountName resolution fails
				group.Members = append(group.Members, memberDN)
			}
		}

		results = append(results, group)
	}

	// --- Name-based lookup for groups without stable domain RIDs ---
	for _, name := range nonRIDGroups {
		entries, err := s.LdapSession.QueryWholeSubtree(
			"",
			fmt.Sprintf("(&(objectClass=group)(sAMAccountName=%s))", name),
			[]string{"sAMAccountName", "distinguishedName", "member"},
		)
		if err != nil || len(entries) == 0 {
			continue
		}

		group := PrivilegedGroupEntry{
			Name: name,
			DN:   entries[0].GetAttributeValue("distinguishedName"),
		}

		for _, memberDN := range entries[0].GetAttributeValues("member") {
			memberEntries, err := s.LdapSession.QueryWholeSubtree(
				"",
				fmt.Sprintf("(distinguishedName=%s)", memberDN),
				[]string{"sAMAccountName"},
			)
			if err == nil && len(memberEntries) > 0 {
				group.Members = append(group.Members, memberEntries[0].GetAttributeValue("sAMAccountName"))
			} else {
				group.Members = append(group.Members, memberDN)
			}
		}

		results = append(results, group)
	}

	return results, nil
}
