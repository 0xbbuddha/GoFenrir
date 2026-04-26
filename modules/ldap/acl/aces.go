package acl

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/ace/aceflags"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/sid"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type ACEEntry struct {
	ObjectName  string // SAMAccountName or DN of the target object
	ObjectType  string // "domain", "user", "group", "computer"
	TrusteeName string // resolved SAMAccountName or SID string as fallback
	TrusteeSID  string
	Right       string
	Inherited   bool
	Severity    string // "critical", "high", "medium"
}

// Dangerous access masks — flagged when held by a non-privileged trustee.
var dangerousMasks = []struct {
	Mask     uint32
	Name     string
	Severity string
}{
	{rights.RIGHT_GENERIC_ALL, "GenericAll", "critical"},
	{rights.RIGHT_GENERIC_WRITE, "GenericWrite", "high"},
	{rights.RIGHT_WRITE_DAC, "WriteDACL", "high"},
	{rights.RIGHT_WRITE_OWNER, "WriteOwner", "high"},
	{rights.RIGHT_DS_CONTROL_ACCESS, "AllExtendedRights", "high"},
	{rights.RIGHT_DS_WRITE_PROPERTY, "WriteProperty", "medium"},
	{rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED, "WriteSelf", "medium"},
}

// Extended right GUIDs (DS_CONTROL_ACCESS with ObjectType GUID).
var dangerousExtendedRightGUIDs = map[string]struct {
	Name     string
	Severity string
}{
	rights.EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD:                 {"ForceChangePassword", "high"},
	rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES:                 {"DCSync (GetChanges)", "critical"},
	rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL:             {"DCSync (GetChangesAll)", "critical"},
	rights.EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET: {"DCSync (GetChangesFiltered)", "critical"},
}

// Property write GUIDs (DS_WRITE_PROPERTY with ObjectType GUID).
var dangerousPropertyGUIDs = map[string]struct {
	Name     string
	Severity string
}{
	"bf9679c0-0de6-11d0-a285-00aa003049e2": {"WriteMember (AddToGroup)", "high"},
	"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": {"WriteAllowedToAct (RBCD)", "high"},
}

// Fixed well-known privileged or noisy trustee SIDs to always skip.
var alwaysSkipSIDs = map[string]bool{
	"S-1-5-10":    true, // Principal Self — objects always have rights over themselves
	"S-1-5-18":    true, // SYSTEM
	"S-1-5-9":     true, // Enterprise Domain Controllers
	"S-1-3-0":     true, // Creator Owner
	"S-1-3-4":     true, // Owner Rights
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-32-548": true, // Account Operators (built-in semi-privileged, expected on many groups)
	"S-1-5-32-557": true, // Incoming Forest Trust Builders
	"S-1-5-32-561": true, // Terminal Server License Servers
	"S-1-1-0":     true, // Everyone
	"S-1-5-11":    true, // Authenticated Users
}

// EnumDangerousACEs finds dangerous ACEs on high-value AD objects.
// Scope: domain object, all groups, adminCount=1 users, all computers.
// Inherited ACEs are skipped — they reflect default AD schema permissions and create noise.
func EnumDangerousACEs(s *ldap.Session) ([]ACEEntry, error) {
	domainSID, err := getDomainSID(s)
	if err != nil {
		return nil, fmt.Errorf("find-aces: %w", err)
	}

	// Build the set of privileged domain-relative SIDs to skip.
	skipSIDs := make(map[string]bool, len(alwaysSkipSIDs)+10)
	for k, v := range alwaysSkipSIDs {
		skipSIDs[k] = v
	}
	for _, rid := range []string{"500", "512", "516", "518", "519", "520", "498"} {
		skipSIDs[domainSID+"-"+rid] = true
	}

	sidCache := make(map[string]string)
	var results []ACEEntry

	// 1. Domain object.
	domEntries, err := s.LdapSession.QueryBaseObject("", "(objectClass=domain)", []string{"distinguishedName"})
	if err == nil && len(domEntries) > 0 {
		dn := domEntries[0].GetAttributeValue("distinguishedName")
		aces, _ := aclForObject(s, dn, "domain", dn, skipSIDs, sidCache)
		results = append(results, aces...)
	}

	// 2. All groups.
	groupEntries, _ := s.LdapSession.QueryWholeSubtree("", "(objectClass=group)", []string{"sAMAccountName", "distinguishedName"})
	for _, g := range groupEntries {
		dn := g.GetAttributeValue("distinguishedName")
		name := g.GetAttributeValue("sAMAccountName")
		aces, _ := aclForObject(s, dn, "group", name, skipSIDs, sidCache)
		results = append(results, aces...)
	}

	// 3. Privileged users (adminCount=1).
	userEntries, _ := s.LdapSession.QueryWholeSubtree("", "(&(objectClass=user)(adminCount=1)(!objectClass=computer))", []string{"sAMAccountName", "distinguishedName"})
	for _, u := range userEntries {
		dn := u.GetAttributeValue("distinguishedName")
		name := u.GetAttributeValue("sAMAccountName")
		aces, _ := aclForObject(s, dn, "user", name, skipSIDs, sidCache)
		results = append(results, aces...)
	}

	// 4. All computers.
	compEntries, _ := s.LdapSession.QueryWholeSubtree("", "(objectClass=computer)", []string{"sAMAccountName", "distinguishedName"})
	for _, c := range compEntries {
		dn := c.GetAttributeValue("distinguishedName")
		name := c.GetAttributeValue("sAMAccountName")
		aces, _ := aclForObject(s, dn, "computer", name, skipSIDs, sidCache)
		results = append(results, aces...)
	}

	return results, nil
}

// aclForObject fetches and parses the nTSecurityDescriptor for one object,
// returning any dangerous ALLOW ACEs held by non-privileged trustees.
func aclForObject(s *ldap.Session, dn, objectType, objectName string, skipSIDs map[string]bool, sidCache map[string]string) ([]ACEEntry, error) {
	sdRaw, err := s.LdapSession.GetNtSecurityDescriptorOf(dn)
	if err != nil || len(sdRaw) == 0 {
		return nil, err
	}

	var ntsd securitydescriptor.NtSecurityDescriptor
	if _, err := ntsd.Unmarshal([]byte(sdRaw)); err != nil {
		return nil, err
	}
	if ntsd.DACL == nil {
		return nil, nil
	}

	var results []ACEEntry
	for _, ace := range ntsd.DACL.Entries {
		// Only ALLOW ACEs (and ALLOW_OBJECT ACEs for extended rights/property writes).
		if ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED &&
			ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
			continue
		}

		trusteeSID := ace.Identity.SID.ToString()
		if skipSIDs[trusteeSID] {
			continue
		}

		inherited := ace.Header.Flags.RawValue&aceflags.ACE_FLAG_INHERITED != 0
		if inherited {
			continue // skip default schema inheritance — overwhelming noise, rarely actionable
		}
		mask := ace.Mask.RawValue

		// Check broad access masks.
		for _, dm := range dangerousMasks {
			if mask&dm.Mask == dm.Mask {
				results = append(results, ACEEntry{
					ObjectName:  objectName,
					ObjectType:  objectType,
					TrusteeSID:  trusteeSID,
					TrusteeName: resolveSIDCached(s, trusteeSID, sidCache),
					Right:       dm.Name,
					Inherited:   inherited,
					Severity:    dm.Severity,
				})
			}
		}

		// For ALLOW_OBJECT ACEs, also check the ObjectType GUID.
		if ace.Header.Type.Value == acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
			guid := ace.AccessControlObjectType.ObjectType.GUID.ToFormatD()

			// Extended rights (DS_CONTROL_ACCESS on specific right GUID).
			if mask&rights.RIGHT_DS_CONTROL_ACCESS == rights.RIGHT_DS_CONTROL_ACCESS {
				if info, ok := dangerousExtendedRightGUIDs[guid]; ok {
					results = append(results, ACEEntry{
						ObjectName:  objectName,
						ObjectType:  objectType,
						TrusteeSID:  trusteeSID,
						TrusteeName: resolveSIDCached(s, trusteeSID, sidCache),
						Right:       info.Name,
						Inherited:   inherited,
						Severity:    info.Severity,
					})
				}
			}

			// Property writes (DS_WRITE_PROPERTY on specific attribute GUID).
			if mask&rights.RIGHT_DS_WRITE_PROPERTY == rights.RIGHT_DS_WRITE_PROPERTY {
				if info, ok := dangerousPropertyGUIDs[guid]; ok {
					results = append(results, ACEEntry{
						ObjectName:  objectName,
						ObjectType:  objectType,
						TrusteeSID:  trusteeSID,
						TrusteeName: resolveSIDCached(s, trusteeSID, sidCache),
						Right:       info.Name,
						Inherited:   inherited,
						Severity:    info.Severity,
					})
				}
			}
		}
	}
	return results, nil
}

// getDomainSID returns the domain SID string (e.g. "S-1-5-21-A-B-C").
func getDomainSID(s *ldap.Session) (string, error) {
	entries, err := s.LdapSession.QueryBaseObject("", "(objectClass=domain)", []string{"objectSid"})
	if err != nil || len(entries) == 0 {
		return "", fmt.Errorf("could not query domain object for SID")
	}
	sidBytes := entries[0].GetRawAttributeValue("objectSid")
	if len(sidBytes) == 0 {
		return "", fmt.Errorf("domain objectSid is empty")
	}
	var domainSID sid.SID
	if _, err := domainSID.Unmarshal(sidBytes); err != nil {
		return "", fmt.Errorf("could not parse domain SID: %w", err)
	}
	return domainSID.ToString(), nil
}

// resolveSIDCached resolves a SID to a SAMAccountName via LDAP, with a cache.
func resolveSIDCached(s *ldap.Session, sidStr string, cache map[string]string) string {
	if name, ok := cache[sidStr]; ok {
		return name
	}
	// Build LDAP binary escape for objectSid filter.
	var sidObj sid.SID
	if err := sidObj.FromString(sidStr); err != nil {
		cache[sidStr] = sidStr
		return sidStr
	}
	rawBytes, err := sidObj.Marshal()
	if err != nil || len(rawBytes) == 0 {
		cache[sidStr] = sidStr
		return sidStr
	}
	var sb strings.Builder
	for _, b := range rawBytes {
		fmt.Fprintf(&sb, "\\%02x", b)
	}
	filter := fmt.Sprintf("(objectSid=%s)", sb.String())
	entries, err := s.LdapSession.QueryWholeSubtree("", filter, []string{"sAMAccountName"})
	if err != nil || len(entries) == 0 {
		cache[sidStr] = sidStr
		return sidStr
	}
	name := entries[0].GetAttributeValue("sAMAccountName")
	if name == "" {
		name = sidStr
	}
	cache[sidStr] = name
	return name
}
