package ldapmodules

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	ldapattrs "github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type CAEntry struct {
	Name        string
	DNSHostname string
	DN          string
	Templates   []string
}

type TemplateEntry struct {
	Name          string
	DN            string
	EKUs          []string
	IsESC1        bool
	IsESC2        bool
	IsESC3        bool
	IsESC9        bool
	IsESC4        bool
	ESC4Principals []string // SIDs with dangerous write rights
}

// EnumADCS enumerates Certificate Authorities and enabled certificate templates.
// It detects ESC1/ESC2/ESC3/ESC4/ESC9 vulnerable templates.
func EnumADCS(s *ldap.Session) ([]CAEntry, []TemplateEntry, error) {
	// --- Certificate Authorities ---
	caEntries, err := s.LdapSession.QueryWholeSubtree(
		"configurationNamingContext",
		"(objectCategory=pKIEnrollmentService)",
		[]string{"name", "dNSHostName", "distinguishedName", "certificateTemplates"},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enumerate CAs: %w", err)
	}

	// Build set of enabled template names
	enabledTemplates := map[string]bool{}
	var cas []CAEntry
	for _, entry := range caEntries {
		templates := entry.GetAttributeValues("certificateTemplates")
		for _, t := range templates {
			enabledTemplates[t] = true
		}
		cas = append(cas, CAEntry{
			Name:        entry.GetAttributeValue("name"),
			DNSHostname: entry.GetAttributeValue("dNSHostName"),
			DN:          entry.GetAttributeValue("distinguishedName"),
			Templates:   templates,
		})
	}

	// --- Certificate Templates ---
	templateEntries, err := s.LdapSession.QueryWholeSubtree(
		"configurationNamingContext",
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"name",
			"distinguishedName",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
		},
	)
	if err != nil {
		return cas, nil, fmt.Errorf("failed to enumerate certificate templates: %w", err)
	}

	var templates []TemplateEntry
	for _, entry := range templateEntries {
		name := entry.GetAttributeValue("name")

		// Only process enabled (published) templates
		if !enabledTemplates[name] {
			continue
		}

		ekus := entry.GetAttributeValues("pKIExtendedKeyUsage")
		dn := entry.GetAttributeValue("distinguishedName")

		nameFlag, _ := strconv.ParseInt(entry.GetAttributeValue("msPKI-Certificate-Name-Flag"), 10, 64)
		enrollFlag, _ := strconv.ParseInt(entry.GetAttributeValue("msPKI-Enrollment-Flag"), 10, 64)
		raSignature, _ := strconv.ParseInt(entry.GetAttributeValue("msPKI-RA-Signature"), 10, 64)

		// ESC1 conditions
		enrolleeSuppliesSub := (nameFlag & int64(ldapattrs.MSPKI_CERTIFICATE_NAME_FLAG_ENROLLEE_SUPPLIES_SUBJECT)) != 0
		requiresApproval := (enrollFlag & 0x00000002) != 0 // CT_FLAG_PEND_ALL_REQUESTS
		hasClientAuth := false
		for _, eku := range ekus {
			if eku == ldapattrs.EKU_CLIENT_AUTHENTICATION {
				hasClientAuth = true
				break
			}
		}
		// Empty EKU = any purpose = includes client auth
		if len(ekus) == 0 {
			hasClientAuth = true
		}

		isESC1 := enrolleeSuppliesSub && hasClientAuth && !requiresApproval && raSignature == 0

		// ESC2: Any Purpose EKU or no EKU restriction + no approval + no issuance requirements
		hasAnyPurpose := false
		for _, eku := range ekus {
			if eku == ldapattrs.EKU_ANY {
				hasAnyPurpose = true
				break
			}
		}
		isESC2 := (hasAnyPurpose || len(ekus) == 0) && !requiresApproval && raSignature == 0 && !isESC1

		// ESC3: Certificate Request Agent EKU (allows requesting certs on behalf of other users)
		hasCertRequestAgent := false
		for _, eku := range ekus {
			if eku == ldapattrs.EKU_CERTIFICATE_REQUEST_AGENT {
				hasCertRequestAgent = true
				break
			}
		}
		isESC3 := hasCertRequestAgent && !requiresApproval && raSignature == 0

		// ESC9: CT_FLAG_NO_SECURITY_EXTENSION — CA won't embed szOID_NTDS_CA_SECURITY_EXT in the
		// issued certificate. Without this SID-binding extension, an attacker with GenericWrite over
		// a victim can change the victim's UPN, enroll a certificate, revert the UPN, and then
		// authenticate as the victim via PKINIT (CVE-2022-26923 variant).
		noSecurityExtension := (enrollFlag & int64(ldapattrs.MSPKI_ENROLLMENT_FLAG_NO_SECURITY_EXTENSION)) != 0
		isESC9 := noSecurityExtension && hasClientAuth && !requiresApproval && raSignature == 0

		// ESC4: Dangerous write rights on the template granted to non-admin principals.
		// An attacker with WriteDacl/WriteOwner/GenericWrite/GenericAll can modify the template
		// to introduce ESC1/ESC2 conditions.
		isESC4, esc4Principals := checkESC4(s, dn)

		templates = append(templates, TemplateEntry{
			Name:           name,
			DN:             dn,
			EKUs:           ekus,
			IsESC1:         isESC1,
			IsESC2:         isESC2,
			IsESC3:         isESC3,
			IsESC9:         isESC9,
			IsESC4:         isESC4,
			ESC4Principals: esc4Principals,
		})
	}

	return cas, templates, nil
}

// checkESC4 fetches the nTSecurityDescriptor of the template and returns any non-admin
// principals that hold dangerous write rights (GenericAll, GenericWrite, WriteDacl,
// WriteOwner, or WriteProperty).
func checkESC4(s *ldap.Session, dn string) (bool, []string) {
	sdRaw, err := s.LdapSession.GetNtSecurityDescriptorOf(dn)
	if err != nil {
		return false, nil
	}

	aces, err := parseDACL([]byte(sdRaw))
	if err != nil {
		return false, nil
	}

	const (
		maskGenericAll    = 0x10000000
		maskGenericWrite  = 0x20000000
		maskWriteDacl     = 0x00040000
		maskWriteOwner    = 0x00080000
		maskWriteProperty = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP
	)
	dangerous := uint32(maskGenericAll | maskGenericWrite | maskWriteDacl | maskWriteOwner | maskWriteProperty)

	var principals []string
	seen := map[string]bool{}
	for _, ace := range aces {
		if ace.AccessMask&dangerous == 0 {
			continue
		}
		if isPrivilegedSID(ace.SID) {
			continue
		}
		if !seen[ace.SID] {
			seen[ace.SID] = true
			principals = append(principals, ace.SID)
		}
	}

	return len(principals) > 0, principals
}

// isPrivilegedSID returns true for well-known admin SIDs that legitimately
// hold write rights on certificate templates.
func isPrivilegedSID(sid string) bool {
	switch sid {
	case "S-1-5-18",   // SYSTEM
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-3-0":      // CREATOR OWNER
		return true
	}
	// Domain-relative admin groups: check last RID
	if strings.HasPrefix(sid, "S-1-5-21-") {
		parts := strings.Split(sid, "-")
		if len(parts) > 0 {
			switch parts[len(parts)-1] {
			case "512", // Domain Admins
				"516", // Domain Controllers
				"518", // Schema Admins
				"519": // Enterprise Admins
				return true
			}
		}
	}
	return false
}

// aceEntry holds a single parsed ACE from the DACL.
type aceEntry struct {
	SID        string
	AccessMask uint32
}

// parseDACL parses a binary SECURITY_DESCRIPTOR (relative self-relative format)
// and returns the ALLOW ACEs from the DACL.
func parseDACL(sd []byte) ([]aceEntry, error) {
	// SECURITY_DESCRIPTOR_RELATIVE header (20 bytes):
	//   Revision   uint8
	//   Sbz1       uint8
	//   Control    uint16
	//   OffsetOwner uint32
	//   OffsetGroup uint32
	//   OffsetSacl  uint32
	//   OffsetDacl  uint32
	if len(sd) < 20 {
		return nil, fmt.Errorf("security descriptor too short (%d bytes)", len(sd))
	}

	offsetDacl := binary.LittleEndian.Uint32(sd[16:20])
	if offsetDacl == 0 {
		return nil, nil // no DACL (NULL DACL = allow all, but skip here)
	}
	if int(offsetDacl)+8 > len(sd) {
		return nil, fmt.Errorf("DACL offset out of bounds")
	}

	// ACL header (8 bytes):
	//   AclRevision uint8
	//   Sbz1        uint8
	//   AclSize     uint16
	//   AceCount    uint16
	//   Sbz2        uint16
	aclSize := binary.LittleEndian.Uint16(sd[offsetDacl+2 : offsetDacl+4])
	aceCount := binary.LittleEndian.Uint16(sd[offsetDacl+4 : offsetDacl+6])

	aclEnd := int(offsetDacl) + int(aclSize)
	if aclEnd > len(sd) {
		return nil, fmt.Errorf("ACL size exceeds descriptor length")
	}

	var aces []aceEntry
	offset := int(offsetDacl) + 8

	for i := 0; i < int(aceCount) && offset+4 <= aclEnd; i++ {
		aceType := sd[offset]
		aceSize := binary.LittleEndian.Uint16(sd[offset+2 : offset+4])

		if aceSize < 4 || offset+int(aceSize) > aclEnd {
			break
		}

		aceData := sd[offset : offset+int(aceSize)]

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE
			if len(aceData) >= 12 {
				mask := binary.LittleEndian.Uint32(aceData[4:8])
				if sid, err := parseSID(aceData[8:]); err == nil {
					aces = append(aces, aceEntry{SID: sid, AccessMask: mask})
				}
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
			if len(aceData) >= 16 {
				mask := binary.LittleEndian.Uint32(aceData[4:8])
				flags := binary.LittleEndian.Uint32(aceData[8:12])
				sidOffset := 12
				if flags&0x01 != 0 { // ObjectType GUID present
					sidOffset += 16
				}
				if flags&0x02 != 0 { // InheritedObjectType GUID present
					sidOffset += 16
				}
				if sidOffset+4 <= len(aceData) {
					if sid, err := parseSID(aceData[sidOffset:]); err == nil {
						aces = append(aces, aceEntry{SID: sid, AccessMask: mask})
					}
				}
			}
		}

		offset += int(aceSize)
	}

	return aces, nil
}

// parseSID converts a binary SID into its string representation (S-1-X-Y-Z...).
func parseSID(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("SID too short")
	}
	subAuthCount := int(data[1])
	if len(data) < 8+subAuthCount*4 {
		return "", fmt.Errorf("SID data truncated")
	}

	// Identifier authority is 6 bytes big-endian starting at offset 2
	authority := int64(data[2])<<40 | int64(data[3])<<32 | int64(data[4])<<24 |
		int64(data[5])<<16 | int64(data[6])<<8 | int64(data[7])

	parts := make([]string, 0, 2+subAuthCount)
	parts = append(parts, "S", "1", fmt.Sprintf("%d", authority))
	for i := 0; i < subAuthCount; i++ {
		sub := binary.LittleEndian.Uint32(data[8+i*4 : 12+i*4])
		parts = append(parts, fmt.Sprintf("%d", sub))
	}

	return strings.Join(parts, "-"), nil
}
