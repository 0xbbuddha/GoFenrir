package ldapmodules

import (
	"fmt"
	"strconv"

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
	Name   string
	DN     string
	EKUs   []string
	IsESC1 bool
	IsESC2 bool
	IsESC3 bool
}

// EnumADCS enumerates Certificate Authorities and enabled certificate templates.
// It detects ESC1 vulnerable templates (enrollee supplies subject + client auth EKU +
// no manager approval + no issuance requirements).
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

		templates = append(templates, TemplateEntry{
			Name:   name,
			DN:     entry.GetAttributeValue("distinguishedName"),
			EKUs:   ekus,
			IsESC1: isESC1,
			IsESC2: isESC2,
			IsESC3: isESC3,
		})
	}

	return cas, templates, nil
}
