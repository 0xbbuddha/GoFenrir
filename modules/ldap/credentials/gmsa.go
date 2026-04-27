package credentials

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"golang.org/x/crypto/md4" //nolint:staticcheck

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type GMSAEntry struct {
	SAMAccountName string
	DN             string
	NTHash         string
	// AllowedReaders lists the SAMAccountNames (or SIDs if unresolvable) that
	// are granted read access on msDS-ManagedPassword via msDS-GroupMSAMembership.
	AllowedReaders []string
}

// EnumGMSA enumerates gMSA accounts and retrieves:
//   - NT hash via msDS-ManagedPassword (if the caller is in the allowed group)
//   - Who can read the password via msDS-GroupMSAMembership (always readable)
//
// msDS-ManagedPassword is a dynamically constructed attribute — it cannot be fetched
// in a subtree search. We enumerate accounts first, then query each DN individually.
func EnumGMSA(s *ldap.Session) ([]GMSAEntry, error) {
	accounts, err := s.LdapSession.QueryWholeSubtree(
		"",
		"(objectClass=msDS-GroupManagedServiceAccount)",
		[]string{"sAMAccountName", "distinguishedName"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate gMSA accounts: %w", err)
	}

	var results []GMSAEntry
	for _, account := range accounts {
		sam := account.GetAttributeValue("sAMAccountName")
		dn := account.GetAttributeValue("distinguishedName")
		e := GMSAEntry{SAMAccountName: sam, DN: dn}

		// msDS-GroupMSAMembership is a regular attribute — readable by authenticated users.
		// Query it separately so a denied msDS-ManagedPassword read doesn't suppress it.
		memberEntries, err := s.LdapSession.QueryBaseObject(
			dn,
			"(objectClass=*)",
			[]string{"msDS-GroupMSAMembership"},
		)
		if err == nil && len(memberEntries) > 0 {
			if sd := memberEntries[0].GetRawAttributeValue("msDS-GroupMSAMembership"); len(sd) > 0 {
				e.AllowedReaders = resolveMSAMembership(s, sd)
			}
		}

		// msDS-ManagedPassword is a dynamically constructed attribute — only returned when
		// the caller is in PrincipalsAllowedToRetrieveManagedPassword.
		pwEntries, err := s.LdapSession.QueryBaseObject(
			dn,
			"(objectClass=*)",
			[]string{"msDS-ManagedPassword"},
		)
		if err == nil && len(pwEntries) > 0 {
			if blob := pwEntries[0].GetRawAttributeValue("msDS-ManagedPassword"); len(blob) > 0 {
				nthash, err := parseManagedPasswordBlob(blob)
				if err != nil {
					e.NTHash = fmt.Sprintf("[error: %s]", err)
				} else {
					e.NTHash = nthash
				}
			}
		}

		results = append(results, e)
	}
	return results, nil
}

// resolveMSAMembership parses the msDS-GroupMSAMembership security descriptor and
// returns the SAMAccountNames (or SID strings as fallback) of the ALLOW ACE principals.
func resolveMSAMembership(s *ldap.Session, sdBlob []byte) []string {
	var ntsd securitydescriptor.NtSecurityDescriptor
	if _, err := ntsd.Unmarshal(sdBlob); err != nil {
		return nil
	}
	if ntsd.DACL == nil {
		return nil
	}

	var readers []string
	seen := make(map[string]bool)

	for _, ace := range ntsd.DACL.Entries {
		if ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED {
			continue
		}
		sidStr := ace.Identity.SID.ToString()
		if seen[sidStr] {
			continue
		}
		seen[sidStr] = true

		name := resolveSID(s, &ace.Identity.SID)
		if name == "" {
			name = sidStr
		}
		readers = append(readers, name)
	}
	return readers
}

// resolveSID looks up a SID in LDAP to return its SAMAccountName.
// Falls back to the SID string if the lookup fails or returns nothing.
func resolveSID(s *ldap.Session, sidObj interface{ Marshal() ([]byte, error) }) string {
	rawBytes, err := sidObj.Marshal()
	if err != nil || len(rawBytes) == 0 {
		return ""
	}

	// Build LDAP binary escape string: \xx for each byte.
	var sb strings.Builder
	for _, b := range rawBytes {
		fmt.Fprintf(&sb, "\\%02x", b)
	}
	filter := fmt.Sprintf("(objectSid=%s)", sb.String())

	entries, err := s.LdapSession.QueryWholeSubtree("", filter, []string{"sAMAccountName"})
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[0].GetAttributeValue("sAMAccountName")
}

// parseManagedPasswordBlob parses an MSDS-MANAGEDPASSWORD_BLOB and returns the NT hash.
//
// Blob layout (all little-endian):
//
//	0x00  uint16  Version (always 1)
//	0x02  uint16  Reserved
//	0x04  uint32  Length (total blob size)
//	0x08  uint16  CurrentPasswordOffset
//	0x0A  uint16  PreviousPasswordOffset (0 = no previous password)
//	0x0C  uint16  QueryPasswordIntervalOffset
//	0x0E  uint16  UnchangedPasswordIntervalOffset
//	...   data at offsets above (UTF-16LE, NULL-terminated)
func parseManagedPasswordBlob(blob []byte) (string, error) {
	if len(blob) < 0x10 {
		return "", fmt.Errorf("blob too short: %d bytes", len(blob))
	}
	offset := int(binary.LittleEndian.Uint16(blob[0x08:0x0A]))
	if offset >= len(blob) {
		return "", fmt.Errorf("CurrentPasswordOffset %d out of bounds (blob len %d)", offset, len(blob))
	}

	// Password is UTF-16LE starting at offset, NULL-terminated (0x00 0x00).
	pwBytes := blob[offset:]
	end := len(pwBytes)
	for end >= 2 && pwBytes[end-2] == 0 && pwBytes[end-1] == 0 {
		end -= 2
	}
	pwBytes = pwBytes[:end]
	if len(pwBytes) == 0 {
		return "", fmt.Errorf("empty password in blob")
	}

	// NT hash = MD4(UTF-16LE password).
	h := md4.New()
	h.Write(pwBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}
