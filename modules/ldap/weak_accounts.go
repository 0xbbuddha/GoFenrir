package ldapmodules

import (
	"fmt"
	"strconv"

	ldapattrs "github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type WeakAccountEntry struct {
	SAMAccountName string
	DN             string
	Flags          []string
}

// weakFlagChecks maps a UAC flag to a human-readable risk label.
var weakFlagChecks = []struct {
	Flag  ldapattrs.UserAccountControl
	Label string
}{
	{ldapattrs.UAF_PASSWD_NOTREQD, "PASSWD_NOTREQD"},
	{ldapattrs.UAF_ENCRYPTED_TEXT_PWD_ALLOWED, "ENCRYPTED_TEXT_PWD_ALLOWED (reversible)"},
	{ldapattrs.UAF_USE_DES_KEY_ONLY, "USE_DES_KEY_ONLY (weak crypto)"},
	{ldapattrs.UAF_DONT_EXPIRE_PASSWORD, "DONT_EXPIRE_PASSWORD"},
}

// EnumWeakAccounts finds user accounts with weak or dangerous UAC flags:
// - PASSWD_NOTREQD: account can have an empty password
// - ENCRYPTED_TEXT_PWD_ALLOWED: password stored with reversible encryption
// - USE_DES_KEY_ONLY: Kerberos only uses weak DES encryption
// - DONT_EXPIRE_PASSWORD: password never expires
func EnumWeakAccounts(s *ldap.Session) ([]WeakAccountEntry, error) {
	// Build an OR filter matching any of the target UAC bits
	filter := "(&(objectClass=user)(objectCategory=person)" +
		"(|" +
		fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldapattrs.UAF_PASSWD_NOTREQD) +
		fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldapattrs.UAF_ENCRYPTED_TEXT_PWD_ALLOWED) +
		fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldapattrs.UAF_USE_DES_KEY_ONLY) +
		fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", ldapattrs.UAF_DONT_EXPIRE_PASSWORD) +
		"))"

	entries, err := s.LdapSession.QueryWholeSubtree(
		"",
		filter,
		[]string{"sAMAccountName", "distinguishedName", "userAccountControl"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate weak accounts: %w", err)
	}

	var results []WeakAccountEntry
	for _, entry := range entries {
		uacVal, _ := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		uac := ldapattrs.UserAccountControl(uacVal)

		var flags []string
		for _, check := range weakFlagChecks {
			if uac&check.Flag != 0 {
				flags = append(flags, check.Label)
			}
		}

		if len(flags) == 0 {
			continue
		}

		results = append(results, WeakAccountEntry{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.GetAttributeValue("distinguishedName"),
			Flags:          flags,
		})
	}
	return results, nil
}
