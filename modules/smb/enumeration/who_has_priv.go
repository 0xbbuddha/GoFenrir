package enumeration

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/dcerpc/dtyp"
	lsarpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0"
	lsafunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/functions"
	lsastructures "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type PrivHolder struct {
	SID  string
	Name string
}

type PrivEntry struct {
	Privilege string
	Holders   []PrivHolder
}

// WhoHasPriv returns which accounts hold the named privilege on the target.
// Pass "all" to iterate every known privilege and return only those with holders.
func WhoHasPriv(session *gofenrirsmb.Session, privFilter string) ([]PrivEntry, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(lsarpc.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open lsarpc pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(lsarpc.SyntaxID()); err != nil {
		return nil, fmt.Errorf("lsarpc bind: %w", err)
	}
	defer rpc.Close()

	policy, err := lsafunctions.LsarOpenPolicy2(rpc, lsarpc.PolicyViewLocalInformation|lsarpc.PolicyLookupNames)
	if err != nil {
		return nil, fmt.Errorf("LsarOpenPolicy2: %w", err)
	}
	defer lsafunctions.LsarClose(rpc, policy)

	var privNames []string
	if privFilter == "all" {
		privNames, err = enumPrivilegeNames(rpc, policy)
		if err != nil {
			return nil, err
		}
	} else {
		privNames = []string{privFilter}
	}

	var results []PrivEntry
	for _, name := range privNames {
		holders, err := holdersForPriv(rpc, policy, name)
		if err != nil || len(holders) == 0 {
			continue
		}
		results = append(results, PrivEntry{Privilege: name, Holders: holders})
	}
	return results, nil
}

func enumPrivilegeNames(rpc *dcerpcclient.Client, policy lsastructures.LSAPR_HANDLE) ([]string, error) {
	var names []string
	var ctx uint32
	for {
		newCtx, buf, err := lsafunctions.LsarEnumeratePrivileges(rpc, policy, ctx, 0xFFFF)
		if err != nil {
			break
		}
		for _, priv := range buf.Privileges {
			names = append(names, priv.Name.String())
		}
		if newCtx == ctx || uint32(buf.Entries) == 0 {
			break
		}
		ctx = newCtx
	}
	return names, nil
}

func holdersForPriv(rpc *dcerpcclient.Client, policy lsastructures.LSAPR_HANDLE, privName string) ([]PrivHolder, error) {
	right := dtyp.NewUnicodeString(privName)
	buf, err := lsafunctions.LsarEnumerateAccountsWithUserRight(rpc, policy, &right)
	if err != nil {
		return nil, err
	}
	if int(buf.EntriesRead) == 0 {
		return nil, nil
	}

	sidInfos := make([]lsastructures.LSAPR_SID_INFORMATION, 0, int(buf.EntriesRead))
	sidStrings := make([]string, 0, int(buf.EntriesRead))
	for _, info := range buf.Information {
		if info.Sid == nil {
			continue
		}
		sidInfos = append(sidInfos, lsastructures.LSAPR_SID_INFORMATION{Sid: info.Sid})
		sidStrings = append(sidStrings, info.Sid.String())
	}
	if len(sidInfos) == 0 {
		return nil, nil
	}

	enumBuf := lsastructures.LSAPR_SID_ENUM_BUFFER{
		Entries: ndr.DWORD(len(sidInfos)),
		SidInfo: sidInfos,
	}
	_, translated, _, lookupErr := lsafunctions.LsarLookupSids(rpc, policy, enumBuf, lsastructures.LsapLookupWksta)

	holders := make([]PrivHolder, len(sidInfos))
	for i := range sidInfos {
		holders[i] = PrivHolder{SID: sidStrings[i], Name: sidStrings[i]}
		if lookupErr == nil && i < int(translated.Entries) && i < len(translated.Names) {
			if n := translated.Names[i].Name.String(); n != "" {
				holders[i].Name = n
			}
		}
	}
	return holders, nil
}
