package enumeration

import (
	"fmt"

	lsarpc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0"
	lsafunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/functions"
	lsastructures "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ab/0.0/structures"
	samr "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0"
	samrfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0/functions"
	samrstructures "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	dcerpcsmb "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type LocalGroupMember struct {
	SID  string
	Name string
	Type string
}

type LocalGroup struct {
	RID     uint32
	Name    string
	Members []LocalGroupMember
}

// LocalGroups enumerates all local groups (aliases) on the target and resolves
// their members via LSA LsarLookupSids. Both the main SAM domain and BUILTIN
// are covered so Administrators (S-1-5-32-544) is always included.
func LocalGroups(session *gofenrirsmb.Session) ([]LocalGroup, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	// SAMR over \samr named pipe
	samrPipe := dcerpcsmb.New(session.Client, samr.PipeName)
	samrRPC := dcerpcclient.NewClient(samrPipe)
	if err := samrRPC.Bind(samr.SyntaxID()); err != nil {
		return nil, fmt.Errorf("SAMR bind: %w", err)
	}
	defer samrRPC.Close()

	// LSA over \lsarpc named pipe (separate FID, same SMB session)
	lsaPipe := dcerpcsmb.New(session.Client, lsarpc.PipeName)
	lsaRPC := dcerpcclient.NewClient(lsaPipe)
	if err := lsaRPC.Bind(lsarpc.SyntaxID()); err != nil {
		return nil, fmt.Errorf("LSA bind: %w", err)
	}
	defer lsaRPC.Close()

	policyHandle, err := lsafunctions.LsarOpenPolicy2(lsaRPC, lsarpc.PolicyLookupNames)
	if err != nil {
		return nil, fmt.Errorf("LsarOpenPolicy2: %w", err)
	}
	defer lsafunctions.LsarClose(lsaRPC, policyHandle)

	serverHandle, err := samrfunctions.SamrConnect2(samrRPC, "", maximumAllowed)
	if err != nil {
		return nil, fmt.Errorf("SamrConnect2: %w", err)
	}
	defer samrfunctions.SamrCloseHandle(samrRPC, serverHandle)

	_, domBuf, _, err := samrfunctions.SamrEnumerateDomainsInSamServer(samrRPC, serverHandle, 0, 0xFFFFFFFF)
	if err != nil || domBuf == nil {
		return nil, fmt.Errorf("enumerate domains: %w", err)
	}

	var groups []LocalGroup

	for _, dom := range domBuf.Buffer {
		domName := dom.Name.String()

		sid, err := samrfunctions.SamrLookupDomainInSamServer(samrRPC, serverHandle, domName)
		if err != nil || sid == nil {
			continue
		}

		domHandle, err := samrfunctions.SamrOpenDomain(samrRPC, serverHandle, maximumAllowed, *sid)
		if err != nil {
			continue
		}

		_, abuf, _, _ := samrfunctions.SamrEnumerateAliasesInDomain(samrRPC, domHandle, 0, 0xFFFFFFFF)
		if abuf == nil {
			samrfunctions.SamrCloseHandle(samrRPC, domHandle)
			continue
		}

		for _, alias := range abuf.Buffer {
			rid := uint32(alias.RelativeId)
			name := alias.Name.String()

			aliasHandle, err := samrfunctions.SamrOpenAlias(samrRPC, domHandle, maximumAllowed, rid)
			if err != nil {
				groups = append(groups, LocalGroup{RID: rid, Name: name})
				continue
			}

			members, err := samrfunctions.SamrGetMembersInAlias(samrRPC, aliasHandle)
			samrfunctions.SamrCloseHandle(samrRPC, aliasHandle)

			group := LocalGroup{RID: rid, Name: name}
			if err == nil && int(members.Count) > 0 {
				group.Members = resolveMemberSIDs(lsaRPC, policyHandle, members)
			}
			groups = append(groups, group)
		}

		samrfunctions.SamrCloseHandle(samrRPC, domHandle)
	}

	return groups, nil
}

// resolveMemberSIDs translates the SID list from SamrGetMembersInAlias into names.
func resolveMemberSIDs(lsaRPC *dcerpcclient.Client, policy lsastructures.LSAPR_HANDLE, members samrstructures.SAMPR_PSID_ARRAY_OUT) []LocalGroupMember {
	// Build LSAPR_SID_ENUM_BUFFER from the SAMPR_PSID_ARRAY_OUT
	sidInfos := make([]lsastructures.LSAPR_SID_INFORMATION, 0, int(members.Count))
	sidStrings := make([]string, 0, int(members.Count))

	for _, info := range members.Sids {
		if info.SidPointer == nil {
			continue
		}
		sidInfos = append(sidInfos, lsastructures.LSAPR_SID_INFORMATION{
			Sid: info.SidPointer,
		})
		sidStrings = append(sidStrings, info.SidPointer.String())
	}

	if len(sidInfos) == 0 {
		return nil
	}

	enumBuf := lsastructures.LSAPR_SID_ENUM_BUFFER{
		Entries: ndr.DWORD(len(sidInfos)),
		SidInfo: sidInfos,
	}

	_, translatedNames, _, err := lsafunctions.LsarLookupSids(lsaRPC, policy, enumBuf, lsastructures.LsapLookupWksta)

	results := make([]LocalGroupMember, len(sidInfos))
	for i := range sidInfos {
		results[i] = LocalGroupMember{
			SID:  sidStrings[i],
			Name: sidStrings[i],
			Type: "unknown",
		}
		if err == nil && i < int(translatedNames.Entries) && i < len(translatedNames.Names) {
			n := translatedNames.Names[i].Name.String()
			if n != "" {
				results[i].Name = n
			}
			results[i].Type = sidUseToType(samrstructures.SID_NAME_USE(translatedNames.Names[i].Use))
			if results[i].Type == "" {
				results[i].Type = "unknown"
			}
		}
	}

	return results
}
