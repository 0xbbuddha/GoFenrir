package enumeration

import (
	"fmt"
	"strings"

	samr "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345778-1234-abcd-ef00-0123456789ac/1.0/structures"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	dcerpcsmb "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

const maximumAllowed uint32 = 0x02000000
const ridBatchSize = 50

type SAMREntry struct {
	RID  uint32
	Name string
	Type string
}

type DomainResult struct {
	Name    string
	Users   []SAMREntry
	Groups  []SAMREntry
	Aliases []SAMREntry
}

// RIDBrute enumerates users, groups and aliases for all domains exposed by the
// target SAMR server. It first attempts SamrEnumerate* (requires admin or
// DOMAIN_LIST_ACCOUNTS). If user enumeration is denied it falls back to RID
// cycling from ridStart to ridEnd via SamrLookupIdsInDomain.
func RIDBrute(session *gofenrirsmb.Session, ridStart, ridEnd uint32) ([]DomainResult, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	pipe := dcerpcsmb.New(session.Client, samr.PipeName)
	rpc := dcerpcclient.NewClient(pipe)
	if err := rpc.Bind(samr.SyntaxID()); err != nil {
		return nil, fmt.Errorf("SAMR bind: %w", err)
	}
	defer rpc.Close()

	serverHandle, err := functions.SamrConnect2(rpc, "", maximumAllowed)
	if err != nil {
		return nil, fmt.Errorf("SamrConnect2: %w", err)
	}
	defer functions.SamrCloseHandle(rpc, serverHandle)

	_, domBuf, _, err := functions.SamrEnumerateDomainsInSamServer(rpc, serverHandle, 0, 0xFFFFFFFF)
	if err != nil {
		return nil, fmt.Errorf("enumerate domains: %w", err)
	}
	if domBuf == nil {
		return nil, nil
	}

	var results []DomainResult

	for _, dom := range domBuf.Buffer {
		domName := dom.Name.String()
		result := DomainResult{Name: domName}

		sid, err := functions.SamrLookupDomainInSamServer(rpc, serverHandle, domName)
		if err != nil || sid == nil {
			continue
		}

		domHandle, err := functions.SamrOpenDomain(rpc, serverHandle, maximumAllowed, *sid)
		if err != nil {
			continue
		}

		// Users
		_, ubuf, _, uErr := functions.SamrEnumerateUsersInDomain(rpc, domHandle, 0, 0, 0xFFFFFFFF)
		if uErr == nil && ubuf != nil {
			for _, u := range ubuf.Buffer {
				result.Users = append(result.Users, SAMREntry{
					RID:  uint32(u.RelativeId),
					Name: u.Name.String(),
					Type: "user",
				})
			}
		} else if isAccessDenied(uErr) {
			result.Users = ridCycle(rpc, domHandle, ridStart, ridEnd)
		}

		// Groups
		_, gbuf, _, _ := functions.SamrEnumerateGroupsInDomain(rpc, domHandle, 0, 0xFFFFFFFF)
		if gbuf != nil {
			for _, g := range gbuf.Buffer {
				result.Groups = append(result.Groups, SAMREntry{
					RID:  uint32(g.RelativeId),
					Name: g.Name.String(),
					Type: "group",
				})
			}
		}

		// Aliases (local groups on member servers, builtin groups on DCs)
		_, abuf, _, _ := functions.SamrEnumerateAliasesInDomain(rpc, domHandle, 0, 0xFFFFFFFF)
		if abuf != nil {
			for _, a := range abuf.Buffer {
				result.Aliases = append(result.Aliases, SAMREntry{
					RID:  uint32(a.RelativeId),
					Name: a.Name.String(),
					Type: "alias",
				})
			}
		}

		functions.SamrCloseHandle(rpc, domHandle)
		results = append(results, result)
	}

	return results, nil
}

// ridCycle resolves RIDs [start, end] in batches via SamrLookupIdsInDomain,
// collecting entries whose SID_NAME_USE indicates a real account.
func ridCycle(rpc *dcerpcclient.Client, domHandle structures.SAMPR_HANDLE, start, end uint32) []SAMREntry {
	var entries []SAMREntry

	for base := start; base <= end; base += ridBatchSize {
		last := base + ridBatchSize - 1
		if last > end {
			last = end
		}

		batch := make([]uint32, 0, last-base+1)
		for rid := base; rid <= last; rid++ {
			batch = append(batch, rid)
		}

		names, use, err := functions.SamrLookupIdsInDomain(rpc, domHandle, batch)
		if err != nil {
			continue
		}

		for i, rid := range batch {
			if i >= len(names.Element) || i >= len(use.Element) {
				break
			}
			name := names.Element[i].String()
			if name == "" {
				continue
			}
			sidUse := structures.SID_NAME_USE(use.Element[i])
			t := sidUseToType(sidUse)
			if t == "" {
				continue
			}
			entries = append(entries, SAMREntry{RID: rid, Name: name, Type: t})
		}
	}

	return entries
}

func sidUseToType(u structures.SID_NAME_USE) string {
	switch u {
	case structures.SidTypeUser:
		return "user"
	case structures.SidTypeGroup:
		return "group"
	case structures.SidTypeAlias:
		return "alias"
	case structures.SidTypeComputer:
		return "computer"
	case structures.SidTypeWellKnownGroup:
		return "group"
	default:
		return ""
	}
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "ACCESS_DENIED")
}
