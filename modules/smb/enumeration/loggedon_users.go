package enumeration

import (
	"fmt"

	wkssvc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/6bffd098-a112-3610-9833-46c3f87e345a/1.0"
	wkssvcfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/6bffd098-a112-3610-9833-46c3f87e345a/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	mswkst "github.com/TheManticoreProject/Manticore/windows/protocols/ms-wkst"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// LoggedOnUser is one interactively logged-on account on the target.
type LoggedOnUser struct {
	Username    string
	LogonDomain string
}

// LoggedOnUsers enumerates the users logged on to the target via MS-WKST
// (NetrWkstaUserEnum, level 1). Results are de-duplicated on domain\username.
func LoggedOnUsers(session *gofenrirsmb.Session) ([]LoggedOnUser, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(`\wkssvc`)
	if err != nil {
		return nil, fmt.Errorf("open wkssvc pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(wkssvc.SyntaxID()); err != nil {
		rpc.Close()
		return nil, fmt.Errorf("wkssvc bind: %w", err)
	}
	defer rpc.Close()

	seen := map[string]bool{}
	var results []LoggedOnUser
	var resume ndr.DWORD

	for {
		in := mswkst.WKSTA_USER_ENUM_STRUCT{
			Level: 1,
			WkstaUserInfo: mswkst.WKSTA_USER_ENUM_UNION{
				Tag:    1,
				Level1: &mswkst.WKSTA_USER_INFO_1_CONTAINER{},
			},
		}
		out, _, next, err := wkssvcfunctions.NetrWkstaUserEnum(rpc, nil, in, 0xFFFFFFFF, &resume)
		if err != nil {
			return nil, fmt.Errorf("NetrWkstaUserEnum: %w", err)
		}

		if out.WkstaUserInfo.Level1 != nil {
			for _, e := range out.WkstaUserInfo.Level1.Buffer {
				u := wstr(e.Wkui1_username)
				d := wstr(e.Wkui1_logon_domain)
				if u == "" {
					continue
				}
				key := d + "\\" + u
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, LoggedOnUser{Username: u, LogonDomain: d})
			}
		}

		// Continue only while the server signals more data via a non-zero resume handle.
		if next == nil || *next == 0 {
			break
		}
		resume = *next
	}
	return results, nil
}

// wstr dereferences an optional NDR wide string to a Go string.
func wstr(p *ndr.WSTR) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
