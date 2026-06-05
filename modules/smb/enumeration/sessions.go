package enumeration

import (
	"fmt"

	srvsvc "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4b324fc8-1670-01d3-1278-5a47bf6ee188/3.0"
	srvsvcfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4b324fc8-1670-01d3-1278-5a47bf6ee188/3.0/functions"
	srvsvcstructures "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4b324fc8-1670-01d3-1278-5a47bf6ee188/3.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	dcerpcsmb "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/smb"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type SessionEntry struct {
	Client   string
	Username string
	// seconds the session has been active
	Time     uint32
	IdleTime uint32
}

// EnumSessions enumerates active SMB sessions on the target via srvsvc
// NetrSessionEnum (level 10). On a DC this reveals which admin accounts
// are currently connected - useful for credential theft targeting.
func EnumSessions(session *gofenrirsmb.Session) ([]SessionEntry, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	pipe := dcerpcsmb.New(session.Client, srvsvc.PipeName)
	rpc := dcerpcclient.NewClient(pipe)
	if err := rpc.Bind(srvsvc.SyntaxID()); err != nil {
		return nil, fmt.Errorf("srvsvc bind: %w", err)
	}
	defer rpc.Close()

	info := srvsvcstructures.SESSION_ENUM_STRUCT{
		Level: ndr.DWORD(10),
		SessionInfo: srvsvcstructures.SESSION_ENUM_UNION{
			Tag:     ndr.DWORD(10),
			Level10: &srvsvcstructures.SESSION_INFO_10_CONTAINER{},
		},
	}

	result, _, _, err := srvsvcfunctions.NetrSessionEnum(rpc, "", "", "", info, 0xFFFFFFFF, 0)
	if err != nil {
		return nil, fmt.Errorf("NetrSessionEnum: %w", err)
	}

	if result.SessionInfo.Level10 == nil {
		return nil, nil
	}

	var entries []SessionEntry
	for _, s := range result.SessionInfo.Level10.Buffer {
		entries = append(entries, SessionEntry{
			Client:   string(s.Sesi10Cname),
			Username: string(s.Sesi10Username),
			Time:     uint32(s.Sesi10Time),
			IdleTime: uint32(s.Sesi10IdleTime),
		})
	}
	return entries, nil
}
