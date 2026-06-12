package enumeration

import (
	"fmt"

	mssrvs "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-srvs"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type SessionEntry struct {
	Client   string
	Username string
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

	srvs := mssrvs.New(session.Client)
	sessions, err := srvs.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("ListSessions: %w", err)
	}

	entries := make([]SessionEntry, len(sessions))
	for i, s := range sessions {
		entries[i] = SessionEntry{
			Client:   s.ClientName,
			Username: s.UserName,
			Time:     s.ActiveSecs,
			IdleTime: s.IdleSecs,
		}
	}
	return entries, nil
}
