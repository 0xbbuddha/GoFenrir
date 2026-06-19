package enumeration

import (
	"fmt"

	mssrvs "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-srvs"

	"github.com/0xbbuddha/GoFenrir/protocols/smb"
)

var CommonShares = []string{
	"ADMIN$",
	"C$",
	"D$",
	"IPC$",
	"NETLOGON",
	"SYSVOL",
	"print$",
}

type ShareAccess struct {
	Name       string
	Accessible bool
}

func CheckShareAccess(s *smb.Session, shares []string) []ShareAccess {
	var results []ShareAccess
	for _, share := range shares {
		err := s.TreeConnect(share)
		results = append(results, ShareAccess{
			Name:       share,
			Accessible: err == nil,
		})
	}
	return results
}

// ShareEntry describes a share returned by NetrShareEnum.
type ShareEntry struct {
	Name      string
	TypeLabel string // "Disk", "Print", "IPC", "Device", etc.
	Comment   string
	Hidden    bool // name ends with '$'
	CanRead   bool
}

const (
	stypeDiskTree  = uint32(0x00000000)
	stypePrintQ    = uint32(0x00000001)
	stypeDevice    = uint32(0x00000002)
	stypeIPC       = uint32(0x00000003)
	stypeSpecial   = uint32(0x80000000)
	stypeTemporary = uint32(0x40000000)
)

// EnumShares lists all shares on the target via srvsvc NetrShareEnum (level 1),
// then attempts a TreeConnect on each to determine read access.
func EnumShares(session *smb.Session) ([]ShareEntry, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	srvs := mssrvs.New(session.Client)
	shares, err := srvs.ListShares()
	if err != nil {
		return nil, fmt.Errorf("ListShares: %w", err)
	}

	entries := make([]ShareEntry, 0, len(shares))
	for _, s := range shares {
		e := ShareEntry{
			Name:    s.Name,
			Comment: s.Comment,
			Hidden:  len(s.Name) > 0 && s.Name[len(s.Name)-1] == '$',
		}

		base := s.Type &^ (stypeSpecial | stypeTemporary)
		switch base {
		case stypeDiskTree:
			e.TypeLabel = "Disk"
		case stypePrintQ:
			e.TypeLabel = "Print"
		case stypeDevice:
			e.TypeLabel = "Device"
		case stypeIPC:
			e.TypeLabel = "IPC"
		default:
			e.TypeLabel = fmt.Sprintf("Type(%d)", base)
		}
		if s.Type&stypeSpecial != 0 {
			e.TypeLabel += "/Special"
		}
		if s.Type&stypeTemporary != 0 {
			e.TypeLabel += "/Temp"
		}

		e.CanRead = session.Client.TreeConnect(s.Name) == nil
		entries = append(entries, e)
	}
	return entries, nil
}
