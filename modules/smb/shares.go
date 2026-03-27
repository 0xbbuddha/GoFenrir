package smbmodules

import (
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
