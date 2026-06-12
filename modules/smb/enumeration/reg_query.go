package enumeration

import (
	"fmt"
	"unicode/utf16"

	"github.com/TheManticoreProject/Manticore/network/dcerpc/dtyp"
	winreg "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0"
	winregfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0/functions"
	winregstructures "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

type AutoLogonResult struct {
	Enabled  bool
	Username string
	Domain   string
	Password string
}

const winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

// GetAutoLogon reads AutoLogon credentials from the Winlogon registry key via MS-RRP.
func GetAutoLogon(session *gofenrirsmb.Session) (*AutoLogonResult, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(winreg.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open winreg pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(winreg.SyntaxID()); err != nil {
		return nil, fmt.Errorf("winreg bind: %w", err)
	}
	defer rpc.Close()

	hklm, err := winregfunctions.OpenLocalMachine(rpc, nil, ndr.DWORD(winreg.KeyRead))
	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine: %w", err)
	}
	defer winregfunctions.BaseRegCloseKey(rpc, hklm)

	hkey, err := winregfunctions.BaseRegOpenKey(rpc, hklm,
		dtyp.NewUnicodeString(winlogonKey+"\x00"),
		0, ndr.DWORD(winreg.KeyRead))
	if err != nil {
		return nil, fmt.Errorf("BaseRegOpenKey: %w", err)
	}
	defer winregfunctions.BaseRegCloseKey(rpc, hkey)

	result := &AutoLogonResult{}

	if v, err := regQueryString(rpc, hkey, "AutoAdminLogon"); err == nil {
		result.Enabled = v == "1"
	}
	result.Username, _ = regQueryString(rpc, hkey, "DefaultUserName")
	result.Domain, _ = regQueryString(rpc, hkey, "DefaultDomainName")
	result.Password, _ = regQueryString(rpc, hkey, "DefaultPassword")

	return result, nil
}

func regQueryString(rpc *dcerpcclient.Client, hkey winregstructures.RPC_HKEY, name string) (string, error) {
	dataType := ndr.DWORD(0)
	bufSize := ndr.DWORD(1024)
	buf := make([]uint8, int(bufSize))
	dataLen := ndr.DWORD(0)

	_, lpData, lpcbData, _, err := winregfunctions.BaseRegQueryValue(
		rpc, hkey,
		dtyp.NewUnicodeString(name+"\x00"),
		&dataType, buf, &bufSize, &dataLen,
	)
	if err != nil {
		return "", err
	}

	n := len(lpData)
	if lpcbData != nil && int(*lpcbData) < n {
		n = int(*lpcbData)
	}
	return decodeUTF16LE(lpData[:n]), nil
}

func decodeUTF16LE(b []byte) string {
	var r []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		r = append(r, c)
	}
	return string(utf16.Decode(r))
}
