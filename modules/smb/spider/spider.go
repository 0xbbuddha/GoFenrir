package spider

import (
	"path/filepath"
	"strings"

	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/fileflags"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
	smbenum "github.com/0xbbuddha/GoFenrir/modules/smb/enumeration"
)

// Result is one file or directory found during a spider walk.
type Result struct {
	Share string
	Path  string // share-relative path with forward slashes
	Size  uint64
	IsDir bool
}

// Options controls spider behavior.
type Options struct {
	// Share is the share to spider, or "all" to spider every readable share.
	Share string
	// Depth is the maximum recursion depth (0 = unlimited).
	Depth int
	// Filter is a glob pattern matched against the filename (case-insensitive).
	// Empty means match everything.
	Filter string
	// ExcludeDirs are directory names to skip (case-insensitive).
	ExcludeDirs []string
}

var defaultExcludeDirs = []string{
	"windows", "system volume information", "$recycle.bin", "program files",
	"program files (x86)", "programdata",
}

// Spider walks shares and returns matching entries.
func Spider(session *gofenrirsmb.Session, opts Options) ([]Result, error) {
	var shares []string

	if strings.ToLower(opts.Share) == "all" {
		all, err := smbenum.EnumShares(session)
		if err != nil {
			return nil, err
		}
		for _, s := range all {
			if s.CanRead && strings.ToLower(s.TypeLabel) != "ipc" && !strings.Contains(strings.ToLower(s.TypeLabel), "ipc") {
				shares = append(shares, s.Name)
			}
		}
	} else {
		shares = []string{opts.Share}
	}

	excludeDirs := opts.ExcludeDirs
	if len(excludeDirs) == 0 {
		excludeDirs = defaultExcludeDirs
	}

	var results []Result
	for _, share := range shares {
		if err := session.Client.TreeConnect(share); err != nil {
			continue
		}
		walk(session, share, ``, opts.Filter, excludeDirs, opts.Depth, 0, &results)
	}
	return results, nil
}

func walk(session *gofenrirsmb.Session, share, dir, filter string, excludeDirs []string, maxDepth, depth int, results *[]Result) {
	if maxDepth > 0 && depth >= maxDepth {
		return
	}

	entries, err := session.Client.ListDirectory(dir, "*")
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.Name == "." || e.Name == ".." {
			continue
		}

		var path string
		if dir == "" {
			path = e.Name
		} else {
			path = dir + `\` + e.Name
		}

		if e.IsDir() {
			if isExcluded(e.Name, excludeDirs) {
				continue
			}
			walk(session, share, path, filter, excludeDirs, maxDepth, depth+1, results)
		} else {
			if matchesFilter(e.Name, filter) {
				*results = append(*results, Result{
					Share: share,
					Path:  strings.ReplaceAll(path, `\`, `/`),
					Size:  e.Size,
				})
			}
		}
	}
}

// ReadFile reads the content of a file on the given share path via SMB.
func ReadFile(session *gofenrirsmb.Session, share, path string) ([]byte, error) {
	if err := session.Client.TreeConnect(share); err != nil {
		return nil, err
	}
	h, err := session.Client.OpenFile(path, smbclient.OpenOptions{
		DesiredAccess:     fileflags.GENERIC_READ,
		ShareAccess:       fileflags.FILE_SHARE_READ | fileflags.FILE_SHARE_WRITE,
		CreateDisposition: fileflags.FILE_OPEN,
	})
	if err != nil {
		return nil, err
	}
	defer session.Client.CloseFile(h)

	var buf []byte
	var off uint64
	const chunk = 65535
	for {
		data, err := session.Client.ReadFile(h, off, chunk)
		if len(data) > 0 {
			buf = append(buf, data...)
			off += uint64(len(data))
		}
		if err != nil || len(data) < chunk {
			break
		}
	}
	return buf, nil
}

func isExcluded(name string, excluded []string) bool {
	lower := strings.ToLower(name)
	for _, ex := range excluded {
		if lower == strings.ToLower(ex) {
			return true
		}
	}
	return false
}

func matchesFilter(name, filter string) bool {
	if filter == "" {
		return true
	}
	matched, err := filepath.Match(strings.ToLower(filter), strings.ToLower(name))
	return err == nil && matched
}
