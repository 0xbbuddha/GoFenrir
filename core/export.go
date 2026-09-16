package core

import (
	"fmt"
	"os"
	"sync"
)

var exportMu sync.Mutex

// AppendLinesToFile appends one line per string to path, creating it if
// needed. Safe to call concurrently (e.g. from multiple target/cred jobs).
func AppendLinesToFile(path string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}

	exportMu.Lock()
	defer exportMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("cannot open export file: %w", err)
	}
	defer f.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return fmt.Errorf("cannot write to export file: %w", err)
		}
	}
	return nil
}
