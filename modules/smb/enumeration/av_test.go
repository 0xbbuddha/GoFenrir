package enumeration

import (
	"strings"
	"testing"
)

// TestAVProductsTable guards the signature table against empty entries and
// ensures a well-known product stays present (catches typos/regressions).
func TestAVProductsTable(t *testing.T) {
	defender := false
	for _, p := range avProducts {
		if p.name == "" || len(p.services) == 0 {
			t.Errorf("product with empty name or no services: %+v", p)
		}
		for _, s := range p.services {
			if strings.TrimSpace(s) == "" {
				t.Errorf("empty service name in %q", p.name)
			}
		}
		if p.name == "Windows Defender" {
			defender = true
		}
	}
	if !defender {
		t.Fatal("Windows Defender missing from table")
	}
}
