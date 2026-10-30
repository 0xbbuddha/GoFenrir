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
		if p.name == "" || (len(p.services) == 0 && len(p.pipes) == 0) {
			t.Errorf("product with empty name or no signatures: %+v", p)
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

func TestPipeMatches(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		pipes    []string
		want     bool
	}{
		{"top-level glob", []string{"aswCallbackPipe*"}, []string{"spoolss", "aswCallbackPipe-1234"}, true},
		{"nested first component", []string{`CrowdStrike\{*`}, []string{"CrowdStrike"}, true},
		{"case insensitive", []string{"MBLG"}, []string{"mblg"}, true},
		{"no match", []string{"nod_scriptmon_pipe"}, []string{"srvsvc", "lsarpc"}, false},
		{"empty pipes", []string{"aswCallbackPipe*"}, nil, false},
	}
	for _, c := range cases {
		if got := pipeMatches(c.patterns, c.pipes); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
