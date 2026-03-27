package core

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"

	"github.com/TheManticoreProject/Manticore/logger"
)

const (
	ColorReset  = "\x1b[0m"
	ColorGreen  = "\x1b[92m"
	ColorRed    = "\x1b[91m"
	ColorYellow = "\x1b[93m"
	ColorBlue   = "\x1b[94m"
)

var (
	outputMu  sync.Mutex
	logWriter io.WriteCloser
	isVerbose bool
	isDebug   bool
	ansiRE    = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

// SetLogFile opens a file for logging (appends if it exists).
func SetLogFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}
	logWriter = f
	return nil
}

// SetVerbose enables or disables verbose output.
func SetVerbose(v bool) { isVerbose = v }

// SetDebug enables or disables debug output.
func SetDebug(d bool) { isDebug = d }

// writeOutput writes to the logger and optionally to the log file (ANSI-stripped).
// Must be called with outputMu held.
func writeOutput(msg string) {
	logger.Print(msg)
	if logWriter != nil {
		fmt.Fprintln(logWriter, ansiRE.ReplaceAllString(msg, ""))
	}
}

// --- Thread-safe global output functions ---

func Success(msg string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("%s[+]%s %s", ColorGreen, ColorReset, msg))
}

func Failure(msg string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("%s[-]%s %s", ColorRed, ColorReset, msg))
}

func Section(title string, count int) {
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("[>] %s (%s%d%s):", title, ColorYellow, count, ColorReset))
}

func TreeEntry(name string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("  %s %s%s%s", prefix, ColorBlue, name, ColorReset))
}

func TreeEntryColored(name, color string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("  %s %s%s%s", prefix, color, name, ColorReset))
}

func TreeDetail(label, value string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("      %s %s: %s%s%s", prefix, label, ColorYellow, value, ColorReset))
}

func Verbose(msg string) {
	if !isVerbose && !isDebug {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("%s[V]%s %s", ColorBlue, ColorReset, msg))
}

func Debug(msg string) {
	if !isDebug {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	writeOutput(fmt.Sprintf("%s[D]%s %s", ColorYellow, ColorReset, msg))
}

// --- OutputBuffer: collects output for one goroutine and flushes atomically ---

// OutputBuffer accumulates output lines from a single goroutine and prints
// them all at once under the global lock, preventing interleaved output
// when multiple goroutines are running concurrently.
type OutputBuffer struct {
	msgs []string
}

func (b *OutputBuffer) add(msg string) {
	b.msgs = append(b.msgs, msg)
}

func (b *OutputBuffer) Success(msg string) {
	b.add(fmt.Sprintf("%s[+]%s %s", ColorGreen, ColorReset, msg))
}

func (b *OutputBuffer) Failure(msg string) {
	b.add(fmt.Sprintf("%s[-]%s %s", ColorRed, ColorReset, msg))
}

func (b *OutputBuffer) Section(title string, count int) {
	b.add(fmt.Sprintf("[>] %s (%s%d%s):", title, ColorYellow, count, ColorReset))
}

func (b *OutputBuffer) TreeEntry(name string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	b.add(fmt.Sprintf("  %s %s%s%s", prefix, ColorBlue, name, ColorReset))
}

func (b *OutputBuffer) TreeEntryColored(name, color string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	b.add(fmt.Sprintf("  %s %s%s%s", prefix, color, name, ColorReset))
}

func (b *OutputBuffer) TreeDetail(label, value string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	b.add(fmt.Sprintf("      %s %s: %s%s%s", prefix, label, ColorYellow, value, ColorReset))
}

// Flush writes all buffered messages atomically to the output.
func (b *OutputBuffer) Flush() {
	if len(b.msgs) == 0 {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	for _, msg := range b.msgs {
		writeOutput(msg)
	}
	b.msgs = b.msgs[:0]
}
