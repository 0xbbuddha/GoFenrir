package core

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
)

const (
	ColorReset  = "\x1b[0m"
	ColorGreen  = "\x1b[92m"
	ColorRed    = "\x1b[91m"
	ColorYellow = "\x1b[93m"
	ColorBlue   = "\x1b[94m"
)

func Success(msg string) {
	logger.Print(fmt.Sprintf("%s[+]%s %s", ColorGreen, ColorReset, msg))
}

func Failure(msg string) {
	logger.Print(fmt.Sprintf("%s[-]%s %s", ColorRed, ColorReset, msg))
}

func Section(title string, count int) {
	logger.Print(fmt.Sprintf("[>] %s (%s%d%s):", title, ColorYellow, count, ColorReset))
}

func TreeEntry(name string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	logger.Print(fmt.Sprintf("  %s %s%s%s", prefix, ColorBlue, name, ColorReset))
}

func TreeEntryColored(name, color string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	logger.Print(fmt.Sprintf("  %s %s%s%s", prefix, color, name, ColorReset))
}

func TreeDetail(label, value string, last bool) {
	prefix := "├──"
	if last {
		prefix = "└──"
	}
	logger.Print(fmt.Sprintf("      %s %s: %s%s%s", prefix, label, ColorYellow, value, ColorReset))
}
