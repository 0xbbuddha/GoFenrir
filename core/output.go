package core

import "fmt"

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

func PrintSuccess(proto, host string, port int, name, msg string) {
	fmt.Printf("%s%-6s%s %-15s %-5d %-15s %s[+]%s %s\n",
		colorCyan, proto, colorReset,
		host, port, name,
		colorGreen, colorReset,
		msg,
	)
}

func PrintFailure(proto, host string, port int, name, msg string) {
	fmt.Printf("%s%-6s%s %-15s %-5d %-15s %s[-]%s %s\n",
		colorCyan, proto, colorReset,
		host, port, name,
		colorRed, colorReset,
		msg,
	)
}

func PrintInfo(proto, host string, port int, name, msg string) {
	fmt.Printf("%s%-6s%s %-15s %-5d %-15s %s[*]%s %s\n",
		colorCyan, proto, colorReset,
		host, port, name,
		colorYellow, colorReset,
		msg,
	)
}
