package root

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/0xbbuddha/GoFenrir/core"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	Verbose bool
	Debug   bool
	Threads int
	Timeout int
	LogFile string
)

func getCommit() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) >= 8 {
					return s.Value[:8]
				}
				return s.Value
			}
		}
	}
	return "unknown"
}

const (
	cyan   = "\x1b[96m"
	blue   = "\x1b[94m"
	bold   = "\x1b[1m"
	reset  = "\x1b[0m"
)

const banner = cyan + `
    |\      _,,,---,,_
    /,` + "`" + `.-'` + "`" + `'    -.  ;-;;,_
   |,4-  ) )-,_..;\ (  ` + "`" + `'-'
  '---''(_/--'  ` + "`" + `-'\_)
` + reset + blue + bold + `
    GoFenrir: network execution tool
    Powered by TheManticoreProject/Manticore
    https://github.com/0xbbuddha/GoFenrir
` + reset

var rootCmd = &cobra.Command{
	Use:   "gf",
	Short: "GoFenrir: network execution framework powered by Manticore",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Help()
		return nil
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if LogFile != "" {
			if err := core.SetLogFile(LogFile); err != nil {
				return err
			}
		}
		core.SetVerbose(Verbose)
		core.SetDebug(Debug)
		return nil
	},
}

func customHelp(cmd *cobra.Command, args []string) {
	fmt.Print(banner)
	fmt.Printf("    "+cyan+"Version"+reset+"  : %s\n", core.Version)
	fmt.Printf("    "+cyan+"Codename"+reset+" : "+bold+"%s"+reset+"\n", core.Codename)
	fmt.Printf("    "+cyan+"Commit"+reset+"   : %s\n\n", getCommit())

	// Subcommand help: show usage + flags for that specific command
	if cmd.Name() != "gf" {
		fmt.Printf(blue+bold+"Usage:"+reset+"\n  %s\n\n", cmd.UseLine())
		if cmd.Short != "" {
			fmt.Printf("%s\n\n", cmd.Short)
		}
		fmt.Println(blue + bold + "Flags:" + reset)
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			if f.Value.Type() == "bool" {
				fmt.Printf("      --%-30s %s\n", f.Name, f.Usage)
			} else {
				fmt.Printf("      --%-22s %s %s\n", f.Name+" "+f.Value.Type(), f.Usage, cyan+"(default: "+f.DefValue+")"+reset)
			}
		})
		fmt.Println("\n" + blue + bold + "Global Flags:" + reset)
		fmt.Println("      --threads int       Number of concurrent threads (default 1)")
		fmt.Println("      --timeout int       Timeout per thread in seconds (default 30)")
		fmt.Println("      --log string        Export output to a file")
		fmt.Println("      --verbose           Verbose output")
		fmt.Println("      --debug             Debug output")
		fmt.Println("  -h, --help              Show this help")
		return
	}

	// Root help
	fmt.Printf(blue+bold+"Usage:"+reset+"\n  gf [protocol] [flags]\n\n")
	fmt.Println(blue + bold + "Available Protocols:" + reset)
	for _, sub := range cmd.Commands() {
		if sub.Name() == "help" || sub.Name() == "completion" {
			continue
		}
		fmt.Printf("  "+cyan+"%-10s"+reset+" %s\n", sub.Name(), sub.Short)
	}
	fmt.Println(blue + bold + "\nGlobal Flags:" + reset)
	fmt.Println("  -t, --target string     Target IP or hostname")
	fmt.Println("  -u, --username string   Username")
	fmt.Println("  -p, --password string   Password")
	fmt.Println("  -H, --hash string       NT hash (format: [LM:]NT)")
	fmt.Println("  -d, --domain string     Domain")
	fmt.Println(blue + bold + "\nOptions:" + reset)
	fmt.Println("      --threads int       Number of concurrent threads (default 1)")
	fmt.Println("      --timeout int       Timeout per thread in seconds (default 30)")
	fmt.Println("      --log string        Export output to a file")
	fmt.Println("      --verbose           Verbose output")
	fmt.Println("      --debug             Debug output")
	fmt.Println("  -h, --help              Show this help")
}

func Execute() {
	rootCmd.SetHelpFunc(customHelp)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&Verbose, "verbose", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&Debug, "debug", false, "Debug output")
	rootCmd.PersistentFlags().IntVar(&Threads, "threads", 1, "Number of concurrent threads")
	rootCmd.PersistentFlags().IntVar(&Timeout, "timeout", 30, "Timeout per thread in seconds")
	rootCmd.PersistentFlags().StringVar(&LogFile, "log", "", "Export output to a file")
}
