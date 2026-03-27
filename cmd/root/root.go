package root

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gofenrir",
	Short: "GoFenrir — Network execution framework powered by Manticore",
	Long: `
  ____       _____            _
 / ___| ___ |  ___|___ _ __  _ _ __
| |  _ / _ \| |_ / _ \ '_ \| | '__|
| |_| | (_) |  _|  __/ | | | | |
 \____|\___/|_|  \___|_| |_|_|_|

GoFenrir — A NetExec-like framework in Go, powered by TheManticoreProject/Manticore.
`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
