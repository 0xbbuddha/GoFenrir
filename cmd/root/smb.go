package root

import (
	"fmt"
	"os"

	"github.com/0xbbuddha/GoFenrir/core"
	smbmodules "github.com/0xbbuddha/GoFenrir/modules/smb"
	"github.com/0xbbuddha/GoFenrir/protocols/smb"
	"github.com/spf13/cobra"
)

var (
	smbTarget        string
	smbUsername      string
	smbPassword      string
	smbHash          string
	smbDomain        string
	smbPort          int
	smbCheckShares   bool
	smbNullSession   bool
)

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Interact with SMB (v1)",
	Run:   runSMB,
}

func runSMB(cmd *cobra.Command, args []string) {
	if smbNullSession {
		core.Section("Null Session Check", 1)
		nullOk := smbmodules.CheckNullSession(smbTarget, smbPort)
		ipcOk := smbmodules.CheckAnonymousIPCAccess(smbTarget, smbPort)
		if nullOk {
			core.TreeEntryColored("Null session allowed", core.ColorRed, false)
		} else {
			core.TreeEntryColored("Null session denied", core.ColorGreen, false)
		}
		if ipcOk {
			core.TreeEntryColored("Anonymous IPC$ access allowed", core.ColorRed, true)
		} else {
			core.TreeEntryColored("Anonymous IPC$ access denied", core.ColorGreen, true)
		}
		return
	}

	session, err := smb.NewSession(smbTarget, smbPort, smbDomain, smbUsername, smbPassword, smbHash)
	if err != nil {
		core.Failure(fmt.Sprintf("[SMB] %s\\%s - %s", smbDomain, smbUsername, err.Error()))
		os.Exit(1)
	}

	authMsg := fmt.Sprintf("[SMB] %s\\%s%s%s", smbDomain, core.ColorGreen, smbUsername, core.ColorReset)
	if smbHash != "" {
		authMsg += fmt.Sprintf(" (Pass-the-Hash: %s%s%s)", core.ColorYellow, smbHash, core.ColorReset)
	}
	core.Success(authMsg)

	if smbCheckShares {
		results := smbmodules.CheckShareAccess(session, smbmodules.CommonShares)
		accessible := []smbmodules.ShareAccess{}
		for _, r := range results {
			if r.Accessible {
				accessible = append(accessible, r)
			}
		}
		core.Section("Accessible Shares", len(accessible))
		for i, r := range results {
			last := i == len(results)-1
			if r.Accessible {
				core.TreeEntryColored(r.Name, core.ColorGreen, last)
			} else {
				core.TreeEntryColored(r.Name+" (denied)", core.ColorRed, last)
			}
		}
	}
}

func init() {
	smbCmd.Flags().StringVarP(&smbTarget, "target", "t", "", "Target IP or hostname")
	smbCmd.Flags().StringVarP(&smbUsername, "username", "u", "", "Username")
	smbCmd.Flags().StringVarP(&smbPassword, "password", "p", "", "Password")
	smbCmd.Flags().StringVarP(&smbHash, "hash", "H", "", "NT hash (format: [LM:]NT)")
	smbCmd.Flags().StringVarP(&smbDomain, "domain", "d", "", "Domain")
	smbCmd.Flags().IntVar(&smbPort, "port", 445, "SMB port")
	smbCmd.Flags().BoolVar(&smbCheckShares, "shares", false, "Check access to common shares")
	smbCmd.Flags().BoolVar(&smbNullSession, "null-session", false, "Check for null/anonymous session")

	rootCmd.AddCommand(smbCmd)
}
