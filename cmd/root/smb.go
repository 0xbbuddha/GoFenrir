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
	smbTarget      string
	smbUsername    string
	smbPassword    string
	smbHash        string
	smbDomain      string
	smbPort        int
	smbCheckShares bool
	smbNullSession bool
)

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Interact with SMB (v1)",
	Run:   runSMB,
}

func runSMB(cmd *cobra.Command, args []string) {
	if smbTarget == "" {
		core.Failure("--target is required")
		os.Exit(1)
	}

	targets, err := core.ParseTargets(smbTarget)
	if err != nil {
		core.Failure(err.Error())
		os.Exit(1)
	}

	if smbNullSession {
		jobs := make([]core.Job, len(targets))
		for i, t := range targets {
			jobs[i] = core.Job{Target: t}
		}
		core.RunConcurrent(jobs, Threads, func(job core.Job) {
			out := &core.OutputBuffer{}
			out.Section(fmt.Sprintf("Null Session - %s", job.Target), 1)
			nullOk := smbmodules.CheckNullSession(job.Target, smbPort)
			ipcOk := smbmodules.CheckAnonymousIPCAccess(job.Target, smbPort)
			if nullOk {
				out.TreeEntryColored("Null session allowed", core.ColorRed, false)
			} else {
				out.TreeEntryColored("Null session denied", core.ColorGreen, false)
			}
			if ipcOk {
				out.TreeEntryColored("Anonymous IPC$ access allowed", core.ColorRed, true)
			} else {
				out.TreeEntryColored("Anonymous IPC$ access denied", core.ColorGreen, true)
			}
			out.Flush()
		})
		return
	}

	creds, err := core.ParseCredentials(smbUsername, smbPassword, smbHash)
	if err != nil {
		core.Failure(err.Error())
		os.Exit(1)
	}

	jobs := make([]core.Job, 0, len(targets)*len(creds))
	for _, target := range targets {
		for _, cred := range creds {
			jobs = append(jobs, core.Job{Target: target, Cred: cred})
		}
	}

	core.RunConcurrent(jobs, Threads, func(job core.Job) {
		out := &core.OutputBuffer{}

		session, err := smb.NewSession(job.Target, smbPort, smbDomain, job.Cred.Username, job.Cred.Password, job.Cred.Hash)
		if err != nil {
			out.Failure(fmt.Sprintf("[SMB] %s %s\\%s - %s", job.Target, smbDomain, job.Cred.Username, err.Error()))
			out.Flush()
			return
		}

		authMsg := fmt.Sprintf("[SMB] %s %s\\%s%s%s", job.Target, smbDomain, core.ColorGreen, job.Cred.Username, core.ColorReset)
		if job.Cred.Hash != "" {
			authMsg += fmt.Sprintf(" (Pass-the-Hash: %s%s%s)", core.ColorYellow, job.Cred.Hash, core.ColorReset)
		}
		out.Success(authMsg)

		if smbCheckShares {
			results := smbmodules.CheckShareAccess(session, smbmodules.CommonShares)
			accessible := 0
			for _, r := range results {
				if r.Accessible {
					accessible++
				}
			}
			out.Section("Accessible Shares", accessible)
			for i, r := range results {
				last := i == len(results)-1
				if r.Accessible {
					out.TreeEntryColored(r.Name, core.ColorGreen, last)
				} else {
					out.TreeEntryColored(r.Name+" (denied)", core.ColorRed, last)
				}
			}
		}

		out.Flush()
	})
}

func init() {
	smbCmd.Flags().StringVarP(&smbTarget, "target", "t", "", "Target IP, hostname, CIDR, or file path")
	smbCmd.Flags().StringVarP(&smbUsername, "username", "u", "", "Username or file of usernames")
	smbCmd.Flags().StringVarP(&smbPassword, "password", "p", "", "Password or file of passwords")
	smbCmd.Flags().StringVarP(&smbHash, "hash", "H", "", "NT hash (format: [LM:]NT)")
	smbCmd.Flags().StringVarP(&smbDomain, "domain", "d", "", "Domain")
	smbCmd.Flags().IntVar(&smbPort, "port", 445, "SMB port")
	for _, f := range []string{"target", "username", "password", "hash", "domain", "port"} {
		smbCmd.Flags().SetAnnotation(f, "group", []string{"Connection"})
	}

	smbCmd.Flags().BoolVar(&smbCheckShares, "shares", false, "Enumerate shares and check access")
	smbCmd.Flags().BoolVar(&smbNullSession, "null-session", false, "Check for null/anonymous session")
	for _, f := range []string{"shares", "null-session"} {
		smbCmd.Flags().SetAnnotation(f, "group", []string{"Enumeration"})
	}

	smbCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(smbCmd)
}
