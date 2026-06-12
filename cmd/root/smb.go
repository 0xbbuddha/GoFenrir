package root

import (
	"fmt"
	"os"

	"github.com/0xbbuddha/GoFenrir/core"
	smbcreds "github.com/0xbbuddha/GoFenrir/modules/smb/credentials"
	smbenum "github.com/0xbbuddha/GoFenrir/modules/smb/enumeration"
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
	smbCheckShares  bool
	smbNullSession  bool
	smbGPPPasswords bool
	smbRIDBrute     bool
	smbRIDStart     uint32
	smbRIDEnd       uint32
	smbLocalGroups  bool
	smbSessions     bool
	smbWhoHasPriv      string
	smbServerInfo      bool
	smbEnumServices    bool
	smbServicesFilter  string
	smbCheckAutoLogon  bool
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
			nullOk := smbenum.CheckNullSession(job.Target, smbPort)
			ipcOk := smbenum.CheckAnonymousIPCAccess(job.Target, smbPort)
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

		if smbServerInfo {
			info, err := smbenum.GetServerInfo(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Server Info: %s", err.Error()))
			} else {
				out.Section("Server Info", 1)
				label := info.Version
				if info.OSHint != "" {
					label = fmt.Sprintf("%s (%s)", info.Version, info.OSHint)
				}
				hasComment := info.Comment != ""
				out.TreeDetail("Name", info.Name, false)
				out.TreeDetail("OS", label, false)
				out.TreeDetail("Roles", smbenum.FormatServerType(info.Roles), !hasComment)
				if hasComment {
					out.TreeDetail("Comment", info.Comment, true)
				}
			}
		}

		if smbGPPPasswords {
			entries, err := smbcreds.FindGPPPasswords(job.Target, smbPort, smbDomain, job.Cred.Username, job.Cred.Password, job.Cred.Hash)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] GPP Passwords: %s", err.Error()))
			} else if len(entries) == 0 {
				out.Section("GPP Passwords", 0)
				out.TreeEntry("No cpassword found in SYSVOL", true)
			} else {
				out.Section("GPP Passwords", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					label := e.UserName
					if label == "" {
						label = e.RunAs
					}
					if label == "" {
						label = "(unknown)"
					}
					out.TreeEntryColored(label, core.ColorRed, last)
					if e.NewName != "" {
						out.TreeDetail("NewName", e.NewName, false)
					}
					out.TreeDetail("CPassword", e.CPassword, false)
					out.TreeDetail("Password", e.Password, false)
					out.TreeDetail("File", e.FilePath, true)
				}
			}
		}

		if smbRIDBrute {
			domains, err := smbenum.RIDBrute(session, smbRIDStart, smbRIDEnd)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] RID Brute: %s", err.Error()))
			} else {
				for _, dom := range domains {
					total := len(dom.Users) + len(dom.Groups) + len(dom.Aliases)
					out.Section(fmt.Sprintf("Domain: %s", dom.Name), total)
					all := make([]smbenum.SAMREntry, 0, total)
					all = append(all, dom.Users...)
					all = append(all, dom.Groups...)
					all = append(all, dom.Aliases...)
					for i, e := range all {
						last := i == len(all)-1
						label := fmt.Sprintf("[RID %-5d] %s (%s)", e.RID, e.Name, e.Type)
						var color string
						switch e.Type {
						case "user":
							color = core.ColorGreen
						case "computer":
							color = core.ColorYellow
						default:
							color = core.ColorBlue
						}
						out.TreeEntryColored(label, color, last)
					}
				}
			}
		}

		if smbSessions {
			sessions, err := smbenum.EnumSessions(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Sessions: %s", err.Error()))
			} else {
				out.Section("Active Sessions", len(sessions))
				for i, s := range sessions {
					last := i == len(sessions)-1
					label := fmt.Sprintf("%s -> %s", s.Client, s.Username)
					if s.Time > 0 {
						label += fmt.Sprintf(" (connected %s, idle %s)", fmtDuration(s.Time), fmtDuration(s.IdleTime))
					}
					out.TreeEntryColored(label, core.ColorYellow, last)
				}
			}
		}

		if smbWhoHasPriv != "" {
			privs, err := smbenum.WhoHasPriv(session, smbWhoHasPriv)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Who-Has-Priv: %s", err.Error()))
			} else if len(privs) == 0 {
				out.Section("Privileges", 0)
				out.TreeEntry("No accounts found holding the specified privilege(s)", true)
			} else {
				out.Section("Privileges", len(privs))
				for pi, pe := range privs {
					lastPriv := pi == len(privs)-1
					out.TreeEntryColored(pe.Privilege, core.ColorYellow, lastPriv && len(pe.Holders) == 0)
					for hi, h := range pe.Holders {
						lastHolder := hi == len(pe.Holders)-1
						label := h.Name
						if h.Name != h.SID {
							label = fmt.Sprintf("%s (%s)", h.Name, h.SID)
						}
						out.TreeDetail("holder", label, lastPriv && lastHolder)
					}
				}
			}
		}

		if smbCheckAutoLogon {
			al, err := smbenum.GetAutoLogon(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] AutoLogon: %s", err.Error()))
			} else {
				out.Section("AutoLogon", 1)
				if al.Enabled {
					out.TreeEntryColored("AutoAdminLogon: ENABLED", core.ColorRed, false)
				} else {
					out.TreeEntryColored("AutoAdminLogon: disabled", core.ColorGreen, false)
				}
				hasUser := al.Username != ""
				hasPass := al.Password != ""
				hasDomain := al.Domain != ""
				last := !hasUser && !hasPass && !hasDomain
				if last {
					out.TreeEntry("No credentials stored", true)
				} else {
					if hasDomain {
						out.TreeDetail("Domain", al.Domain, false)
					}
					if hasUser {
						out.TreeDetail("Username", al.Username, !hasPass)
					}
					if hasPass {
						out.TreeDetail("Password", al.Password, true)
					}
				}
			}
		}

		if smbEnumServices {
			svcs, err := smbenum.EnumServices(session, smbServicesFilter)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Services: %s", err.Error()))
			} else {
				out.Section("Services", len(svcs))
				for i, svc := range svcs {
					lastSvc := i == len(svcs)-1

					type kv struct{ k, v string }
					var details []kv
					if svc.DisplayName != "" && svc.DisplayName != svc.Name {
						details = append(details, kv{"Display", svc.DisplayName})
					}
					if svc.BinaryPath != "" {
						details = append(details, kv{"Path", svc.BinaryPath})
					}
					if svc.Account != "" {
						details = append(details, kv{"Account", svc.Account})
					}
					if svc.StartType != "" {
						details = append(details, kv{"Start", svc.StartType})
					}

					var color string
					switch svc.State {
					case "Running":
						color = core.ColorGreen
					case "Stopped":
						color = core.ColorRed
					default:
						color = core.ColorYellow
					}
					label := fmt.Sprintf("[%-12s] %s", svc.State, svc.Name)
					out.TreeEntryColored(label, color, lastSvc && len(details) == 0)
					for di, d := range details {
						out.TreeDetail(d.k, d.v, lastSvc && di == len(details)-1)
					}
				}
			}
		}

		if smbLocalGroups {
			groups, err := smbenum.LocalGroups(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Local Groups: %s", err.Error()))
			} else {
				for _, g := range groups {
					out.Section(fmt.Sprintf("Group: %s (RID %d)", g.Name, g.RID), len(g.Members))
					for i, m := range g.Members {
						last := i == len(g.Members)-1
						label := m.Name
						if m.Name == m.SID {
							label = m.SID
						} else {
							label = fmt.Sprintf("%s (%s)", m.Name, m.SID)
						}
						var color string
						switch m.Type {
						case "user":
							color = core.ColorGreen
						case "computer":
							color = core.ColorYellow
						default:
							color = core.ColorBlue
						}
						out.TreeEntryColored(label, color, last)
					}
				}
			}
		}

		if smbCheckShares {
			results := smbenum.CheckShareAccess(session, smbenum.CommonShares)
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

func fmtDuration(secs uint32) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm%ds", secs/60, secs%60)
	}
	return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
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
	smbCmd.Flags().BoolVar(&smbGPPPasswords, "gpp-passwords", false, "Search SYSVOL for GPP cpasswords and decrypt them (MS14-025)")
	smbCmd.Flags().BoolVar(&smbRIDBrute, "rid-brute", false, "Enumerate users/groups via SAMR (RID cycling fallback if enumeration denied)")
	smbCmd.Flags().Uint32Var(&smbRIDStart, "rid-start", 500, "Starting RID for cycling fallback")
	smbCmd.Flags().Uint32Var(&smbRIDEnd, "rid-end", 4000, "Ending RID for cycling fallback")
	smbCmd.Flags().BoolVar(&smbLocalGroups, "local-groups", false, "Enumerate local groups and their members via SAMR+LSA")
	smbCmd.Flags().BoolVar(&smbSessions, "sessions", false, "Enumerate active SMB sessions via srvsvc (useful on DCs to spot admin sessions)")
	smbCmd.Flags().StringVar(&smbWhoHasPriv, "who-has-priv", "", `List accounts holding a privilege (e.g. SeDebugPrivilege) or "all" for every non-empty privilege`)
	smbCmd.Flags().BoolVar(&smbServerInfo, "server-info", false, "Query server name, OS version and roles via srvsvc NetrServerGetInfo")
	smbCmd.Flags().BoolVar(&smbEnumServices, "services", false, "Enumerate services via MS-SCMR (svcctl) including binary path and run-as account")
	smbCmd.Flags().StringVar(&smbServicesFilter, "services-filter", "", `Filter services by state: "running" or "stopped" (default: all)`)
	smbCmd.Flags().BoolVar(&smbCheckAutoLogon, "check-autologon", false, "Read AutoLogon credentials from HKLM\\...\\Winlogon via MS-RRP (winreg)")
	for _, f := range []string{"shares", "null-session", "gpp-passwords", "rid-brute", "rid-start", "rid-end", "local-groups", "sessions", "who-has-priv", "server-info", "services", "services-filter", "check-autologon"} {
		smbCmd.Flags().SetAnnotation(f, "group", []string{"Enumeration"})
	}

	smbCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(smbCmd)
}
