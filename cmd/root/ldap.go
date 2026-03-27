package root

import (
	"fmt"
	"os"

	"github.com/0xbbuddha/GoFenrir/core"
	ldapmodules "github.com/0xbbuddha/GoFenrir/modules/ldap"
	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
	"github.com/spf13/cobra"
)

var (
	ldapTarget   string
	ldapUsername string
	ldapPassword string
	ldapHash     string
	ldapDomain   string
	ldapTLS      bool
	ldapPort     int

	ldapEnumUsers      bool
	ldapEnumGroups     bool
	ldapEnumDCs        bool
	ldapEnumKerberoast bool
	ldapEnumASREP      bool
	ldapEnumAdmins     bool
	ldapEnumComputers  bool
	ldapEnumPwdPolicy  bool
	ldapEnumTrusts     bool
	ldapEnumGPOs       bool
	ldapEnumOUs        bool
)

var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Interact with LDAP/LDAPS",
	Run:   runLDAP,
}

func runLDAP(cmd *cobra.Command, args []string) {
	proto := "LDAP"
	if ldapTLS {
		proto = "LDAPS"
	}

	targets, err := core.ParseTargets(ldapTarget)
	if err != nil {
		core.Failure(err.Error())
		os.Exit(1)
	}

	creds, err := core.ParseCredentials(ldapUsername, ldapPassword, ldapHash)
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

		session, err := ldap.NewSession(job.Target, ldapPort, ldapDomain, job.Cred.Username, job.Cred.Password, job.Cred.Hash, ldapTLS)
		if err != nil {
			out.Failure(fmt.Sprintf("[%s] %s - %s", proto, job.Target, err.Error()))
			out.Flush()
			return
		}

		if err := session.Connect(); err != nil {
			out.Failure(fmt.Sprintf("[%s] %s %s\\%s - %s", proto, job.Target, ldapDomain, job.Cred.Username, err.Error()))
			out.Flush()
			return
		}
		defer session.Close()

		authMsg := fmt.Sprintf("[%s] %s %s\\%s%s%s", proto, job.Target, ldapDomain, core.ColorGreen, job.Cred.Username, core.ColorReset)
		if job.Cred.Hash != "" {
			authMsg += fmt.Sprintf(" (Pass-the-Hash: %s%s%s)", core.ColorYellow, job.Cred.Hash, core.ColorReset)
		}
		out.Success(authMsg)

		if ldapEnumUsers {
			users, err := ldapmodules.EnumUsers(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Users", len(users))
				for i, u := range users {
					color := core.ColorGreen
					label := u.SAMAccountName
					if !u.IsEnabled() {
						color = core.ColorRed
						label += " (disabled)"
					}
					out.TreeEntryColored(label, color, i == len(users)-1)
				}
			}
		}

		if ldapEnumGroups {
			groups, err := ldapmodules.EnumGroups(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Groups", len(groups))
				for i, g := range groups {
					out.TreeEntry(fmt.Sprintf("%s (%d member(s))", g.Name, len(g.Members)), i == len(groups)-1)
				}
			}
		}

		if ldapEnumDCs {
			dcs, err := ldapmodules.EnumDCs(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Domain Controllers", len(dcs))
				for i, dc := range dcs {
					label := dc.Hostname
					if dc.ReadOnly {
						label += " (RODC)"
					}
					out.TreeEntry(label, i == len(dcs)-1)
				}
			}
		}

		if ldapEnumKerberoast {
			accounts, err := ldapmodules.EnumKerberoastable(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Kerberoastable Accounts", len(accounts))
				for i, a := range accounts {
					last := i == len(accounts)-1
					out.TreeEntryColored(a.SAMAccountName, core.ColorYellow, last)
					for j, spn := range a.SPNs {
						out.TreeDetail("SPN", spn, j == len(a.SPNs)-1)
					}
				}
			}
		}

		if ldapEnumASREP {
			accounts, err := ldapmodules.EnumASREPRoastable(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("AS-REP Roastable Accounts", len(accounts))
				for i, a := range accounts {
					out.TreeEntryColored(a.SAMAccountName, core.ColorYellow, i == len(accounts)-1)
				}
			}
		}

		if ldapEnumAdmins {
			admins, err := ldapmodules.EnumAdmins(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Domain Admins (primary group)", len(admins))
				for i, a := range admins {
					out.TreeEntryColored(a.SAMAccountName, core.ColorRed, i == len(admins)-1)
				}
			}
		}

		if ldapEnumComputers {
			computers, err := ldapmodules.EnumComputers(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Computers", len(computers))
				for i, c := range computers {
					last := i == len(computers)-1
					label := c.Name
					if c.DNSHostname != "" {
						label = c.DNSHostname
					}
					out.TreeEntry(label, last)
					if c.OS != "" {
						out.TreeDetail("OS", fmt.Sprintf("%s %s", c.OS, c.OSVersion), true)
					}
				}
			}
		}

		if ldapEnumPwdPolicy {
			policy, err := ldapmodules.GetPasswordPolicy(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Password Policy", 1)
				complex := fmt.Sprintf("%sNo%s", core.ColorRed, core.ColorReset)
				if policy.PwdComplexity {
					complex = fmt.Sprintf("%sYes%s", core.ColorGreen, core.ColorReset)
				}
				out.TreeDetail("Min Length", policy.MinPwdLength, false)
				out.TreeDetail("History Length", policy.PwdHistoryLength, false)
				out.TreeDetail("Lockout Threshold", policy.LockoutThreshold, false)
				out.TreeDetail("Complexity", complex, true)
			}
		}

		if ldapEnumTrusts {
			trusts, err := ldapmodules.EnumTrusts(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Domain Trusts", len(trusts))
				for i, t := range trusts {
					last := i == len(trusts)-1
					out.TreeEntry(t.Name, last)
					out.TreeDetail("Type", t.TrustType, false)
					out.TreeDetail("Direction", t.Direction, true)
				}
			}
		}

		if ldapEnumGPOs {
			gpos, err := ldapmodules.EnumGPOs(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Group Policy Objects", len(gpos))
				for i, g := range gpos {
					last := i == len(gpos)-1
					out.TreeEntry(g.DisplayName, last)
					if g.FileSysPath != "" {
						out.TreeDetail("Path", g.FileSysPath, true)
					}
				}
			}
		}

		if ldapEnumOUs {
			ous, err := ldapmodules.EnumOUs(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Organizational Units", len(ous))
				for i, o := range ous {
					out.TreeEntry(o.DN, i == len(ous)-1)
				}
			}
		}

		out.Flush()
	})
}

func init() {
	ldapCmd.Flags().StringVarP(&ldapTarget, "target", "t", "", "Target IP, hostname, CIDR, or file path")
	ldapCmd.Flags().StringVarP(&ldapUsername, "username", "u", "", "Username or file of usernames")
	ldapCmd.Flags().StringVarP(&ldapPassword, "password", "p", "", "Password or file of passwords")
	ldapCmd.Flags().StringVarP(&ldapHash, "hash", "H", "", "NT hash (format: [LM:]NT)")
	ldapCmd.Flags().StringVarP(&ldapDomain, "domain", "d", "", "Domain")
	ldapCmd.Flags().BoolVar(&ldapTLS, "tls", false, "Use LDAPS (TLS, port 636)")
	ldapCmd.Flags().IntVar(&ldapPort, "port", 389, "LDAP port")

	ldapCmd.Flags().BoolVar(&ldapEnumUsers, "users", false, "Enumerate users")
	ldapCmd.Flags().BoolVar(&ldapEnumGroups, "groups", false, "Enumerate groups")
	ldapCmd.Flags().BoolVar(&ldapEnumDCs, "dcs", false, "Enumerate domain controllers")
	ldapCmd.Flags().BoolVar(&ldapEnumKerberoast, "kerberoastable", false, "Find kerberoastable accounts")
	ldapCmd.Flags().BoolVar(&ldapEnumASREP, "asreproast", false, "Find AS-REP roastable accounts")
	ldapCmd.Flags().BoolVar(&ldapEnumAdmins, "admins", false, "Enumerate domain admins")
	ldapCmd.Flags().BoolVar(&ldapEnumComputers, "computers", false, "Enumerate computer accounts")
	ldapCmd.Flags().BoolVar(&ldapEnumPwdPolicy, "pwd-policy", false, "Get password policy")
	ldapCmd.Flags().BoolVar(&ldapEnumTrusts, "trusts", false, "Enumerate domain trusts")
	ldapCmd.Flags().BoolVar(&ldapEnumGPOs, "gpos", false, "Enumerate Group Policy Objects")
	ldapCmd.Flags().BoolVar(&ldapEnumOUs, "ous", false, "Enumerate Organizational Units")

	ldapCmd.MarkFlagRequired("target")
	ldapCmd.MarkFlagRequired("username")
	ldapCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(ldapCmd)
}
