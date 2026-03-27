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

	ldapEnumUsers       bool
	ldapEnumGroups      bool
	ldapEnumDCs         bool
	ldapEnumKerberoast  bool
	ldapEnumASREP       bool
	ldapEnumAdmins      bool
	ldapEnumComputers   bool
	ldapEnumPwdPolicy   bool
	ldapEnumTrusts      bool
	ldapEnumGPOs        bool
	ldapEnumOUs         bool
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

	session, err := ldap.NewSession(ldapTarget, ldapPort, ldapDomain, ldapUsername, ldapPassword, ldapHash, ldapTLS)
	if err != nil {
		core.Failure(fmt.Sprintf("[%s] %s", proto, err.Error()))
		os.Exit(1)
	}

	if err := session.Connect(); err != nil {
		core.Failure(fmt.Sprintf("[%s] %s\\%s - %s", proto, ldapDomain, ldapUsername, err.Error()))
		os.Exit(1)
	}
	defer session.Close()

	authMsg := fmt.Sprintf("[%s] %s\\%s%s%s", proto, ldapDomain, core.ColorGreen, ldapUsername, core.ColorReset)
	if ldapHash != "" {
		authMsg += fmt.Sprintf(" (Pass-the-Hash: %s%s%s)", core.ColorYellow, ldapHash, core.ColorReset)
	}
	core.Success(authMsg)

	if ldapEnumUsers {
		users, err := ldapmodules.EnumUsers(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Users", len(users))
			for i, u := range users {
				color := core.ColorGreen
				label := u.SAMAccountName
				if !u.IsEnabled() {
					color = core.ColorRed
					label += " (disabled)"
				}
				core.TreeEntryColored(label, color, i == len(users)-1)
			}
		}
	}

	if ldapEnumGroups {
		groups, err := ldapmodules.EnumGroups(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Groups", len(groups))
			for i, g := range groups {
				core.TreeEntry(fmt.Sprintf("%s (%d member(s))", g.Name, len(g.Members)), i == len(groups)-1)
			}
		}
	}

	if ldapEnumDCs {
		dcs, err := ldapmodules.EnumDCs(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Domain Controllers", len(dcs))
			for i, dc := range dcs {
				label := dc.Hostname
				if dc.ReadOnly {
					label += " (RODC)"
				}
				core.TreeEntry(label, i == len(dcs)-1)
			}
		}
	}

	if ldapEnumKerberoast {
		accounts, err := ldapmodules.EnumKerberoastable(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Kerberoastable Accounts", len(accounts))
			for i, a := range accounts {
				last := i == len(accounts)-1
				core.TreeEntryColored(a.SAMAccountName, core.ColorYellow, last)
				for j, spn := range a.SPNs {
					core.TreeDetail("SPN", spn, j == len(a.SPNs)-1)
				}
			}
		}
	}

	if ldapEnumASREP {
		accounts, err := ldapmodules.EnumASREPRoastable(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("AS-REP Roastable Accounts", len(accounts))
			for i, a := range accounts {
				core.TreeEntryColored(a.SAMAccountName, core.ColorYellow, i == len(accounts)-1)
			}
		}
	}

	if ldapEnumAdmins {
		admins, err := ldapmodules.EnumAdmins(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Domain Admins (primary group)", len(admins))
			for i, a := range admins {
				core.TreeEntryColored(a.SAMAccountName, core.ColorRed, i == len(admins)-1)
			}
		}
	}

	if ldapEnumComputers {
		computers, err := ldapmodules.EnumComputers(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Computers", len(computers))
			for i, c := range computers {
				last := i == len(computers)-1
				label := c.Name
				if c.DNSHostname != "" {
					label = c.DNSHostname
				}
				core.TreeEntry(label, last)
				if c.OS != "" {
					core.TreeDetail("OS", fmt.Sprintf("%s %s", c.OS, c.OSVersion), true)
				}
			}
		}
	}

	if ldapEnumPwdPolicy {
		policy, err := ldapmodules.GetPasswordPolicy(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Password Policy", 1)
			complex := fmt.Sprintf("%sNo%s", core.ColorRed, core.ColorReset)
			if policy.PwdComplexity {
				complex = fmt.Sprintf("%sYes%s", core.ColorGreen, core.ColorReset)
			}
			core.TreeDetail("Min Length", policy.MinPwdLength, false)
			core.TreeDetail("History Length", policy.PwdHistoryLength, false)
			core.TreeDetail("Lockout Threshold", policy.LockoutThreshold, false)
			core.TreeDetail("Complexity", complex, true)
		}
	}

	if ldapEnumTrusts {
		trusts, err := ldapmodules.EnumTrusts(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Domain Trusts", len(trusts))
			for i, t := range trusts {
				last := i == len(trusts)-1
				core.TreeEntry(t.Name, last)
				core.TreeDetail("Type", t.TrustType, false)
				core.TreeDetail("Direction", t.Direction, true)
			}
		}
	}

	if ldapEnumGPOs {
		gpos, err := ldapmodules.EnumGPOs(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Group Policy Objects", len(gpos))
			for i, g := range gpos {
				last := i == len(gpos)-1
				core.TreeEntry(g.DisplayName, last)
				if g.FileSysPath != "" {
					core.TreeDetail("Path", g.FileSysPath, true)
				}
			}
		}
	}

	if ldapEnumOUs {
		ous, err := ldapmodules.EnumOUs(session)
		if err != nil {
			core.Failure(err.Error())
		} else {
			core.Section("Organizational Units", len(ous))
			for i, o := range ous {
				core.TreeEntry(o.DN, i == len(ous)-1)
			}
		}
	}
}

func init() {
	ldapCmd.Flags().StringVarP(&ldapTarget, "target", "t", "", "Target IP or hostname")
	ldapCmd.Flags().StringVarP(&ldapUsername, "username", "u", "", "Username")
	ldapCmd.Flags().StringVarP(&ldapPassword, "password", "p", "", "Password")
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
