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

	// Action flags
	ldapEnumUsers  bool
	ldapEnumGroups bool
	ldapEnumDCs    bool
)

var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Interact with LDAP/LDAPS",
	Run:   runLDAP,
}

func runLDAP(cmd *cobra.Command, args []string) {
	proto := "LDAPS"
	if !ldapTLS {
		proto = "LDAP"
	}

	session, err := ldap.NewSession(ldapTarget, ldapPort, ldapDomain, ldapUsername, ldapPassword, ldapHash, ldapTLS)
	if err != nil {
		core.PrintFailure(proto, ldapTarget, ldapPort, "", err.Error())
		os.Exit(1)
	}

	if err := session.Connect(); err != nil {
		core.PrintFailure(proto, ldapTarget, ldapPort, "", fmt.Sprintf("%s\\%s - %s", ldapDomain, ldapUsername, err.Error()))
		os.Exit(1)
	}
	defer session.Close()

	authMsg := fmt.Sprintf("%s\\%s", ldapDomain, ldapUsername)
	if ldapHash != "" {
		authMsg += " (Pass-the-Hash)"
	}
	core.PrintSuccess(proto, ldapTarget, ldapPort, "", authMsg)

	if ldapEnumUsers {
		core.PrintInfo(proto, ldapTarget, ldapPort, "", "Enumerating users...")
		users, err := ldapmodules.EnumUsers(session)
		if err != nil {
			core.PrintFailure(proto, ldapTarget, ldapPort, "", err.Error())
		} else {
			for _, u := range users {
				status := "enabled"
				if !u.Enabled {
					status = "disabled"
				}
				fmt.Printf("  %-30s (%s)\n", u.SAMAccountName, status)
			}
			core.PrintInfo(proto, ldapTarget, ldapPort, "", fmt.Sprintf("%d user(s) found", len(users)))
		}
	}

	if ldapEnumGroups {
		core.PrintInfo(proto, ldapTarget, ldapPort, "", "Enumerating groups...")
		groups, err := ldapmodules.EnumGroups(session)
		if err != nil {
			core.PrintFailure(proto, ldapTarget, ldapPort, "", err.Error())
		} else {
			for _, g := range groups {
				fmt.Printf("  %-30s (%d member(s))\n", g.Name, len(g.Members))
			}
			core.PrintInfo(proto, ldapTarget, ldapPort, "", fmt.Sprintf("%d group(s) found", len(groups)))
		}
	}

	if ldapEnumDCs {
		core.PrintInfo(proto, ldapTarget, ldapPort, "", "Enumerating domain controllers...")
		dcs, err := ldapmodules.EnumDCs(session)
		if err != nil {
			core.PrintFailure(proto, ldapTarget, ldapPort, "", err.Error())
		} else {
			for _, dc := range dcs {
				dcType := "DC"
				if dc.ReadOnly {
					dcType = "RODC"
				}
				fmt.Printf("  %-30s [%s]\n", dc.Hostname, dcType)
			}
			core.PrintInfo(proto, ldapTarget, ldapPort, "", fmt.Sprintf("%d DC(s) found", len(dcs)))
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

	ldapCmd.MarkFlagRequired("target")
	ldapCmd.MarkFlagRequired("username")
	ldapCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(ldapCmd)
}
