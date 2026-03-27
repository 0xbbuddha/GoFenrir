package root

import (
	"github.com/spf13/cobra"
)

var (
	ldapTarget   string
	ldapUsername string
	ldapPassword string
	ldapHash     string
	ldapDomain   string
	ldapTLS      bool
)

var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Interact with LDAP/LDAPS",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	ldapCmd.PersistentFlags().StringVarP(&ldapTarget, "target", "t", "", "Target IP or CIDR range")
	ldapCmd.PersistentFlags().StringVarP(&ldapUsername, "username", "u", "", "Username")
	ldapCmd.PersistentFlags().StringVarP(&ldapPassword, "password", "p", "", "Password")
	ldapCmd.PersistentFlags().StringVarP(&ldapHash, "hash", "H", "", "NT hash")
	ldapCmd.PersistentFlags().StringVarP(&ldapDomain, "domain", "d", "", "Domain")
	ldapCmd.PersistentFlags().BoolVar(&ldapTLS, "tls", false, "Use LDAPS (TLS)")

	ldapCmd.MarkFlagRequired("target")
	ldapCmd.MarkFlagRequired("username")
	ldapCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(ldapCmd)
}
