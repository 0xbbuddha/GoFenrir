package root

import (
	"fmt"
	"os"

	"github.com/0xbbuddha/GoFenrir/core"
	ldapadcs "github.com/0xbbuddha/GoFenrir/modules/ldap/adcs"
	ldapacl "github.com/0xbbuddha/GoFenrir/modules/ldap/acl"
	ldapcreds "github.com/0xbbuddha/GoFenrir/modules/ldap/credentials"
	ldapenum "github.com/0xbbuddha/GoFenrir/modules/ldap/enumeration"
	ldapkrb "github.com/0xbbuddha/GoFenrir/modules/ldap/kerberos"
	ldappriv "github.com/0xbbuddha/GoFenrir/modules/ldap/privilege"
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

	ldapEnumUsers              bool
	ldapEnumGroups             bool
	ldapEnumDCs                bool
	ldapEnumKerberoast         bool
	ldapEnumASREP              bool
	ldapEnumAdmins             bool
	ldapEnumComputers          bool
	ldapEnumPwdPolicy          bool
	ldapEnumTrusts             bool
	ldapEnumGPOs               bool
	ldapEnumOUs                bool
	ldapEnumUnconstrainedDel   bool
	ldapEnumConstrainedDel     bool
	ldapEnumRBCD               bool
	ldapEnumADCS               bool
	ldapEnumShadowCreds        bool
	ldapEnumWeakAccounts       bool
	ldapEnumDomainInfo         bool
	ldapEnumPrivilegedGroups   bool
	ldapEnumAdminCount         bool
	ldapEnumLAPS               bool
	ldapEnumGMSA               bool
	ldapEnumPSO                bool
	ldapEnumACEs               bool
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

	effectivePort := ldapPort
	if ldapTLS && ldapPort == 389 {
		effectivePort = 636
	}

	core.RunConcurrent(jobs, Threads, func(job core.Job) {
		out := &core.OutputBuffer{}

		session, err := ldap.NewSession(job.Target, effectivePort, ldapDomain, job.Cred.Username, job.Cred.Password, job.Cred.Hash, ldapTLS)
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
			users, err := ldapenum.EnumUsers(session)
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
			groups, err := ldapenum.EnumGroups(session)
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
			dcs, err := ldapenum.EnumDCs(session)
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
			accounts, err := ldapkrb.EnumKerberoastable(session)
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
				hashes, err := ldapkrb.KerberoastActive(accounts, job.Cred.Username, job.Cred.Password, ldapDomain, job.Target)
				if err != nil {
					out.Failure(fmt.Sprintf("[Kerberoast] %s", err.Error()))
				} else if len(hashes) > 0 {
					out.Section("TGS Hashes (hashcat)", len(hashes))
					for i, h := range hashes {
						out.TreeEntryColored(h.Hash, core.ColorYellow, i == len(hashes)-1)
					}
				}
			}
		}

		if ldapEnumASREP {
			accounts, err := ldapkrb.EnumASREPRoastable(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("AS-REP Roastable Accounts", len(accounts))
				for i, a := range accounts {
					out.TreeEntryColored(a.SAMAccountName, core.ColorYellow, i == len(accounts)-1)
				}
				if hashes := ldapkrb.ASREPRoastActive(accounts, ldapDomain, job.Target); len(hashes) > 0 {
					out.Section("AS-REP Hashes (hashcat)", len(hashes))
					for i, h := range hashes {
						out.TreeEntryColored(h.Hash, core.ColorYellow, i == len(hashes)-1)
					}
				}
			}
		}

		if ldapEnumAdmins {
			admins, err := ldappriv.EnumAdmins(session)
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
			computers, err := ldapenum.EnumComputers(session)
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
			policy, err := ldappriv.GetPasswordPolicy(session)
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
			trusts, err := ldapenum.EnumTrusts(session)
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
			gpos, err := ldapenum.EnumGPOs(session)
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
			ous, err := ldapenum.EnumOUs(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Organizational Units", len(ous))
				for i, o := range ous {
					out.TreeEntry(o.DN, i == len(ous)-1)
				}
			}
		}

		if ldapEnumUnconstrainedDel {
			accounts, err := ldapkrb.EnumUnconstrainedDelegation(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Unconstrained Delegation", len(accounts))
				for i, a := range accounts {
					label := fmt.Sprintf("%s (%s)", a.SAMAccountName, a.ObjectType)
					out.TreeEntryColored(label, core.ColorRed, i == len(accounts)-1)
				}
			}
		}

		if ldapEnumConstrainedDel {
			accounts, err := ldapkrb.EnumConstrainedDelegation(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Constrained Delegation", len(accounts))
				for i, a := range accounts {
					last := i == len(accounts)-1
					label := a.SAMAccountName
					color := core.ColorBlue
					if a.ProtocolTransition {
						label += " [Protocol Transition]"
						color = core.ColorYellow
					}
					out.TreeEntryColored(label, color, last)
					for j, svc := range a.AllowedServices {
						out.TreeDetail("SPN", svc, j == len(a.AllowedServices)-1)
					}
				}
			}
		}

		if ldapEnumRBCD {
			entries, err := ldapacl.EnumRBCD(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Resource-Based Constrained Delegation", len(entries))
				for i, e := range entries {
					label := fmt.Sprintf("%s (%s)", e.SAMAccountName, e.ObjectType)
					out.TreeEntryColored(label, core.ColorYellow, i == len(entries)-1)
				}
			}
		}

		if ldapEnumADCS {
			cas, templates, err := ldapadcs.EnumADCS(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Certificate Authorities", len(cas))
				for i, ca := range cas {
					out.TreeEntryColored(fmt.Sprintf("%s (%s)", ca.Name, ca.DNSHostname), core.ColorBlue, i == len(cas)-1)
					for j, t := range ca.Templates {
						out.TreeDetail("Template", t, j == len(ca.Templates)-1)
					}
				}

				out.Section("ADCS Enabled Templates", len(templates))
				for i, t := range templates {
					last := i == len(templates)-1
					color := core.ColorBlue
					label := t.Name
					if t.IsESC1 {
						color = core.ColorRed
						label += " [ESC1]"
					} else if t.IsESC2 {
						color = core.ColorRed
						label += " [ESC2]"
					} else if t.IsESC3 {
						color = core.ColorYellow
						label += " [ESC3]"
					} else if t.IsESC4 {
						color = core.ColorRed
						label += " [ESC4]"
					} else if t.IsESC9 {
						color = core.ColorYellow
						label += " [ESC9]"
					}
					out.TreeEntryColored(label, color, last)
					for j, eku := range t.EKUs {
						out.TreeDetail("EKU", eku, j == len(t.EKUs)-1)
					}
				}

				var vulnTemplates []ldapadcs.TemplateEntry
				for _, t := range templates {
					if t.IsESC1 || t.IsESC2 || t.IsESC3 || t.IsESC4 || t.IsESC9 {
						vulnTemplates = append(vulnTemplates, t)
					}
				}
				if len(vulnTemplates) > 0 {
					out.Section("Vulnerable Templates (ESC1/ESC2/ESC3/ESC4/ESC9)", len(vulnTemplates))
					for i, t := range vulnTemplates {
						last := i == len(vulnTemplates)-1
						tag := ""
						color := core.ColorYellow
						if t.IsESC1 {
							tag = "[ESC1]"
							color = core.ColorRed
						} else if t.IsESC2 {
							tag = "[ESC2]"
							color = core.ColorRed
						} else if t.IsESC3 {
							tag = "[ESC3]"
						} else if t.IsESC4 {
							tag = "[ESC4]"
							color = core.ColorRed
						} else if t.IsESC9 {
							tag = "[ESC9]"
						}
						out.TreeEntryColored(fmt.Sprintf("%s %s", t.Name, tag), color, last)
						out.TreeDetail("DN", t.DN, false)
						for j, p := range t.ESC4Principals {
							out.TreeDetail("Write access", p, j == len(t.ESC4Principals)-1)
						}
					}
				}
			}
		}

		if ldapEnumShadowCreds {
			entries, err := ldapacl.EnumShadowCreds(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Shadow Credentials", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					label := fmt.Sprintf("%s (%s)", e.SAMAccountName, e.ObjectType)
					out.TreeEntryColored(label, core.ColorYellow, last)
					for j, k := range e.Keys {
						lastKey := j == len(e.Keys)-1
						out.TreeDetail("Key ID", k.Identifier, false)
						out.TreeDetail("Usage", k.Usage, false)
						out.TreeDetail("Source", k.Source, false)
						out.TreeDetail("Created", k.CreationTime, lastKey)
					}
				}
			}
		}

		if ldapEnumWeakAccounts {
			entries, err := ldappriv.EnumWeakAccounts(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Weak Accounts", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					out.TreeEntryColored(e.SAMAccountName, core.ColorYellow, last)
					for j, f := range e.Flags {
						out.TreeDetail("Flag", f, j == len(e.Flags)-1)
					}
				}
			}
		}

		if ldapEnumDomainInfo {
			info, err := ldapenum.GetDomainInfo(session, ldapDomain)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Domain Information", 1)
				out.TreeDetail("DNS Name", info.DNSName, false)
				out.TreeDetail("NetBIOS", info.NetBIOSName, false)
				out.TreeDetail("SID", info.SID, false)
				out.TreeDetail("Functional Level", info.FunctionalLevel, false)
				out.TreeDetail("PDC", info.PDC, false)
				out.TreeDetail("DN", info.DN, false)
				for j, ns := range info.NamingContexts {
					out.TreeDetail("Naming Context", ns, false)
					_ = j
				}
				for j, dns := range info.DNSServers {
					out.TreeDetail("DNS Server", dns, j == len(info.DNSServers)-1)
				}
			}
		}

		if ldapEnumPrivilegedGroups {
			groups, err := ldappriv.EnumPrivilegedGroups(session, ldapDomain)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Privileged Groups", len(groups))
				for i, g := range groups {
					last := i == len(groups)-1
					out.TreeEntryColored(fmt.Sprintf("%s (%d member(s))", g.Name, len(g.Members)), core.ColorRed, last)
					for j, m := range g.Members {
						out.TreeDetail("Member", m, j == len(g.Members)-1)
					}
				}
			}
		}

		if ldapEnumLAPS {
			entries, err := ldapcreds.EnumLAPS(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("LAPS Passwords", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					ver := fmt.Sprintf("LAPSv%d", e.Version)
					label := fmt.Sprintf("%s [%s]", e.ComputerName, ver)
					out.TreeEntryColored(label, core.ColorRed, last)
					out.TreeDetail("Password", e.Password, false)
					if e.Expiration != "" {
						out.TreeDetail("Expiration", e.Expiration, true)
					}
				}
			}
		}

		if ldapEnumACEs {
			aces, err := ldapacl.EnumDangerousACEs(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				// Group by object for readability.
				type objKey struct{ name, typ string }
				grouped := make(map[objKey][]ldapacl.ACEEntry)
				var order []objKey
				for _, a := range aces {
					k := objKey{a.ObjectName, a.ObjectType}
					if _, exists := grouped[k]; !exists {
						order = append(order, k)
					}
					grouped[k] = append(grouped[k], a)
				}
				out.Section("Dangerous ACEs", len(aces))
				for i, k := range order {
					entries := grouped[k]
					lastObj := i == len(order)-1
					label := fmt.Sprintf("%s (%s)", k.name, k.typ)
					out.TreeEntry(label, lastObj)
					for j, a := range entries {
						lastAce := j == len(entries)-1
						color := core.ColorYellow
						if a.Severity == "critical" {
							color = core.ColorRed
						}
						out.TreeDetail(a.Right, fmt.Sprintf("%s%s%s → %s", color, a.TrusteeName, core.ColorReset, a.TrusteeSID), lastAce)
					}
				}
			}
		}

		if ldapEnumGMSA {
			entries, err := ldapcreds.EnumGMSA(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("gMSA Accounts", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					color := core.ColorYellow
					if e.NTHash != "" {
						color = core.ColorRed
					}
					out.TreeEntryColored(e.SAMAccountName, color, last)
					for j, r := range e.AllowedReaders {
						isLastReader := j == len(e.AllowedReaders)-1 && e.NTHash == ""
						out.TreeDetail("Allowed reader", r, isLastReader)
					}
					if e.NTHash != "" {
						out.TreeDetail("NT Hash", e.NTHash, true)
					}
				}
			}
		}

		if ldapEnumPSO {
			psos, err := ldappriv.EnumPSO(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("Fine-Grained Password Policies (PSO)", len(psos))
				for i, p := range psos {
					last := i == len(psos)-1
					out.TreeEntryColored(fmt.Sprintf("%s (precedence %d)", p.Name, p.Precedence), core.ColorYellow, last)
					out.TreeDetail("Min Length", fmt.Sprintf("%d", p.MinPwdLength), false)
					out.TreeDetail("History", fmt.Sprintf("%d", p.PwdHistoryLength), false)
					out.TreeDetail("Lockout Threshold", fmt.Sprintf("%d", p.LockoutThreshold), false)
					complexity := fmt.Sprintf("%sNo%s", core.ColorRed, core.ColorReset)
					if p.ComplexityEnabled {
						complexity = fmt.Sprintf("%sYes%s", core.ColorGreen, core.ColorReset)
					}
					out.TreeDetail("Complexity", complexity, false)
					if p.ReversibleEncrypt {
						out.TreeDetail("Reversible Encrypt", fmt.Sprintf("%sYes (cleartext exposed!)%s", core.ColorRed, core.ColorReset), false)
					}
					for j, t := range p.AppliesTo {
						out.TreeDetail("Applies to", t, j == len(p.AppliesTo)-1)
					}
				}
			}
		}

		if ldapEnumAdminCount {
			entries, err := ldappriv.EnumAdminCount(session)
			if err != nil {
				out.Failure(err.Error())
			} else {
				out.Section("AdminCount=1 Objects (AdminSDHolder protected)", len(entries))
				for i, e := range entries {
					last := i == len(entries)-1
					label := fmt.Sprintf("%s (%s)", e.SAMAccountName, e.ObjectType)
					color := core.ColorYellow
					if e.ObjectType == "group" {
						color = core.ColorRed
					}
					out.TreeEntryColored(label, color, last)
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
	for _, f := range []string{"target", "username", "password", "hash", "domain", "tls", "port"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Connection"})
	}

	ldapCmd.Flags().BoolVar(&ldapEnumUsers, "users", false, "Enumerate users")
	ldapCmd.Flags().BoolVar(&ldapEnumGroups, "groups", false, "Enumerate groups")
	ldapCmd.Flags().BoolVar(&ldapEnumDCs, "dcs", false, "Enumerate domain controllers")
	ldapCmd.Flags().BoolVar(&ldapEnumAdmins, "admins", false, "Enumerate domain admins")
	ldapCmd.Flags().BoolVar(&ldapEnumComputers, "computers", false, "Enumerate computer accounts with OS info")
	ldapCmd.Flags().BoolVar(&ldapEnumPwdPolicy, "pwd-policy", false, "Get password policy")
	ldapCmd.Flags().BoolVar(&ldapEnumTrusts, "trusts", false, "Enumerate domain trusts")
	ldapCmd.Flags().BoolVar(&ldapEnumGPOs, "gpos", false, "Enumerate Group Policy Objects")
	ldapCmd.Flags().BoolVar(&ldapEnumOUs, "ous", false, "Enumerate Organizational Units")
	for _, f := range []string{"users", "groups", "dcs", "admins", "computers", "pwd-policy", "trusts", "gpos", "ous"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Enumeration"})
	}

	ldapCmd.Flags().BoolVar(&ldapEnumDomainInfo, "domain-info", false, "Get domain info (functional level, SID, PDC, DNS servers, naming contexts)")
	ldapCmd.Flags().BoolVar(&ldapEnumPrivilegedGroups, "privileged-groups", false, "Enumerate privileged groups and their members (Domain Admins, Enterprise Admins, etc.)")
	ldapCmd.Flags().BoolVar(&ldapEnumAdminCount, "admin-count", false, "Find objects with adminCount=1 (AdminSDHolder protected)")
	ldapCmd.Flags().BoolVar(&ldapEnumPSO, "pso", false, "Enumerate Fine-Grained Password Policies (PSO) and their targets")
	for _, f := range []string{"domain-info", "privileged-groups", "admin-count", "pso"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Domain"})
	}

	ldapCmd.Flags().BoolVar(&ldapEnumKerberoast, "kerberoastable", false, "Find kerberoastable accounts (SPN-based)")
	ldapCmd.Flags().BoolVar(&ldapEnumASREP, "asreproast", false, "Find AS-REP roastable accounts (pre-auth disabled)")
	for _, f := range []string{"kerberoastable", "asreproast"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Kerberos"})
	}

	ldapCmd.Flags().BoolVar(&ldapEnumUnconstrainedDel, "unconstrained", false, "Find accounts with unconstrained delegation (excludes DCs)")
	ldapCmd.Flags().BoolVar(&ldapEnumConstrainedDel, "constrained", false, "Find accounts with constrained delegation + SPNs")
	ldapCmd.Flags().BoolVar(&ldapEnumRBCD, "rbcd", false, "Find accounts with resource-based constrained delegation configured")
	for _, f := range []string{"unconstrained", "constrained", "rbcd"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Delegation"})
	}

	ldapCmd.Flags().BoolVar(&ldapEnumADCS, "adcs", false, "Enumerate CAs and templates, detect ESC1/ESC2/ESC3/ESC4/ESC9")
	ldapCmd.Flags().SetAnnotation("adcs", "group", []string{"ADCS"})

	ldapCmd.Flags().BoolVar(&ldapEnumShadowCreds, "shadow-creds", false, "Find objects with shadow credentials (msDS-KeyCredentialLink)")
	ldapCmd.Flags().BoolVar(&ldapEnumWeakAccounts, "weak-accounts", false, "Find accounts with dangerous UAC flags (no pwd required, reversible encryption, DES...)")
	ldapCmd.Flags().BoolVar(&ldapEnumLAPS, "laps", false, "Dump LAPS passwords (LAPSv1: ms-Mcs-AdmPwd, LAPSv2: msLAPS-Password)")
	ldapCmd.Flags().BoolVar(&ldapEnumGMSA, "gmsa", false, "Dump gMSA passwords as NT hashes (requires read access to msDS-ManagedPassword)")
	ldapCmd.Flags().BoolVar(&ldapEnumACEs, "find-aces", false, "Find dangerous ACEs (GenericAll, WriteDACL, ForceChangePassword, DCSync...) on domain, groups, adminCount users, computers")
	for _, f := range []string{"shadow-creds", "weak-accounts", "laps", "gmsa", "find-aces"} {
		ldapCmd.Flags().SetAnnotation(f, "group", []string{"Credential Attacks"})
	}

	ldapCmd.MarkFlagRequired("target")
	ldapCmd.MarkFlagRequired("username")
	ldapCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(ldapCmd)
}
