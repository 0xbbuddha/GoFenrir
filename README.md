<p align="center">
  <img src="assets/logo.png" alt="GoFenrir Logo" width="200"/>
</p>

<h1 align="center">GoFenrir</h1>

<p align="center">
  Active Directory enumeration and attack framework written in Go, built on top of <a href="https://github.com/TheManticoreProject/Manticore">TheManticoreProject/Manticore</a>.
</p>

## What is GoFenrir?

GoFenrir is an Active Directory offensive framework inspired by [NetExec](https://github.com/Pennyw0rth/NetExec). Where NetExec relies on Impacket, GoFenrir uses [Manticore](https://github.com/TheManticoreProject/Manticore) as its protocol backend. Everything is written in Go - single binary, no Python, no dependency hell.

## Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| LDAP / LDAPS | Working | Full enumeration + attack support |
| SMB v1/v2/v3 | Working | Auto-negotiated (SMB1 legacy targets, SMB2/3 modern Windows) |
| Kerberos | Working | Native (no external library): auth (`-k`/PTT), Kerberoast, ASREPRoast, DCSync, Shadow Credentials |

Protocol support grows alongside [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore).

## Usage

```
Usage:
  gf [protocol] [flags]

Available Protocols:
  ldap       Interact with LDAP/LDAPS
  smb        Interact with SMB (v1/v2/v3)

Global Flags:
  -t, --target string     Target IP or hostname
  -u, --username string   Username
  -p, --password string   Password
  -H, --hash string       NT hash (format: [LM:]NT)
  -d, --domain string     Domain

Options:
      --threads int       Number of concurrent threads (default 1)
      --timeout int       Timeout per thread in seconds (default 30)
      --log string        Export output to a file
      --verbose           Verbose output
      --debug             Debug output
  -h, --help              Show this help
```

### LDAP

```
Usage:
  gf ldap [flags]

Interact with LDAP/LDAPS

Connection:
  -d, --domain string                  Domain
  -H, --hash string                    NT hash (format: [LM:]NT)
  -p, --password string                Password or file of passwords
      --port int                       LDAP port
  -t, --target string                  Target IP, hostname, CIDR, or file path
      --tls                            Use LDAPS (TLS, port 636)
  -u, --username string                Username or file of usernames

Enumeration:
      --admins                         Enumerate domain admins
      --computers                      Enumerate computer accounts with OS info
      --dcs                            Enumerate domain controllers
      --export-users string            Dump found sAMAccountNames to a file
      --gpos                           Enumerate Group Policy Objects
      --groups                         Enumerate groups
      --ous                            Enumerate Organizational Units
      --pwd-policy                     Get password policy
      --trusts                         Enumerate domain trusts
      --users                          Enumerate users

Domain:
      --admin-count                    Find objects with adminCount=1 (AdminSDHolder protected)
      --domain-info                    Get domain info (functional level, SID, PDC, DNS servers, naming contexts)
      --maq                            Get ms-DS-MachineAccountQuota (machine accounts a user can create - RBCD/noPac)
      --privileged-groups              Enumerate privileged groups and their members (Domain Admins, Enterprise Admins, etc.)
      --pso                            Enumerate Fine-Grained Password Policies (PSO) and their targets

Kerberos:
      --asreproast                     Find AS-REP roastable accounts (pre-auth disabled)
      --kerberoastable                 Find kerberoastable accounts (SPN-based)

Delegation:
      --constrained                    Find accounts with constrained delegation + SPNs
      --impersonate string             User to impersonate for --s4u and forged tickets (default "Administrator")
      --rbcd                           Find accounts with resource-based constrained delegation configured
      --s4u string                     Constrained-delegation abuse: S4U2Self+S4U2Proxy to this target SPN, export ccache/kirbi
      --unconstrained                  Find accounts with unconstrained delegation (excludes DCs)

Ticket Forging:
      --golden                         Forge a golden ticket (--forge-key = krbtgt key); exports ccache/kirbi
      --silver string                  Forge a silver ticket for this SPN (--forge-key = service account key)
      --forge-key string               Signing key (hex): NT hash (RC4) or AES128/256 key
      --forge-sid string               Domain SID (auto-resolved from the domain when omitted)
      --forge-rid uint32               RID of the impersonated account (default 500)
      --out string                     Base filename for exported tickets

ADCS:
      --adcs                           Enumerate CAs and templates, detect ESC1/ESC2/ESC3/ESC4/ESC9

Authentication:
  -k, --kerberos                       Authenticate with Kerberos (GSSAPI); derives a TGT from password/hash/AES key or uses a ccache/kirbi
      --aes-key string                 Kerberos AES128/AES256 key (hex) for authentication (implies -k)
      --ccache string                  Path to a Kerberos ccache (FILE) for pass-the-ticket (implies -k)
      --kirbi string                   Path to a .kirbi (KRB-CRED) for pass-the-ticket (implies -k)
      --keytab string                  Path to a Kerberos keytab for authentication (implies -k)

Credential Attacks:
      --dcsync string                  DCSync secrets via MS-DRSR ("all", "DOMAIN\user", UPN, DN, or username; needs replication rights)
      --find-aces                      Find dangerous ACEs (GenericAll, WriteDACL, ForceChangePassword, DCSync...) on domain, groups, adminCount users, computers
      --gmsa                           Dump gMSA passwords as NT hashes (requires read access to msDS-ManagedPassword)
      --laps                           Dump LAPS passwords (LAPSv1: ms-Mcs-AdmPwd, LAPSv2: msLAPS-Password)
      --shadow-creds                   Find objects with shadow credentials (msDS-KeyCredentialLink)
      --shadow-creds-add string        Shadow Credentials attack: write msDS-KeyCredentialLink, PKINIT, UnPAC-the-hash, clean up (needs GenericWrite over target)
      --weak-accounts                  Find accounts with dangerous UAC flags (no pwd required, reversible encryption, DES...)

Global:
      --threads int            Number of concurrent threads (default 1)
      --timeout int            Timeout per thread in seconds (default 30)
      --log string             Export output to a file
      --verbose                Verbose output
      --debug                  Debug output
  -h, --help                   Show this help
```

### SMB

```
Usage:
  gf smb [flags]

Interact with SMB

Connection:
  -d, --domain string                  Domain
  -H, --hash string                    NT hash (format: [LM:]NT)
  -p, --password string                Password or file of passwords
      --port int                       SMB port
  -t, --target string                  Target IP, hostname, CIDR, or file path
  -u, --username string                Username or file of usernames
      --connect-timeout int            Per-attempt connect/negotiate timeout in seconds (0 = manticore default, <0 = no limit)
      --no-banner                      Skip the host banner (OS, dialect, SMBv1, signing, null session) shown on login
      --oneline                        Render the host banner on a single compact line instead of a tree

Enumeration:
      --shares                         Enumerate all shares via NetrShareEnum with access check (falls back to probing common names if denied)
      --null-session                   Check for null/anonymous session
      --gpp-passwords                  Search SYSVOL for GPP cpasswords and decrypt them (MS14-025)
      --rid-brute                      Enumerate users/groups via SAMR (RID cycling fallback if enumeration denied)
      --rid-start uint32               Starting RID for cycling fallback
      --rid-end uint32                 Ending RID for cycling fallback
      --local-groups                   Enumerate local groups and their members via SAMR+LSA
      --sessions                       Enumerate active SMB sessions via srvsvc (useful on DCs to spot admin sessions)
      --loggedon-users                 Enumerate logged-on users via MS-WKST (NetrWkstaUserEnum)
      --who-has-priv string            List accounts holding a privilege (e.g. SeDebugPrivilege) or "all" for every non-empty privilege
      --server-info                    Query server name, OS version and roles via srvsvc NetrServerGetInfo
      --services                       Enumerate services via MS-SCMR (svcctl) including binary path and run-as account
      --services-filter string         Filter services by state: "running" or "stopped" (default: all)
      --check-autologon                Read AutoLogon credentials from HKLM\...\Winlogon via MS-RRP (winreg)
      --enum-rpc                       Enumerate registered RPC endpoints via the endpoint mapper (EPM, port 135 via IPC$)
      --lsa-settings                   Read LSA security settings: WDigest, RunAsPPL, LmCompatibilityLevel, null session restrictions
      --enum-av                        Detect installed/running AV/EDR via LsarLookupNames (service SIDs) and IPC$ named pipes

Vulnerability checks:
      --zerologon                      Check for Zerologon (CVE-2020-1472) - detection only, does not reset the machine password

Coercion:
      --coerce-to string               Trigger coercion: target authenticates to <attacker_ip> (capture with Responder)
      --coerce-method string           Coercion method: petitpotam (MS-EFSR), printerbug (MS-RPRN), shadowcoerce (MS-FSRVP) or dfscoerce (MS-DFSNM)

Spider:
      --spider string                  Recursively list files on a share (e.g. SYSVOL) or "all" for every readable share
      --spider-filter string           Glob pattern to match filenames (e.g. "*.xml", "pass*", default: all files)
      --depth int                      Maximum spider recursion depth (0 = unlimited)

Execution:
      --exec string                    Execute a command on the target (see --exec-method)
      --exec-method string             Execution method: smbexec (MS-SCMR service) or atexec (MS-TSCH scheduled task)
      --no-output                      Suppress command output (use with --exec for fire-and-forget)

Credential Attacks:
      --password-spray                 Test credentials only (no enumeration) - use with -u file and -p password

Global:
      --threads int            Number of concurrent threads (default 1)
      --timeout int            Timeout per thread in seconds (default 30)
      --log string             Export output to a file
      --verbose                Verbose output
      --debug                  Debug output
  -h, --help                   Show this help
```

## Installation

Via `go install`:

```bash
go install github.com/0xbbuddha/GoFenrir/cmd/gf@latest
```

From source:

```bash
git clone https://github.com/0xbbuddha/GoFenrir
cd GoFenrir
go build -o gf ./cmd/gf/
```

## Built With

- [Go](https://golang.org/)
- [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore)
- [Cobra](https://github.com/spf13/cobra)

## Disclaimer

For authorized security testing only.
