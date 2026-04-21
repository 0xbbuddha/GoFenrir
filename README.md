<p align="center">
  <img src="assets/logo.png" alt="GoFenrir Logo" width="200"/>
</p>

<h1 align="center">GoFenrir</h1>

<p align="center">
  Active Directory enumeration and attack framework written in Go, built on top of <a href="https://github.com/TheManticoreProject/Manticore">TheManticoreProject/Manticore</a>.
</p>

## What is GoFenrir?

GoFenrir is an Active Directory offensive framework inspired by [NetExec](https://github.com/Pennyw0rth/NetExec). Where NetExec relies on Impacket, GoFenrir uses [Manticore](https://github.com/TheManticoreProject/Manticore) as its protocol backend. Everything is written in Go — single binary, no Python, no dependency hell.

## Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| LDAP / LDAPS | Working | Full enumeration + attack support |
| SMB v1 | Working | Limited to targets with SMBv1 enabled |
| SMB v2/v3 | Planned | Waiting on Manticore |
| Kerberos | Working | Kerberoast + ASREPRoast (native, no external library) |

Protocol support grows alongside [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore).

## Usage

```
Usage:
  gf [protocol] [flags]

Available Protocols:
  ldap       Interact with LDAP/LDAPS
  smb        Interact with SMB (v1)

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
  -d, --domain string          Domain
  -H, --hash string            NT hash (format: [LM:]NT)
  -p, --password string        Password or file of passwords
      --port int               LDAP port
  -t, --target string          Target IP, hostname, CIDR, or file path
      --tls                    Use LDAPS (TLS, port 636)
  -u, --username string        Username or file of usernames

Enumeration:
      --admins                 Enumerate domain admins
      --computers              Enumerate computer accounts with OS info
      --dcs                    Enumerate domain controllers
      --gpos                   Enumerate Group Policy Objects
      --groups                 Enumerate groups
      --ous                    Enumerate Organizational Units
      --pwd-policy             Get password policy
      --trusts                 Enumerate domain trusts
      --users                  Enumerate users

Domain:
      --admin-count            Find objects with adminCount=1 (AdminSDHolder protected)
      --domain-info            Get domain info (functional level, SID, PDC, DNS servers, naming contexts)
      --privileged-groups      Enumerate privileged groups and their members (Domain Admins, Enterprise Admins, etc.)

Kerberos:
      --asreproast             Find AS-REP roastable accounts (pre-auth disabled)
      --kerberoastable         Find kerberoastable accounts (SPN-based)

Delegation:
      --constrained            Find accounts with constrained delegation + SPNs
      --rbcd                   Find accounts with resource-based constrained delegation configured
      --unconstrained          Find accounts with unconstrained delegation (excludes DCs)

ADCS:
      --adcs                   Enumerate CAs and templates, detect ESC1/ESC2/ESC3/ESC4/ESC9

Credential Attacks:
      --laps                   Dump LAPS passwords (LAPSv1: ms-Mcs-AdmPwd, LAPSv2: msLAPS-Password)
      --shadow-creds           Find objects with shadow credentials (msDS-KeyCredentialLink)
      --weak-accounts          Find accounts with dangerous UAC flags (no pwd required, reversible encryption, DES...)

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

Interact with SMB (v1)

Connection:
  -d, --domain string          Domain
  -H, --hash string            NT hash (format: [LM:]NT)
  -p, --password string        Password or file of passwords
      --port int               SMB port
  -t, --target string          Target IP, hostname, CIDR, or file path
  -u, --username string        Username or file of usernames

Enumeration:
      --gpp-passwords          Search SYSVOL for GPP cpasswords and decrypt them (MS14-025)
      --null-session           Check for null/anonymous session
      --shares                 Enumerate shares and check access

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
