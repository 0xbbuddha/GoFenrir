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
| Kerberos | Planned | Waiting on Manticore |

Protocol support grows alongside [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore).

## Usage

```
gf <protocol> [options]
```

### LDAP

```bash
# Authentication check
gf ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local

# Pass-the-Hash
gf ldap -t DC01.domain.local -u user -H <NT_HASH> -d domain.local

# Spray credentials across a subnet
gf ldap -t 192.168.1.0/24 -u users.txt -p passwords.txt -d domain.local --threads 10
```

#### Enumeration

```bash
gf ldap ... --users              # User accounts (enabled/disabled)
gf ldap ... --groups             # Groups with member count
gf ldap ... --dcs                # Domain controllers (including RODCs)
gf ldap ... --computers          # Computer accounts with OS info
gf ldap ... --admins             # Domain admins
gf ldap ... --ous                # Organizational units
gf ldap ... --gpos               # Group Policy Objects
gf ldap ... --trusts             # Domain trusts
gf ldap ... --pwd-policy         # Password policy
```

#### Kerberos Attacks

```bash
gf ldap ... --kerberoastable     # Accounts with SPNs (Kerberoast targets)
gf ldap ... --asreproast         # Accounts without pre-auth (AS-REP roast targets)
```

#### Delegation

```bash
gf ldap ... --unconstrained      # Computers/users with unconstrained delegation (excludes DCs)
gf ldap ... --constrained        # Accounts with constrained delegation + SPNs + protocol transition flag
gf ldap ... --rbcd               # Objects with resource-based constrained delegation configured
```

#### ADCS

```bash
gf ldap ... --adcs               # Enumerate CAs, enabled templates, and detect ESC1 vulnerabilities
```

ESC1 detection checks:
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set in `msPKI-Certificate-Name-Flag`
- Client Authentication EKU present (or no EKU restriction)
- No manager approval required
- No issuance agent requirements (`msPKI-RA-Signature == 0`)

#### Credential Attacks

```bash
gf ldap ... --shadow-creds       # Objects with msDS-KeyCredentialLink (shadow credentials)
gf ldap ... --weak-accounts      # Accounts with dangerous UAC flags
```

Weak account flags checked:
- `PASSWD_NOTREQD` — account may have an empty password
- `ENCRYPTED_TEXT_PWD_ALLOWED` — password stored with reversible encryption
- `USE_DES_KEY_ONLY` — Kerberos restricted to weak DES encryption
- `DONT_EXPIRE_PASSWORD` — password never expires

### SMB

```bash
# Authentication check
gf smb -t DC01.domain.local -u user -p 'Password123' -d domain.local

# Enumerate share access
gf smb -t DC01.domain.local -u user -p 'Password123' -d domain.local --shares

# Null session check
gf smb -t DC01.domain.local --null-session
```

> SMB currently uses Manticore's SMBv1 implementation. Modern Windows targets have SMBv1 disabled. SMBv2/v3 support will arrive when Manticore implements it.

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
