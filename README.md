<p align="center">
  <img src="assets/logo.png" alt="GoFenrir Logo" width="200"/>
</p>

<h1 align="center">GoFenrir</h1>

<p align="center">
  NetExec-like network execution framework written in Go, built on top of <a href="https://github.com/TheManticoreProject/Manticore">TheManticoreProject/Manticore</a>.
</p>

## What is GoFenrir?

GoFenrir is a network attack and enumeration framework inspired by [NetExec](https://github.com/Pennyw0rth/NetExec). The idea is simple: NetExec uses impacket as its backend, GoFenrir uses [Manticore](https://github.com/TheManticoreProject/Manticore) instead. Everything is written in Go, single binary, no Python dependency hell.

## Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| LDAP / LDAPS | Working | Full enumeration support |
| SMB v1 | Working | Limited to targets with SMBv1 enabled |
| SMB v2/v3 | Not yet | Waiting on Manticore to implement it |
| Kerberos | Partial | Waiting on Manticore |

Protocol support grows alongside [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore).

## Usage

```
gofenrir <protocol> [options]
```

### LDAP

```bash
# Auth check
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local

# Pass-the-Hash
gofenrir ldap -t DC01.domain.local -u user -H <NT_HASH> -d domain.local

# Enumeration
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --users
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --groups
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --dcs
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --kerberoastable
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --asreproast
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --admins
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --computers
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --pwd-policy
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --trusts
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --gpos
gofenrir ldap -t DC01.domain.local -u user -p 'Password123' -d domain.local --ous
```

### SMB

```bash
# Auth check
gofenrir smb -t DC01.domain.local -u user -p 'Password123' -d domain.local

# Check share access
gofenrir smb -t DC01.domain.local -u user -p 'Password123' -d domain.local --shares

# Null session
gofenrir smb -t DC01.domain.local --null-session
```

> SMB currently uses Manticore's SMBv1 implementation. Modern Windows systems have SMBv1 disabled so it won't work against those. SMBv2/v3 support will come when Manticore implements it.

## Installation

```bash
git clone https://github.com/0xbbuddha/GoFenrir
cd GoFenrir
go build -o gofenrir ./cmd/
```

## Built With

- [Go](https://golang.org/)
- [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore)
- [Cobra](https://github.com/spf13/cobra)

## Disclaimer

For authorized security testing only.
