<p align="center">
  <img src="assets/logo.png" alt="GoFenrir Logo" width="200"/>
</p>

<h1 align="center">GoFenrir</h1>

<p align="center">
  A NetExec-like network execution framework written in Go, powered by <a href="https://github.com/TheManticoreProject/Manticore">TheManticoreProject/Manticore</a>.
</p>

---

## What is GoFenrir?

GoFenrir is a network attack and enumeration framework inspired by [NetExec](https://github.com/Pennyw0rth/NetExec), rebuilt from the ground up in Go using [Manticore](https://github.com/TheManticoreProject/Manticore) as its only backend library — just like NetExec relies exclusively on impacket.

The goal: a single, portable, dependency-free binary for Active Directory and network pentesting.

## Supported Protocols

| Protocol | Status |
|----------|--------|
| LDAP / LDAPS | In progress |
| SMB v1 | Planned |
| Kerberos | Planned |

> Protocol support grows alongside [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore).

## Usage

```
gofenrir <protocol> [options]

Protocols:
  ldap    Interact with LDAP/LDAPS
  smb     Interact with SMB

Examples:
  gofenrir ldap -t 192.168.1.1 -u admin -p Password123
  gofenrir ldap -t 192.168.1.0/24 -u admin -H <NT_HASH>
```

## Installation

```bash
git clone https://github.com/0xbbuddha/GoFenrir
cd GoFenrir
go build -o gofenrir ./cmd/
```

## Built With

- [Go](https://golang.org/)
- [TheManticoreProject/Manticore](https://github.com/TheManticoreProject/Manticore)
- [Cobra](https://github.com/spf13/cobra) — CLI framework

## Disclaimer

GoFenrir is intended for authorized security testing and research only. Use responsibly.
