# Roadmap

This roadmap tracks what adshell-rs already does and what is planned. The goal is a single interactive AD attack tool that runs every action over **either LDAP or ADWS**, reusing the transport model of [RustHound-CE](https://github.com/g0h4n/RustHound-CE), the ADWS layer of [`adws`](https://github.com/g0h4n/adws), and the action set and style of [PassTheCert-rs](https://github.com/g0h4n/PassTheCert-rs).

## Transports

- [x] `--transport ldap` : LDAP/LDAPS (default) via [ldap3](https://crates.io/crates/ldap3) lib :white_check_mark:
- [x] `--transport soap` (alias `adws`) : ADWS / SOAP, tcp/9389, via [adws](https://crates.io/crates/adws) lib :white_check_mark:
- [x] `Session` abstraction so every action dispatches to the chosen transport :white_check_mark:
- [x] `--ldapport` overrides the port (389/636 for LDAP, 9389 for ADWS) :white_check_mark:

## Authentication

- [x] Username + password (LDAP simple bind / ADWS NTLM) :white_check_mark:
- [x] Pass-the-Hash (NTLM) over LDAP and ADWS :white_check_mark:
- [x] Pass-the-Certificate (Schannel, LDAP only) :white_check_mark:
- [x] Password prompt when `-u` is given without `-p` (LDAP + ADWS), like RustHound-CE :white_check_mark:
- [x] Kerberos (ccache) over LDAP :white_check_mark:
- [ ] Kerberos / certificate over ADWS (PKINIT, blocked on `adws`) :red_circle:

## Implemented actions

`--action` defaults to `ldapshell`, the interactive shell, which now drives **either transport** (each command dispatches to the LDAP or ADWS action by the active `Session`).

| Action | LDAP(S) | ADWS |
| ------ | ---- | ---- |
| `ldapshell` (interactive, default) | :white_check_mark: | :white_check_mark: |
| `whoami` | :white_check_mark: | :white_check_mark: |
| `read_object` | :white_check_mark: | :white_check_mark: |
| `dn` | :white_check_mark: | :white_check_mark: |
| `search <baseDN> [filter]` | :white_check_mark: | :white_check_mark: |
| `del_computer` | :white_check_mark: | :white_check_mark: |
| `add_computer` | :white_check_mark: | :white_check_mark: |
| `enable_account` / `disable_account` | :white_check_mark: | :white_check_mark: |
| `elevate` / `dcsync` | :white_check_mark: | :white_check_mark: |
| `add_member` / `remove_member` | :white_check_mark: | :white_check_mark: |
| `enable_account` / `disable_account` | :white_check_mark: | :white_check_mark: |
| `read_rbcd` / `write_rbcd` / `remove_rbcd` / `flush_rbcd` | :white_check_mark: | :white_check_mark: |
| `read_object` | :white_check_mark: | :white_check_mark: |
| `addshadow_cred` / `list_shadow_cred` / `remove_shadow_cred` /`flush_shadow_cred` | :white_check_mark: | :white_check_mark: |