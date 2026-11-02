# Changelog

## 1.0.0 - 2026-11-02

First release. An interactive shell and Active Directory attack toolkit that
runs every action over **either LDAP(S) or ADWS (SOAP)**, selected with
`--transport ldap|(adws,soap)`. Built on RustHound-CE's transport model and the
[`adws`](https://github.com/g0h4n/adws) crate.

### Added

- Dual transport, chosen at runtime with `-t, --transport ldap|soap` (alias
  `adws`, case-insensitive); LDAP is the default. A `Session` abstraction routes
  every action to the active wire.
- Interactive `ldapshell` (default action) driving either transport, with Tab
  completion and history.
- Action set over both LDAP and ADWS: `whoami`, `read_object`, group membership
  (`add_member` / `remove_member`), account status (`enable` / `disable`),
  `modify_user` (password reset, `--elevate` for DCSync), RBCD
  (`read` / `write` / `remove` / `flush`), Shadow Credentials
  (`add` / `list` / `remove` / `flush`), and computer accounts
  (`add_computer` / `del_computer`).
- Authentication: password, pass-the-hash (NTLM) and Pass-the-Certificate
  (Schannel) over LDAP; password and pass-the-hash over ADWS. The password is
  prompted when `-u` is given without `-p`, like RustHound-CE.
- Docs: README, HELP, ROADMAP.

### Validated

- Live against a lab DC (GOAD): LDAP and ADWS collection parity, the RBCD and
  computer-account write paths, and NTLM password / pass-the-hash auth.