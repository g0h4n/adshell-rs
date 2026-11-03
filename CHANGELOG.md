# Changelog

## 1.0.1 - 2026-11-03

### Added

- `info` command: shows the current connection and authentication parameters
  (transport, endpoint, security, domain, DC, auth method, username), with the
  password and NT hash masked. Transport-agnostic (LDAP and ADWS), in
  `actions::common::info`.
- `log` command (mimikatz-style): `log` logs the session to
  `<TIMESTAMP>-adshell-rs.log`, `log <file>` to a chosen file, `log stop` ends
  it. Every command is written with a local timestamp (`[ts] $ <command>`), and
  all output is mirrored to the file: `log`-facade records (via an `env_logger`
  `.format` tee) and the shell's own output (via the `shlog!` macro), with ANSI
  color codes stripped.
- Colored interactive prompt `[adshell-rs] $` (brackets dark gray, name orange,
  `$` white) with the typed command shown in light gray. Cross-platform through
  `colored`.
- Shadow Credentials over ADWS (SOAP): `add_shadow_cred` / `list_shadow_cred` /
  `remove_shadow_cred` / `flush_shadow_cred` now run over the ADWS transport,
  reaching parity with the LDAP path.

### Changed

- `read_object` (LDAP) now uses the shared `common::dump` decoder, so its output
  matches the ADWS path exactly (SID / GUID / userAccountControl / FILETIME).
  The duplicated decoding (~215 lines) was removed.
- Action output is routed through the `shlog!` macro so the `log` command
  captures it in the log file.
- The `rustyline` backend is capped at `warn` so its key-event / layout DEBUG
  spam no longer floods the prompt at `-v` / `-vv`.

### Dependencies

- Added `colored` (prompt / shell colors) and `chrono` (local-time log
  timestamps).

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