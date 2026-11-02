//! Attack / management actions.
//!
//! * `common`: transport-agnostic helpers (binary security descriptors, SID
//!   conversion, base DN, object dump/decoding).
//! * `ldap`: actions over an `ldap3::Ldap` session.
//! * `soap`: actions over an `adws::AdwsClient` session.
//! * `shell`: the interactive shell, dispatching each command to the `ldap` or
//!   `adws` action by the active transport.
//!
//! An action usually shares its payload building (an ACE, a KeyCredential, a
//! UTF-16 password) through `common`, and only the read/modify step differs
//! between the two transports.

pub mod adws;
pub mod common;
pub mod ldap;
pub mod shell;
pub mod shell_completer;
