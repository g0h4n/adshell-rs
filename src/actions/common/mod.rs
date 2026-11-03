//! Transport-agnostic helpers shared by the `ldap` and `adws` actions.

pub mod dump;
pub mod info;
pub mod keycred;
pub mod logfile;
pub mod sd;

/// `domain.local` => `dc=domain,dc=local`.
pub fn base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("dc={p}"))
        .collect::<Vec<_>>()
        .join(",")
}