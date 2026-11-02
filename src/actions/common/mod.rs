//! Transport-agnostic helpers shared by the `ldap` and `adws` actions.

pub mod dump;
pub mod sd;
pub mod keycred;

/// `domain.local` => `dc=domain,dc=local`.
pub fn base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("dc={p}"))
        .collect::<Vec<_>>()
        .join(",")
}
