//! Actions over an `adws::AdwsClient` session (ADWS / SOAP transport).
//!
//! Mirrors the `actions::ldap` set; the payload building (security descriptors,
//! SID conversion) is shared through `actions::common`. Only the read/modify
//! step differs: `AdwsClient::search` / `modify` / `delete` instead of `ldap3`.

pub mod account;
pub mod computer;
pub mod group;
pub mod modify_user;
pub mod rbcd;
pub mod read_object;
pub mod shadow_cred;
pub mod whoami;

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Scope};

/// RFC 4515 escape for a filter assertion value.
pub(crate) fn escape_filter(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Resolve a sAMAccountName to `(dn, objectSid-bytes)`.
pub(crate) async fn find_object(
    client: &mut AdwsClient,
    base: &str,
    sam: &str,
) -> Result<(String, Vec<u8>)> {
    let filter = format!("(sAMAccountName={})", escape_filter(sam));
    let entries = client
        .search(base, Scope::Subtree, &filter, &["objectSid"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS search for '{sam}': {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("object '{sam}' not found"))?;
    let sid = e.bin_attrs.get("objectSid").and_then(|v| v.first().cloned()).unwrap_or_default();
    Ok((e.dn, sid))
}

/// Resolve a sAMAccountName to its distinguishedName.
pub(crate) async fn resolve_dn(client: &mut AdwsClient, base: &str, sam: &str) -> Result<String> {
    let filter = format!("(sAMAccountName={})", escape_filter(sam));
    let entries = client
        .search(base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS search for '{sam}': {e}"))?;
    entries.into_iter().next().map(|e| e.dn).ok_or_else(|| anyhow!("object '{sam}' not found"))
}

/// Resolve a group's DN (value may be a sAMAccountName or already a DN).
pub(crate) async fn resolve_group_dn(client: &mut AdwsClient, base: &str, group: &str) -> Result<String> {
    if group.to_lowercase().contains("dc=") {
        return Ok(group.to_string());
    }
    let filter = format!("(&(objectClass=group)(sAMAccountName={}))", escape_filter(group));
    let entries = client
        .search(base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS search for group '{group}': {e}"))?;
    entries.into_iter().next().map(|e| e.dn).ok_or_else(|| anyhow!("group '{group}' not found"))
}
