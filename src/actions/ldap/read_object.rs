//! read_object action (LDAP): dump every attribute of a single AD object.
//!
//! Resolves a target by sAMAccountName, CN, or full DN, then performs a
//! Scope::Base search asking for all attributes (user + operational) and
//! prints them via the shared `common::dump` pretty-printer (same output as
//! the ADWS read_object).

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Scope, SearchEntry};
use log::debug;

use crate::actions::common::{base_dn, dump};
use crate::args::Options;

// Heuristic: does the string look like a distinguished name?
fn looks_like_dn(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("cn=") || l.starts_with("ou=") || l.starts_with("dc=") || l.contains(",dc=")
}

// Resolve the target to a DN. Accepts a full DN, a sAMAccountName (with or
// without a trailing '$' for machine accounts), or a CN.
async fn resolve_dn(ldap: &mut Ldap, base: &str, target: &str) -> Result<String> {
    if looks_like_dn(target) {
        debug!("[read_object] target treated as DN: {target}");
        return Ok(target.to_string());
    }

    let dollar = format!("{target}$");
    let filter = format!(
        "(|(sAMAccountName={})(sAMAccountName={})(cn={})(name={}))",
        ldap3::ldap_escape(target),
        ldap3::ldap_escape(&dollar),
        ldap3::ldap_escape(target),
        ldap3::ldap_escape(target),
    );
    debug!("[read_object] resolve filter: {filter}");

    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("object '{target}' not found"))?;
    let dn = SearchEntry::construct(entry).dn;
    debug!("[read_object] resolved DN: {dn}");
    Ok(dn)
}

/// Dump every attribute of the target object.
pub async fn run(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target required (sAMAccountName, CN, or DN)"))?;
    let base = base_dn(&opts.domain);
    let dn = resolve_dn(ldap, &base, target).await?;

    // "*" = all user attributes, "+" = all operational attributes.
    debug!("[read_object] base search on {dn}");
    let (rs, _) = ldap
        .search(&dn, Scope::Base, "(objectClass=*)", vec!["*", "+"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("object not found or not readable: {dn}"))?;
    let se = SearchEntry::construct(entry);

    // Shared decoder (SID / GUID / UAC / FILETIME / opaque blobs), identical
    // output to the ADWS path.
    dump::dump(&se.dn, &se.attrs, &se.bin_attrs);

    debug!("[read_object] dumped {} attribute name(s)", se.attrs.len() + se.bin_attrs.len());
    Ok(())
}