//! read_object over ADWS: dump every attribute of a single AD object,
//! pretty-printed via `actions::common::dump` (same output as LDAP).

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Scope};
use log::debug;

use crate::actions::common::{base_dn, dump};
use crate::args::Options;

use super::escape_filter;

fn looks_like_dn(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("cn=") || l.starts_with("ou=") || l.starts_with("dc=") || l.contains(",dc=")
}

async fn resolve_dn(client: &mut AdwsClient, base: &str, target: &str) -> Result<String> {
    if looks_like_dn(target) {
        return Ok(target.to_string());
    }
    let dollar = format!("{target}$");
    let filter = format!(
        "(|(sAMAccountName={})(sAMAccountName={})(cn={})(name={}))",
        escape_filter(target),
        escape_filter(&dollar),
        escape_filter(target),
        escape_filter(target),
    );
    let entries = client
        .search(base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS resolve of '{target}': {e}"))?;
    entries.into_iter().next().map(|e| e.dn).ok_or_else(|| anyhow!("object '{target}' not found"))
}

pub async fn run(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target required (sAMAccountName, CN, or DN)"))?;
    let base = base_dn(&opts.domain);
    let dn = resolve_dn(client, &base, target).await?;

    debug!("[read_object] base search on {dn}");
    // ADWS has no "+" (operational) wildcard like LDAP, and `addata:+` is an
    // invalid selection property; "*" maps to ad:all (all user attributes).
    let entries = client
        .search(&dn, Scope::Base, "(objectClass=*)", &["*"], None, false)
        .await
        .map_err(|e| anyhow!("object not found or not readable: {dn}: {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("object not found or not readable: {dn}"))?;

    dump::dump(&e.dn, &e.attrs, &e.bin_attrs);
    Ok(())
}