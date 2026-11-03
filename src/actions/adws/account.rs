//! account actions over ADWS: enable_account / disable_account.
//! Toggles the ACCOUNTDISABLE (0x2) bit of userAccountControl.

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Mod, Scope, Value};

use crate::actions::common::base_dn;
use crate::args::Options;
use crate::shlog;

use super::escape_filter;

const UAC_ACCOUNTDISABLE: u32 = 0x0002;

/// Fetch (dn, current userAccountControl).
async fn get_uac(client: &mut AdwsClient, base: &str, sam: &str) -> Result<(String, u32)> {
    let filter = format!("(sAMAccountName={})", escape_filter(sam));
    let entries = client
        .search(base, Scope::Subtree, &filter, &["userAccountControl"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS search for '{sam}': {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("account '{sam}' not found"))?;
    let uac = e
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| anyhow!("could not read userAccountControl for '{sam}'"))?;
    Ok((e.dn, uac))
}

async fn set_uac(client: &mut AdwsClient, dn: &str, uac: u32) -> Result<()> {
    client
        .modify(dn, &[Mod::replace("userAccountControl", vec![Value::Text(uac.to_string())])], None)
        .await
        .map_err(|e| anyhow!("failed to write userAccountControl (need write access): {e}"))?;
    Ok(())
}

pub async fn enable(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref().ok_or_else(|| anyhow!("--target required"))?;
    let base = base_dn(&opts.domain);
    let (dn, uac) = get_uac(client, &base, target).await?;
    if uac & UAC_ACCOUNTDISABLE == 0 {
        shlog!("account '{target}' is already enabled (UAC={uac})");
        return Ok(());
    }
    let new_uac = uac & !UAC_ACCOUNTDISABLE;
    set_uac(client, &dn, new_uac).await?;
    shlog!("account '{target}' enabled (UAC {uac} -> {new_uac})");
    Ok(())
}

pub async fn disable(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref().ok_or_else(|| anyhow!("--target required"))?;
    let base = base_dn(&opts.domain);
    let (dn, uac) = get_uac(client, &base, target).await?;
    if uac & UAC_ACCOUNTDISABLE != 0 {
        shlog!("account '{target}' is already disabled (UAC={uac})");
        return Ok(());
    }
    let new_uac = uac | UAC_ACCOUNTDISABLE;
    set_uac(client, &dn, new_uac).await?;
    shlog!("account '{target}' disabled (UAC {uac} -> {new_uac})");
    Ok(())
}
