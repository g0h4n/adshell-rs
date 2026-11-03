//! group actions over ADWS: add_member / remove_member (group `member` attr).

use anyhow::{anyhow, Result};
use adws_rs::{Mod, Value};

use crate::{actions::common::base_dn, shlog};
use crate::args::Options;

use super::{resolve_dn, resolve_group_dn};

pub async fn add_member(client: &mut adws_rs::AdwsClient, opts: &Options) -> Result<()> {
    let member = opts.target.as_deref().ok_or_else(|| anyhow!("--target (member) required"))?;
    let group = opts.group.as_deref().ok_or_else(|| anyhow!("--group required"))?;
    let base = base_dn(&opts.domain);

    let member_dn = resolve_dn(client, &base, member).await?;
    let group_dn = resolve_group_dn(client, &base, group).await?;

    client
        .modify(&group_dn, &[Mod::add("member", vec![Value::Text(member_dn)])], None)
        .await
        .map_err(|e| anyhow!("add_member failed (need write on the group): {e}"))?;
    shlog!("added '{member}' to group '{group}'");
    Ok(())
}

pub async fn remove_member(client: &mut adws_rs::AdwsClient, opts: &Options) -> Result<()> {
    let member = opts.target.as_deref().ok_or_else(|| anyhow!("--target (member) required"))?;
    let group = opts.group.as_deref().ok_or_else(|| anyhow!("--group required"))?;
    let base = base_dn(&opts.domain);

    let member_dn = resolve_dn(client, &base, member).await?;
    let group_dn = resolve_group_dn(client, &base, group).await?;

    client
        .modify(&group_dn, &[Mod::delete("member", vec![Value::Text(member_dn)])], None)
        .await
        .map_err(|e| anyhow!("remove_member failed (need write on the group): {e}"))?;
    shlog!("removed '{member}' from group '{group}'");
    Ok(())
}
