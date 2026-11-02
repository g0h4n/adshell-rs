//! whoami over ADWS.
//!
//! ADWS has no RFC 4532 "Who am I?" extended operation, so this reports the
//! principal we authenticated as and confirms the session by reading the
//! RootDSE naming contexts.

use anyhow::{anyhow, Result};
use adws_rs::AdwsClient;
use log::info;

use crate::args::Options;

pub async fn run(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let raw = opts.username.as_deref().unwrap_or("<unknown>");
    let user = raw.rsplit('\\').next().unwrap_or(raw);
    let user = user.split('@').next().unwrap_or(user);
    let netbios = opts.domain.split('.').next().unwrap_or(&opts.domain).to_uppercase();

    let ncs = client
        .naming_contexts()
        .await
        .map_err(|e| anyhow!("ADWS RootDSE read failed: {e}"))?;

    info!("[whoami] authenticated as {netbios}\\{user} over ADWS");
    if let Some(nc) = ncs.iter().find(|n| n.to_lowercase().starts_with("dc=")) {
        info!("[whoami] default naming context: {nc}");
    }
    Ok(())
}
