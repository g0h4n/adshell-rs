//! ADWS / SOAP transport via the `adws` crate. Returns a connected
//! `AdwsClient` the actions operate on. NTLM only for now (password /
//! pass-the-hash); Kerberos and certificate over ADWS are not wired yet.

use anyhow::{anyhow, Result};
use adws_rs::client::Target;
use adws_rs::{AdwsClient, Credentials};
use log::{debug, info};

use crate::args::Options;

/// Connect to the DC's ADWS endpoint (TCP 9389) and authenticate.
pub async fn adws_auth(opts: &Options) -> Result<AdwsClient> {
    if opts.kerberos || opts.pfx.is_some() || opts.crt.is_some() {
        return Err(anyhow!(
            "ADWS (-t soap) supports only password / NT-hash (NTLM); Kerberos and \
             certificate auth over ADWS are not wired yet"
        ));
    }

    let host = opts
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| opts.ip.clone())
        .unwrap_or_else(|| opts.domain.clone());

    let raw_user = opts.username.clone().ok_or_else(|| anyhow!("ADWS requires a username (-u)"))?;
    let username = bare_sam(&raw_user);
    let nt_domain = opts.domain.split('.').next().unwrap_or(&opts.domain).to_uppercase();

    let creds = if let Some(h) = opts.hashes.as_deref() {
        let nt_hash = parse_nt_hash(h)?;
        debug!("ADWS NTLM pass-the-hash as {nt_domain}\\{username}");
        Credentials::NtHash { domain: nt_domain, username, nt_hash }
    } else {
        let password = opts.password.clone().ok_or_else(|| anyhow!("ADWS requires a password (-p) or NT hash (-H)"))?;
        debug!("ADWS NTLM password as {nt_domain}\\{username}");
        Credentials::Password { domain: nt_domain, username, password }
    };

    let mut target = Target::new(host, opts.domain.clone());
    if let Some(port) = opts.port {
        target.port = port;
    }

    let client = AdwsClient::connect(target, creds)
        .await
        .map_err(|e| anyhow!("ADWS connection failed: {e}"))?;
    info!("Connected to {} via ADWS (SOAP)!", opts.domain.to_uppercase());
    Ok(client)
}

/// Reduce a `-u` value to the bare sAMAccountName.
fn bare_sam(raw: &str) -> String {
    let after = raw.rsplit('\\').next().unwrap_or(raw);
    after.split('@').next().unwrap_or(after).to_string()
}

/// Parse an NT hash ("32 hex", ":NTHASH" or "LM:NT") into 16 bytes.
fn parse_nt_hash(h: &str) -> Result<[u8; 16]> {
    let nt = h.trim().rsplit(':').next().unwrap_or(h).trim();
    if nt.len() != 32 || !nt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid NT hash: expected 32 hex characters"));
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&nt[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
