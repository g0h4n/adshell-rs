//! LDAP(S) transport with all authentication methods:
//! simple bind (password), NTLM pass-the-hash, Kerberos (GSSAPI), and
//! Pass-the-Certificate (Schannel). Returns a ready `ldap3::Ldap` session the
//! actions operate on directly.

use anyhow::{anyhow, Result};
use ldap3::exop::WhoAmI;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use log::{debug, info, warn};

use super::cert;
use crate::args::Options;

/// Connect + authenticate, returning the bound `Ldap` session.
pub async fn ldap_auth(opts: &Options) -> Result<Ldap> {
    let use_cert = opts.pfx.is_some() || opts.crt.is_some();
    let use_ntlm = opts.hashes.is_some();

    // URL + transport selection.
    let target = opts
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| opts.ip.clone())
        .unwrap_or_else(|| opts.domain.clone());

    // Certificate auth: StartTLS 389 by default, LDAPS 636 with --ldaps.
    // Everything else: LDAP 389 (or LDAPS 636 with --ldaps).
    let starttls = use_cert && !opts.ldaps;
    let (url, is_ldaps) = if opts.ldaps {
        (format!("ldaps://{target}:{}", opts.port.unwrap_or(636)), true)
    } else {
        (format!("ldap://{target}:{}", opts.port.unwrap_or(389)), false)
    };

    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_no_tls_verify(true);
    if use_cert {
        let config = cert::build_client_config(
            opts.pfx.as_deref(),
            opts.pfx_pass.as_deref(),
            opts.crt.as_deref(),
            opts.key.as_deref(),
        )?;
        settings = settings.set_config(config);
        if starttls {
            settings = settings.set_starttls(true);
        }
    }

    info!("connecting to {url}");
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await?;
    ldap3::drive!(conn);

    let domain = &opts.domain;

    if use_cert {
        if starttls {
            debug!("certificate auth: SASL EXTERNAL over StartTLS");
            ldap.sasl_external_bind()
                .await
                .and_then(|r| r.success())
                .map_err(|e| anyhow!("SASL EXTERNAL bind failed (try --ldaps): {e}"))?;
        } else {
            debug!("certificate auth: implicit Schannel mapping over LDAPS");
        }
        let who = whoami_identity(&mut ldap).await?;
        info!("Pass-the-Certificate OK, Schannel identity: {who}");
    } else if use_ntlm {
        let user = ntlm_logon_name(domain, opts.username.as_deref().unwrap_or(""));
        let nt = parse_nt_hash(opts.hashes.as_deref().unwrap_or(""))?;
        let password = nt_hash_to_ntlm_password(&nt);
        debug!("NTLM pass-the-hash as {user}");
        ldap.sasl_ntlm_bind(&user, &password)
            .await?
            .success()
            .map_err(|e| anyhow!("NTLM authentication to {} failed: {e}", domain.to_uppercase()))?;
        info!("Connected to {} via NTLM!", domain.to_uppercase());
    } else if opts.kerberos {
        let _ = is_ldaps;
        // Kerberos needs ldap3's `gssapi` feature and libgssapi system libs; not
        // enabled in this build to keep it dependency-light. Re-enable by adding
        // `ldap3/gssapi` and a `sasl_gssapi_bind(fqdn)` call here.
        return Err(anyhow!(
            "Kerberos is not wired in this build (needs the ldap3 `gssapi` feature)"
        ));
    } else {
        // Simple bind as a UPN.
        let email = user_to_upn(opts.username.as_deref().unwrap_or(""), domain);
        let password = opts.password.clone().unwrap_or_default();
        debug!("simple bind as {email}");
        ldap.simple_bind(&email, &password)
            .await?
            .success()
            .map_err(|e| anyhow!("authentication to {} failed: {e}", domain.to_uppercase()))?;
        info!("Connected to {}!", domain.to_uppercase());
    }

    Ok(ldap)
}

/// `user@domain` for a bare sAMAccountName; passthrough if already a UPN.
fn user_to_upn(user: &str, domain: &str) -> String {
    if user.contains('@') { user.to_string() } else { format!("{user}@{domain}") }
}

/// `NETBIOS\user` for NTLM; strips a UPN suffix / down-level prefix first.
fn ntlm_logon_name(domain: &str, user: &str) -> String {
    let bare = user.rsplit('\\').next().unwrap_or(user);
    let bare = bare.split('@').next().unwrap_or(bare);
    let netbios = domain.split('.').next().unwrap_or(domain).to_uppercase();
    format!("{netbios}\\{bare}")
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

/// Encode an NT hash into the "password" sspi reads for pass-the-hash (same as
/// RustHound-CE): 32 upper-hex ASCII chars + 512 bytes of padding, UTF-16LE.
fn nt_hash_to_ntlm_password(nt: &[u8; 16]) -> String {
    let hex: String = nt.iter().map(|b| format!("{b:02X}")).collect();
    let bytes = hex.as_bytes();
    let mut password = String::new();
    for pair in bytes.chunks(2) {
        let low = pair[0] as u32;
        let high = if pair.len() > 1 { pair[1] as u32 } else { 0 };
        password.push(char::from_u32((high << 8) | low).unwrap_or('\0'));
    }
    for _ in 0..256 {
        password.push('\0');
    }
    password
}

/// whoami, parsing the raw value defensively (empty => clean error).
async fn whoami_identity(ldap: &mut Ldap) -> Result<String> {
    let res = ldap
        .extended(WhoAmI)
        .await
        .map_err(|e| anyhow!("whoami request failed: {e}"))?
        .success()
        .map_err(|e| anyhow!("whoami failed: {e}"))?;
    match &res.0.val {
        Some(v) if !v.is_empty() => Ok(String::from_utf8_lossy(v).to_string()),
        _ => {
            warn!("empty whoami (certificate not mapped?)");
            Err(anyhow!("server returned an empty identity"))
        }
    }
}
