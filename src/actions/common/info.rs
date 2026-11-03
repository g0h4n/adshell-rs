//! `info` command: show the current connection / authentication parameters,
//! transport-agnostic. Secrets (password, NT hash) are masked. Shared by both
//! the LDAP and ADWS sessions.

use crate::args::Options;
use crate::shlog;
use crate::transport::Session;

/// Resolve the host the transport dials: FQDN, else IP, else the domain.
fn resolved_host(opts: &Options) -> String {
    opts.ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| opts.ip.clone())
        .unwrap_or_else(|| opts.domain.clone())
}

/// Human name of the authentication method in effect.
fn auth_method(opts: &Options) -> &'static str {
    if opts.kerberos {
        "Kerberos (ccache)"
    } else if opts.pfx.is_some() {
        "Certificate (PFX/PKCS#12)"
    } else if opts.crt.is_some() {
        "Certificate (PEM crt+key)"
    } else if opts.hashes.is_some() {
        "Pass-the-Hash (NTLM)"
    } else if opts.password.is_some() {
        "Password (NTLM)"
    } else {
        "none / anonymous"
    }
}

/// Mask a secret: keep a short head and tail, hide the middle, show the length.
/// `AB…YZ (12 chars)`; very short secrets are fully starred.
fn mask(secret: &str) -> String {
    let n = secret.chars().count();
    if n == 0 {
        return "(empty)".to_string();
    }
    if n <= 4 {
        return format!("{} ({n} chars)", "*".repeat(n));
    }
    let head: String = secret.chars().take(2).collect();
    let tail: String = {
        let mut t: Vec<char> = secret.chars().rev().take(2).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("{head}\u{2026}{tail} ({n} chars)")
}

/// Print one aligned `label : value` row (label colored).
fn row(label: &str, value: &str) {
    shlog!("    {:<12} {}", format!("{label}:"), value);
}

/// Dump the connection/auth parameters of the active session.
pub fn run(session: &Session, opts: &Options) {
    let host = resolved_host(opts);

    // --- Transport / endpoint / security ---------------------------------
    match session {
        Session::Ldap(_) => {
            let port = opts.port.unwrap_or(if opts.ldaps { 636 } else { 389 });
            let scheme = if opts.ldaps { "ldaps" } else { "ldap" };
            row("Transport", &"LDAP");
            row("Endpoint", &format!("{scheme}://{host}:{port}"));
            row(
                "Security",
                if opts.ldaps { "LDAPS (TLS)" } else { "LDAP + StartTLS" },
            );
        }
        Session::Adws(_) => {
            let port = opts.port.unwrap_or(9389);
            row("Transport", &"ADWS (SOAP)");
            row(
                "Endpoint",
                &format!("net.tcp://{host}:{port}/ActiveDirectoryWebServices"),
            );
            row("Security", "MS-NNS (NegotiateStream, sign+seal)");
        }
    }

    // --- Target ----------------------------------------------------------
    row("Domain", &opts.domain);
    if let Some(fqdn) = opts.ldapfqdn.as_deref().filter(|s| !s.is_empty()) {
        row("DC FQDN", fqdn);
    }
    if let Some(ip) = opts.ip.as_deref() {
        row("DC IP", ip);
    }

    // --- Authentication --------------------------------------------------
    row("Auth", auth_method(opts));
    if let Some(u) = opts.username.as_deref() {
        row("Username", u);
    }
    if let Some(p) = opts.password.as_deref() {
        row("Password", &mask(p));
    }
    if let Some(h) = opts.hashes.as_deref() {
        row("NT hash", &mask(h));
    }
    if opts.kerberos {
        let ccache = std::env::var("KRB5CCNAME").unwrap_or_else(|_| "(KRB5CCNAME not set)".into());
        row("Kerberos", &format!("ccache: {ccache}"));
    }
    if let Some(pfx) = opts.pfx.as_deref() {
        row("PFX", pfx);
        if opts.pfx_pass.is_some() {
            row("PFX pass", &mask(opts.pfx_pass.as_deref().unwrap_or("")));
        }
    }
    if let Some(crt) = opts.crt.as_deref() {
        row("Cert (crt)", crt);
    }
    if let Some(key) = opts.key.as_deref() {
        row("Cert (key)", key);
    }
}