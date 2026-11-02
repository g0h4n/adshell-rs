//! Network transports (RustHound-CE layout).
//!
//! * `ldap`: LDAP/LDAPS + StartTLS, all authentication methods (password,
//!   pass-the-hash, Kerberos, certificate).
//! * `adws`: ADWS / SOAP (TCP 9389) via the `adws` crate (NTLM for now).
//! * `cert`: rustls ClientConfig carrying a client certificate (PFX/PEM).
//!
//! [`connect`] returns a [`Session`] over the transport chosen in `Options`;
//! actions then operate on the concrete session (`ldap3::Ldap` or
//! `adws::AdwsClient`) because reads *and writes* are transport-specific.

pub mod adws;
pub mod cert;
pub mod ldap;

use anyhow::Result;

use crate::args::{Options, Transport};

/// An authenticated directory session.
pub enum Session {
    Ldap(ldap3::Ldap),
    Adws(adws_rs::AdwsClient),
}

/// Connect and authenticate over the transport selected in `opts`.
pub async fn connect(opts: &Options) -> Result<Session> {
    match opts.transport {
        Transport::Soap => {
            log::info!("transport: ADWS (SOAP, tcp/9389)");
            Ok(Session::Adws(adws::adws_auth(opts).await?))
        }
        Transport::Ldap => {
            log::info!("transport: LDAP");
            Ok(Session::Ldap(ldap::ldap_auth(opts).await?))
        }
    }
}
