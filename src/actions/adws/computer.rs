//! Computer account actions over ADWS: add_computer (WS-Transfer Create) and
//! del_computer (Delete), via adws.

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Scope, Value};
use log::info;

use crate::actions::common::base_dn;
use crate::args::Options;

use super::{escape_filter, resolve_dn};

fn random_name() -> String {
    use rand::Rng;
    let s: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(8)
        .map(|c| c as char)
        .collect::<String>()
        .to_uppercase();
    format!("DESKTOP-{s}$")
}

fn pwd_utf16(p: &str) -> Vec<u8> {
    format!("\"{p}\"").encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

async fn exists(client: &mut AdwsClient, base: &str, sam: &str) -> Result<bool> {
    let filter = format!("(sAMAccountName={})", escape_filter(sam));
    let entries = client
        .search(base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await
        .map_err(|e| anyhow!("ADWS lookup for '{sam}': {e}"))?;
    Ok(!entries.is_empty())
}

pub async fn run(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let base = base_dn(&opts.domain);
    let group = opts
        .computer_group
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| format!("CN=Computers,{base}"));
    let name = opts
        .computer_name
        .clone()
        .map(|n| if n.ends_with('$') { n } else { format!("{n}$") })
        .unwrap_or_else(random_name);
    let pass = opts.computer_pass.clone().unwrap_or_else(|| {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(|c| c as char)
            .collect()
    });

    if exists(client, &base, &name).await? {
        return Err(anyhow!("computer account {name} already exists"));
    }

    let hostname = name.trim_end_matches('$');
    let dn = format!("CN={hostname},{group}");
    let dns = format!("{hostname}.{}", opts.domain);

    // ADWS/IMDA Create wants only the structural class "computer" (unlike an
    // LDAP add, which lists the full top/person/.../computer chain).
    let t = |s: String| Value::Text(s);
    let attrs: Vec<(String, Vec<Value>)> = vec![
        ("objectClass".into(), vec![t("computer".into())]),
        ("sAMAccountName".into(), vec![t(name.clone())]),
        ("dNSHostName".into(), vec![t(dns.clone())]),
        ("userAccountControl".into(), vec![t("4096".into())]), // WORKSTATION_TRUST_ACCOUNT
        ("unicodePwd".into(), vec![Value::Bytes(pwd_utf16(&pass))]),
        (
            "servicePrincipalName".into(),
            vec![t(format!("HOST/{hostname}")), t(format!("HOST/{dns}"))],
        ),
    ];

    client.create(&dn, &attrs).await.map_err(|e| anyhow!("add_computer failed: {e}"))?;
    info!("computer account '{name}' created with password: {pass}");
    Ok(())
}

pub async fn del_computer(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let name = opts
        .computer_name
        .as_deref()
        .ok_or_else(|| anyhow!("--computer-name (e.g. EVIL$) required"))?;
    let name = if name.ends_with('$') { name.to_string() } else { format!("{name}$") };
    let base = base_dn(&opts.domain);
    let dn = resolve_dn(client, &base, &name).await?;
    client.delete(&dn).await.map_err(|e| anyhow!("del_computer failed: {e}"))?;
    info!("computer account '{name}' deleted ({dn})");
    Ok(())
}