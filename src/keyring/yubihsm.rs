/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

//! YubiHSM 2 backed keyring using hybrid HSM-derived keys + local AES-256-GCM file storage.
//!
//! # Design
//!
//! One HMAC-SHA256 key lives on the YubiHSM 2.  For each secret:
//!
//! 1. **Nonce** (12 bytes): `SHA-256("cryptex-nonce" ‖ OS_rng₃₂ ‖ HSM_rng₃₂)[..12]`.
//!    This limites RNG manipulation attacks as attackers much affect two sources of randomness
//!    and even if they manage to affect both, hashing the result mitigates the impact since it
//!    destroys any structure in the randomness.
//!
//! 2. **PRK**: `HMAC-SHA256(master_key, "cryptex-keyring" ‖ version ‖ uuid ‖ key_id_BE ‖ nonce)`
//!    computed **on the YubiHSM** — the raw key never leaves the device.
//!
//! 3. **K_enc = PRK** — the HMAC output is already 32 bytes of pseudorandom key material,
//!    domain-separated and per-entry unique, so no further derivation is needed.
//!
//! 4. **Ciphertext**: `AES-256-GCM(K_enc, nonce, plaintext, AAD)` where
//!    `AAD = version ‖ uuid ‖ key_id_BE ‖ nonce`.
//!
//! Each secret is stored as a small binary file under `~/.cryptex/yubihsm/<service>/`.
//! The YubiHSM only needs to store **one HMAC key** regardless of how many secrets exist.
//!
//! # Connection string
//!
//! ```text
//! # USB (no daemon needed, just libusb):
//! connector=usb hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp
//!
//! # HTTP (requires yubihsm-connector):
//! connector=http addr=127.0.0.1 port=12345 hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp
//! ```
//!
//! # One-time setup
//!
//! Before first use, generate the HMAC key on the device:
//!
//! ```no_run
//! cryptex::yubihsm::YubiHsmKeyRing::setup(
//!     "connector=usb auth_key_id=1 password=password domain=1",
//!     2,   // object ID for the new HMAC key
//! ).unwrap();
//! ```

use super::*;
use crate::error::KeyRingError;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};
use zeroize::{Zeroize, Zeroizing};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Domain-separation tag used in the HMAC input.
const CONTEXT: &[u8] = b"cryptex-keyring";

/// Domain-separation tag used when mixing OS + HSM randomness for the nonce.
const NONCE_DST: &[u8] = b"cryptex-nonce";

/// Current entry format version stored in every file.
const ENTRY_VERSION: u8 = 1;

// ─── Public types ────────────────────────────────────────────────────────────

/// YubiHSM 2 keyring: one HMAC key on-device, unlimited AES-256-GCM encrypted
/// secrets stored as local files.
pub struct YubiHsmKeyRing {
    client: ::yubihsm::Client,
    domain: ::yubihsm::Domain,
    /// Object ID of the HMAC-SHA256 key on the YubiHSM.
    hmac_key_id: u16,
    /// 16-byte identifier derived from the device serial number.
    device_uuid: [u8; 16],
    /// Directory where entry files are stored.
    storage_dir: PathBuf,
}

/// On-disk representation of an encrypted secret.
#[derive(Clone)]
pub struct Entry {
    pub version: u8,
    pub yubihsm_uuid: [u8; 16],
    pub key_id: u16,
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext (includes 16-byte authentication tag).
    pub ciphertext: Vec<u8>,
}

// ─── DynKeyRing ──────────────────────────────────────────────────────────────

impl DynKeyRing for YubiHsmKeyRing {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        let path = self.entry_path(id);
        if !path.exists() {
            return Err(KeyRingError::ItemNotFound);
        }

        let (_stored_id, entry) = read_entry_file(&path)?;
        let plaintext = self.decrypt_entry(&entry)?;
        Ok(KeyRingSecret(plaintext))
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        let nonce = self.generate_nonce()?;
        let entry = self.encrypt_entry(secret, nonce)?;
        let path = self.entry_path(id);
        write_entry_file(&path, id, &entry)
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        let path = self.entry_path(id);
        if !path.exists() {
            return Err(KeyRingError::ItemNotFound);
        }
        fs::remove_file(&path).map_err(io_err)
    }
}

// ─── NewKeyRing ──────────────────────────────────────────────────────────────

impl NewKeyRing for YubiHsmKeyRing {
    fn new<S: AsRef<str>>(connection_string: S) -> Result<Self> {
        connection_string
            .as_ref()
            .parse::<ConnectionParams>()?
            .open()
    }
}

// ─── YubiHsmKeyRing impl ─────────────────────────────────────────────────────

impl YubiHsmKeyRing {
    /// One-time setup: generate an HMAC-SHA256 key at `hmac_key_id` on the device.
    ///
    /// The auth key used must have the `GENERATE_HMAC_KEY` and `SIGN_HMAC` capabilities.
    /// Call this once; subsequent calls with the same ID will fail (object already exists).
    pub fn setup(connection_string: &str, hmac_key_id: u16) -> Result<()> {
        let params: ConnectionParams = connection_string.parse()?;
        let ring = params.open()?;
        let label = ::yubihsm::object::Label::from_bytes(b"cryptex-hmac").map_err(hsm_label_err)?;
        ring.client
            .generate_hmac_key(
                hmac_key_id,
                label,
                ring.domain,
                ::yubihsm::Capability::SIGN_HMAC,
                ::yubihsm::hmac::Algorithm::Sha256,
            )
            .map_err(hsm_err)?;
        Ok(())
    }

    /// List all secrets stored for this keyring instance's service.
    pub fn list_hsm_secrets(&self) -> Result<Vec<BTreeMap<String, String>>> {
        let mut results = Vec::new();
        let entries = fs::read_dir(&self.storage_dir).map_err(io_err)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            if let Ok((id, e)) = read_entry_file(&path) {
                let mut map = BTreeMap::new();
                map.insert("id".to_string(), id);
                map.insert("key_id".to_string(), e.key_id.to_string());
                map.insert("uuid".to_string(), hex::encode(e.yubihsm_uuid));
                results.push(map);
            }
        }
        Ok(results)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn entry_path(&self, id: &str) -> PathBuf {
        self.storage_dir.join(entry_filename(id))
    }

    /// Generate a 12-byte nonce from combined OS RNG and HSM pseudo-random,
    /// domain-separated with `"cryptex-nonce"`.
    fn generate_nonce(&self) -> Result<[u8; 12]> {
        // 32 bytes from OS RNG
        let mut os_rand = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(os_rand.as_mut()).map_err(|e| KeyRingError::GeneralError {
            msg: format!("OS RNG failed: {}", e),
        })?;

        // 32 bytes from HSM pseudo-random
        let hsm_rand = self.client.get_pseudo_random(32).map_err(hsm_err)?;

        // nonce = SHA-256("cryptex-nonce" || os_rand || hsm_rand)[..12]
        let mut hasher = Sha256::new();
        hasher.update(NONCE_DST);
        hasher.update(os_rand.as_ref());
        hasher.update(&hsm_rand);
        let digest = hasher.finalize();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        Ok(nonce)
    }

    /// Derive K_enc for `entry`: the PRK from the YubiHSM HMAC is used directly as the
    /// AES-256-GCM key.  It is already 32 bytes of pseudorandom output, domain-separated
    /// by the `"cryptex-keyring"` prefix and per-entry unique via the nonce, so no further
    /// derivation step is needed.
    fn derive_key(&self, entry: &Entry) -> Result<Zeroizing<[u8; 32]>> {
        // HMAC input: "cryptex-keyring" || version || uuid || key_id_BE || nonce
        let mut hmac_input = Vec::with_capacity(CONTEXT.len() + 1 + 16 + 2 + 12);
        hmac_input.extend_from_slice(CONTEXT);
        hmac_input.push(entry.version);
        hmac_input.extend_from_slice(&entry.yubihsm_uuid);
        hmac_input.extend_from_slice(&entry.key_id.to_be_bytes());
        hmac_input.extend_from_slice(&entry.nonce);

        // K_enc = HMAC-SHA256(master_key, hmac_input) — computed on the YubiHSM
        let tag = self
            .client
            .sign_hmac(entry.key_id, hmac_input)
            .map_err(hsm_err)?;

        let mut k_enc = Zeroizing::new([0u8; 32]);
        k_enc.copy_from_slice(tag.as_slice());
        Ok(k_enc)
    }

    /// Build the 31-byte AAD: `version || uuid || key_id_BE || nonce`.
    ///
    /// Including `version` prevents an attacker from reinterpreting a v1 blob as a later
    /// version with different key-derivation semantics — any version byte change causes
    /// authentication to fail.
    fn build_aad(entry: &Entry) -> [u8; 31] {
        let mut aad = [0u8; 31];
        aad[0] = entry.version;
        aad[1..17].copy_from_slice(&entry.yubihsm_uuid);
        aad[17..19].copy_from_slice(&entry.key_id.to_be_bytes());
        aad[19..31].copy_from_slice(&entry.nonce);
        aad
    }

    fn encrypt_entry(&self, plaintext: &[u8], nonce: [u8; 12]) -> Result<Entry> {
        let entry = Entry {
            version: ENTRY_VERSION,
            yubihsm_uuid: self.device_uuid,
            key_id: self.hmac_key_id,
            nonce,
            ciphertext: Vec::new(), // filled below
        };

        let k_enc = self.derive_key(&entry)?;
        let cipher =
            Aes256Gcm::new_from_slice(k_enc.as_ref()).map_err(|_| KeyRingError::GeneralError {
                msg: "invalid key length for AES-256-GCM".to_string(),
            })?;

        let aad = Self::build_aad(&entry);
        let gcm_nonce = aes_gcm::Nonce::from_slice(&entry.nonce);
        let ciphertext = cipher
            .encrypt(
                gcm_nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyRingError::GeneralError {
                msg: "AES-256-GCM encryption failed".to_string(),
            })?;

        Ok(Entry {
            ciphertext,
            ..entry
        })
    }

    fn decrypt_entry(&self, entry: &Entry) -> Result<Vec<u8>> {
        let k_enc = self.derive_key(entry)?;
        let cipher =
            Aes256Gcm::new_from_slice(k_enc.as_ref()).map_err(|_| KeyRingError::GeneralError {
                msg: "invalid key length for AES-256-GCM".to_string(),
            })?;

        let aad = Self::build_aad(entry);
        let gcm_nonce = aes_gcm::Nonce::from_slice(&entry.nonce);
        cipher
            .decrypt(
                gcm_nonce,
                Payload {
                    msg: &entry.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyRingError::GeneralError {
                msg: "AES-256-GCM decryption failed (wrong device, key, or corrupted data)"
                    .to_string(),
            })
    }
}

// ─── Entry serialization ─────────────────────────────────────────────────────

impl Entry {
    /// Serialize to bytes: `version(1) || uuid(16) || key_id_LE(2) || nonce(12) || ct_len_LE(4) || ct`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u32;
        let mut buf = Vec::with_capacity(1 + 16 + 2 + 12 + 4 + self.ciphertext.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.yubihsm_uuid);
        buf.extend_from_slice(&self.key_id.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&ct_len.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from bytes produced by [`Entry::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        const HEADER: usize = 1 + 16 + 2 + 12 + 4; // = 35
        if b.len() < HEADER {
            return Err(corrupt());
        }
        let version = b[0];
        let mut yubihsm_uuid = [0u8; 16];
        yubihsm_uuid.copy_from_slice(&b[1..17]);
        let key_id = u16::from_le_bytes([b[17], b[18]]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[19..31]);
        let ct_len = u32::from_le_bytes([b[31], b[32], b[33], b[34]]) as usize;
        if b.len() < HEADER + ct_len {
            return Err(corrupt());
        }
        let ciphertext = b[HEADER..HEADER + ct_len].to_vec();
        Ok(Entry {
            version,
            yubihsm_uuid,
            key_id,
            nonce,
            ciphertext,
        })
    }
}

// ─── File helpers ─────────────────────────────────────────────────────────────

/// Filename for a given secret ID: `hex(sha256(id_bytes)).bin`.
fn entry_filename(id: &str) -> String {
    let hash = Sha256::digest(id.as_bytes());
    format!("{}.bin", hex::encode(hash))
}

/// Write `[u16_LE id_len][id][entry_bytes]` atomically via a temp file.
fn write_entry_file(path: &Path, id: &str, entry: &Entry) -> Result<()> {
    let id_bytes = id.as_bytes();
    let id_len = id_bytes.len() as u16;

    let mut data = Vec::new();
    data.extend_from_slice(&id_len.to_le_bytes());
    data.extend_from_slice(id_bytes);
    data.extend_from_slice(&entry.to_bytes());

    // Write to a temp file alongside the target, then rename (atomic on most OSes).
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &data).map_err(io_err)?;
    fs::rename(&tmp, path).map_err(io_err)
}

/// Read a file written by [`write_entry_file`], returning `(id, Entry)`.
fn read_entry_file(path: &Path) -> Result<(String, Entry)> {
    let data = fs::read(path).map_err(io_err)?;
    if data.len() < 2 {
        return Err(corrupt());
    }
    let id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let header = 2 + id_len;
    if data.len() < header {
        return Err(corrupt());
    }
    let id = String::from_utf8(data[2..header].to_vec()).map_err(|_| corrupt())?;
    let entry = Entry::from_bytes(&data[header..])?;
    Ok((id, entry))
}

fn corrupt() -> KeyRingError {
    KeyRingError::GeneralError {
        msg: "corrupted YubiHSM entry file".to_string(),
    }
}

fn io_err(e: io::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

fn hsm_err(e: ::yubihsm::client::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

fn hsm_label_err(e: ::yubihsm::object::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

// ─── Connection Parameters ────────────────────────────────────────────────────

/// Connection parameters for [`YubiHsmKeyRing`].
///
/// Parse from a connection string:
///
/// ```text
/// connector=usb hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp
/// connector=http addr=127.0.0.1 port=12345 hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp
/// ```
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ConnectionParams {
    /// `"usb"` or `"http"`.
    pub connector: String,
    /// Object ID of the HMAC-SHA256 key on the YubiHSM (default: `1`).
    pub hmac_key_id: u16,
    /// Auth key object ID (default: `1`).
    pub auth_key_id: u16,
    /// Auth key password (default: `"password"` — factory default).
    pub password: String,
    /// HSM domain, 1–16 (default: `1`).
    pub domain: u8,
    /// Service / application name used to namespace entry files (default: `"default"`).
    pub service: String,
    /// HTTP connector address (default: `"127.0.0.1"`).
    pub addr: String,
    /// HTTP connector port (default: `12345`).
    pub port: u16,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        Self {
            #[cfg(feature = "yubihsm-usb")]
            connector: "usb".to_string(),
            #[cfg(all(not(feature = "yubihsm-usb"), feature = "yubihsm-http"))]
            connector: "http".to_string(),
            hmac_key_id: 1,
            auth_key_id: 1,
            password: "password".to_string(),
            domain: 1,
            service: "default".to_string(),
            addr: "127.0.0.1".to_string(),
            port: 12345,
        }
    }
}

impl ConnectionParams {
    /// Open a [`YubiHsmKeyRing`] using these parameters.
    pub fn open(self) -> Result<YubiHsmKeyRing> {
        let domain = domain_from_num(self.domain)?;
        let credentials = ::yubihsm::authentication::Credentials::from_password(
            self.auth_key_id,
            self.password.as_bytes(),
        );

        let client = match self.connector.as_str() {
            #[cfg(feature = "yubihsm-usb")]
            "usb" => {
                let connector = ::yubihsm::connector::Connector::usb(
                    &::yubihsm::connector::UsbConfig::default(),
                );
                ::yubihsm::Client::open(connector, credentials, true)
                    .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?
            }
            #[cfg(feature = "yubihsm-http")]
            "http" => {
                let config = ::yubihsm::connector::HttpConfig {
                    addr: self.addr.clone(),
                    port: self.port,
                    timeout_ms: 5_000,
                };
                let connector = ::yubihsm::connector::Connector::http(&config);
                ::yubihsm::Client::open(connector, credentials, true)
                    .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?
            }
            other => {
                return Err(KeyRingError::GeneralError {
                    msg: format!(
                        "Unknown connector '{}'. Enable 'yubihsm-usb' or 'yubihsm-http' feature.",
                        other
                    ),
                });
            }
        };

        // Derive a stable 16-byte device UUID from the HSM serial number.
        // serial_number implements Display as a 10-digit decimal string.
        let info = client.device_info().map_err(hsm_err)?;
        let serial_str = info.serial_number.to_string();
        let hash = Sha256::digest(serial_str.as_bytes());
        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&hash[..16]);

        // Prepare storage directory.
        let storage_dir = entry_dir(&self.service)?;

        Ok(YubiHsmKeyRing {
            client,
            domain,
            hmac_key_id: self.hmac_key_id,
            device_uuid,
            storage_dir,
        })
    }

    fn set_param(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "connector" => self.connector = value.to_string(),
            "hmac_key_id" => {
                self.hmac_key_id = value.parse().map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid hmac_key_id: {}", e),
                })?
            }
            "auth_key_id" => {
                self.auth_key_id = value.parse().map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid auth_key_id: {}", e),
                })?
            }
            "password" => self.password = value.to_string(),
            "domain" => {
                self.domain = value.parse().map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid domain: {}", e),
                })?
            }
            "service" => self.service = value.to_string(),
            "addr" => self.addr = value.to_string(),
            "port" => {
                self.port = value.parse().map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid port: {}", e),
                })?
            }
            _ => {
                return Err(KeyRingError::GeneralError {
                    msg: format!("unknown parameter: '{}'", key),
                });
            }
        }
        Ok(())
    }
}

impl FromStr for ConnectionParams {
    type Err = KeyRingError;

    fn from_str(s: &str) -> Result<Self> {
        let mut params = Self::default();
        let mut rest = s;

        loop {
            rest = rest.trim_start();
            if rest.is_empty() {
                break;
            }
            let eq = rest.find('=').ok_or_else(|| KeyRingError::GeneralError {
                msg: format!("expected 'key=value', got: '{}'", rest),
            })?;
            let key = rest[..eq].trim_end();
            rest = &rest[eq + 1..];

            let (value, remaining) = if rest.starts_with('\'') {
                let close = rest[1..]
                    .find('\'')
                    .ok_or_else(|| KeyRingError::GeneralError {
                        msg: "unterminated quoted value".to_string(),
                    })?;
                (&rest[1..close + 1], &rest[close + 2..])
            } else {
                match rest.find(char::is_whitespace) {
                    Some(ws) => (&rest[..ws], &rest[ws..]),
                    None => (rest, ""),
                }
            };

            params.set_param(key, value)?;
            rest = remaining;
        }

        Ok(params)
    }
}

// ─── Storage path helpers ─────────────────────────────────────────────────────

fn entry_dir(service: &str) -> Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| KeyRingError::GeneralError {
        msg: "could not determine home directory".to_string(),
    })?;
    let dir = base
        .join(".cryptex")
        .join("yubihsm")
        .join(sanitize_name(service));
    fs::create_dir_all(&dir).map_err(io_err)?;
    Ok(dir)
}

/// Replace filesystem-unsafe characters with `_`.
fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

fn domain_from_num(n: u8) -> Result<::yubihsm::Domain> {
    if n == 0 || n > 16 {
        return Err(KeyRingError::GeneralError {
            msg: format!("domain must be 1–16, got {}", n),
        });
    }
    ::yubihsm::Domain::from_bits(1u16 << (n - 1)).ok_or_else(|| KeyRingError::GeneralError {
        msg: format!("invalid domain number: {}", n),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Explicit imports to avoid ambiguity between KeyRing and DynKeyRing
    // (both are in scope via `use super::*` since the parent imports them).
    use super::{Entry, YubiHsmKeyRing};
    use crate::keyring::{DynKeyRing, NewKeyRing};
    use std::{collections::HashSet, fs};

    /// USB connection string using factory-default credentials.
    /// Adjust `auth_key_id`, `password`, and `domain` if your device differs.
    const TEST_CONN: &str = "connector=http addr=127.0.0.1 port=12345 hmac_key_id=100 auth_key_id=1 password=password domain=1 service=cryptex-test";

    /// Object ID reserved for the test HMAC key.
    const TEST_HMAC_KEY_ID: u16 = 100;

    /// Ensure a clean slate before each test:
    /// 1. Delete the test HMAC key from the device (ignore "not found").
    /// 2. Remove leftover `.bin` files from previous runs.
    /// 3. Generate a fresh HMAC key at `TEST_HMAC_KEY_ID`.
    /// 4. Return a connected `YubiHsmKeyRing` ready for use.
    fn ensure_test_key() -> YubiHsmKeyRing {
        // Single session for the entire setup — avoids exhausting the 16-session limit.
        let ring = YubiHsmKeyRing::new(TEST_CONN)
            .expect("connect to YubiHSM — is the device plugged in and yubihsm-connector running?");

        // Best-effort delete; ignore error if key doesn't exist yet.
        let _ = ring
            .client
            .delete_object(TEST_HMAC_KEY_ID, ::yubihsm::object::Type::HmacKey);

        // Wipe leftover .bin files from previous test runs.
        if ring.storage_dir.exists() {
            for e in fs::read_dir(&ring.storage_dir)
                .expect("read test storage dir")
                .flatten()
            {
                if e.path().extension().and_then(|s| s.to_str()) == Some("bin") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }

        // Create a fresh HMAC key reusing the same session.
        let label = ::yubihsm::object::Label::from_bytes(b"cryptex-hmac")
            .map_err(super::hsm_label_err)
            .expect("create HMAC key label");
        ring.client
            .generate_hmac_key(
                TEST_HMAC_KEY_ID,
                label,
                ring.domain,
                ::yubihsm::Capability::SIGN_HMAC,
                ::yubihsm::hmac::Algorithm::Sha256,
            )
            .map_err(super::hsm_err)
            .expect("generate test HMAC key on YubiHSM");

        ring
    }

    // ── Serialization (no hardware required) ──────────────────────────────────

    #[test]
    fn test_entry_round_trip() {
        let entry = Entry {
            version: 1,
            yubihsm_uuid: [0xABu8; 16],
            key_id: 0x0064,
            nonce: [0xCDu8; 12],
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let bytes = entry.to_bytes();
        let decoded = Entry::from_bytes(&bytes).expect("decode entry");
        assert_eq!(decoded.version, entry.version);
        assert_eq!(decoded.yubihsm_uuid, entry.yubihsm_uuid);
        assert_eq!(decoded.key_id, entry.key_id);
        assert_eq!(decoded.nonce, entry.nonce);
        assert_eq!(decoded.ciphertext, entry.ciphertext);
    }

    #[test]
    fn test_entry_rejects_short_input() {
        assert!(Entry::from_bytes(&[0u8; 10]).is_err());
        assert!(Entry::from_bytes(&[]).is_err());
    }

    // ── Hardware integration tests (require a plugged-in YubiHSM 2) ───────────

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_lifecycle_set_get_delete() {
        let mut ring = ensure_test_key();

        ring.set_secret("my-secret", b"hello world")
            .expect("set_secret");
        let got = ring.get_secret("my-secret").expect("get_secret");
        assert_eq!(got.as_slice(), b"hello world");

        ring.delete_secret("my-secret").expect("delete_secret");
        let err = ring
            .get_secret("my-secret")
            .expect_err("expected ItemNotFound after delete");
        assert!(
            matches!(err, crate::error::KeyRingError::ItemNotFound),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_overwrite() {
        let mut ring = ensure_test_key();

        ring.set_secret("k", b"first").expect("set first value");
        ring.set_secret("k", b"second").expect("overwrite value");
        let got = ring.get_secret("k").expect("get after overwrite");
        assert_eq!(got.as_slice(), b"second");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_get_nonexistent() {
        let mut ring = ensure_test_key();
        let err = ring
            .get_secret("does-not-exist")
            .expect_err("expected ItemNotFound for unknown id");
        assert!(
            matches!(err, crate::error::KeyRingError::ItemNotFound),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_delete_nonexistent() {
        let mut ring = ensure_test_key();
        let err = ring
            .delete_secret("does-not-exist")
            .expect_err("expected ItemNotFound for unknown id");
        assert!(
            matches!(err, crate::error::KeyRingError::ItemNotFound),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_multiple_secrets() {
        let mut ring = ensure_test_key();

        let pairs: &[(&str, &[u8])] = &[
            ("alpha", b"secret-alpha"),
            ("beta", b"secret-beta"),
            ("gamma", b"secret-gamma"),
        ];

        for (id, secret) in pairs {
            ring.set_secret(id, secret).expect("set");
        }
        for (id, expected) in pairs {
            let got = ring.get_secret(id).expect("get");
            assert_eq!(got.as_slice(), *expected, "mismatch for '{}'", id);
        }
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_binary_secret() {
        let mut ring = ensure_test_key();

        let binary: Vec<u8> = (0u8..=255).collect();
        ring.set_secret("bin-secret", &binary)
            .expect("set binary secret");
        let got = ring.get_secret("bin-secret").expect("get binary secret");
        assert_eq!(got.as_slice(), binary.as_slice());
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_empty_secret() {
        let mut ring = ensure_test_key();

        ring.set_secret("empty", b"").expect("set empty secret");
        let got = ring.get_secret("empty").expect("get empty secret");
        assert_eq!(got.as_slice(), b"");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_list_hsm_secrets() {
        let mut ring = ensure_test_key();

        ring.set_secret("x", b"val-x").expect("set x");
        ring.set_secret("y", b"val-y").expect("set y");

        let list = ring.list_hsm_secrets().expect("list secrets");
        let ids: Vec<&str> = list
            .iter()
            .filter_map(|m| m.get("id").map(|s| s.as_str()))
            .collect();
        assert!(ids.contains(&"x"), "x missing from list: {:?}", ids);
        assert!(ids.contains(&"y"), "y missing from list: {:?}", ids);
    }

    #[test]
    #[ignore = "requires YubiHSM hardware (USB)"]
    fn test_nonces_are_unique() {
        let ring = ensure_test_key();

        let mut seen: HashSet<[u8; 12]> = HashSet::new();
        for _ in 0..10 {
            let n = ring.generate_nonce().expect("generate_nonce");
            assert!(seen.insert(n), "duplicate nonce generated");
        }
    }
}
