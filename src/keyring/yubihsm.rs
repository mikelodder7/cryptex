/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

//! YubiHSM 2 backed keyring — a thin [`KmsBackend`] implementation on top of
//! the shared [`kms`] layer.
//!
//! # Design
//!
//! One HMAC-SHA256 key lives on the YubiHSM 2.  All crypto and file-storage
//! logic lives in [`crate::keyring::kms`]; this module only handles device
//! connection, the HMAC oracle, and one-time setup.
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

use super::kms::{KmsBackend, KmsKeyRing};
use super::*;
use crate::error::KeyRingError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;
use zeroize::Zeroize;

// ─── YubiHsmBackend ──────────────────────────────────────────────────────────

/// [`KmsBackend`] implementation backed by a YubiHSM 2.
pub struct YubiHsmBackend {
    pub(crate) client: ::yubihsm::Client,
    pub(crate) domain: ::yubihsm::Domain,
    /// Object ID of the HMAC-SHA256 key on the YubiHSM.
    pub(crate) hmac_key_id: u16,
    /// `SHA-256(serial_str)[..16]` — stable device identity.
    device_id_bytes: [u8; 16],
    /// Decimal string of `hmac_key_id` (e.g. `"2"`).
    key_id_str: String,
}

impl KmsBackend for YubiHsmBackend {
    fn backend_name(&self) -> &'static str {
        "yubihsm"
    }

    fn key_id(&self) -> &str {
        &self.key_id_str
    }

    fn device_id(&self) -> [u8; 16] {
        self.device_id_bytes
    }

    fn get_random(&self, n: usize) -> Result<Vec<u8>> {
        self.client.get_pseudo_random(n).map_err(hsm_err)
    }

    fn hmac_sha256(&self, msg: Vec<u8>) -> Result<[u8; 32]> {
        let tag = self
            .client
            .sign_hmac(self.hmac_key_id, msg)
            .map_err(hsm_err)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }
}

// ─── Type alias ──────────────────────────────────────────────────────────────

/// YubiHSM 2 keyring: one HMAC key on-device, unlimited AES-256-GCM encrypted
/// secrets stored as local files under `~/.cryptex/yubihsm/<service>/`.
pub type YubiHsmKeyRing = KmsKeyRing<YubiHsmBackend>;

// ─── YubiHSM-specific impls ──────────────────────────────────────────────────

impl KmsKeyRing<YubiHsmBackend> {
    /// One-time setup: generate an HMAC-SHA256 key at `hmac_key_id` on the device.
    ///
    /// The auth key used must have `GENERATE_HMAC_KEY` and `SIGN_HMAC` capabilities.
    /// Call this once; subsequent calls with the same ID will fail (object already exists).
    pub fn setup(connection_string: &str, hmac_key_id: u16) -> Result<()> {
        let params: ConnectionParams = connection_string.parse()?;
        let ring = params.open()?;
        let label = ::yubihsm::object::Label::from_bytes(b"cryptex-hmac").map_err(hsm_label_err)?;
        ring.backend
            .client
            .generate_hmac_key(
                hmac_key_id,
                label,
                ring.backend.domain,
                ::yubihsm::Capability::SIGN_HMAC,
                ::yubihsm::hmac::Algorithm::Sha256,
            )
            .map_err(hsm_err)?;
        Ok(())
    }

    /// List all secrets stored for this keyring instance's service.
    pub fn list_hsm_secrets(&self) -> Result<Vec<BTreeMap<String, String>>> {
        self.list_secrets()
    }
}

// ─── NewKeyRing ──────────────────────────────────────────────────────────────

impl NewKeyRing for KmsKeyRing<YubiHsmBackend> {
    fn new<S: AsRef<str>>(connection_string: S) -> Result<Self> {
        connection_string
            .as_ref()
            .parse::<ConnectionParams>()?
            .open()
    }
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

        // Derive stable identifiers from the device serial number.
        let info = client.device_info().map_err(hsm_err)?;
        let serial_str = info.serial_number.to_string();

        // device_id: SHA-256(serial_str)[..16] — binds entries to this physical device.
        let device_hash = Sha256::digest(serial_str.as_bytes());
        let mut device_id_bytes = [0u8; 16];
        device_id_bytes.copy_from_slice(&device_hash[..16]);

        // key_id: decimal string of the HMAC key object ID.
        // The device is already captured in device_id; no need to encode the serial here.
        let key_id_str = self.hmac_key_id.to_string();

        let backend = YubiHsmBackend {
            client,
            domain,
            hmac_key_id: self.hmac_key_id,
            device_id_bytes,
            key_id_str,
        };

        KmsKeyRing::open(backend, &self.service)
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

            let (value, remaining) = if let Some(after_open) = rest.strip_prefix('\'') {
                let close = after_open
                    .find('\'')
                    .ok_or_else(|| KeyRingError::GeneralError {
                        msg: "unterminated quoted value".to_string(),
                    })?;
                (&after_open[..close], &after_open[close + 1..])
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

pub(crate) fn hsm_err(e: ::yubihsm::client::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

pub(crate) fn hsm_label_err(e: ::yubihsm::object::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::YubiHsmKeyRing;
    use crate::keyring::{DynKeyRing, NewKeyRing};
    use std::{collections::HashSet, fs};

    /// HTTP connection string using factory-default credentials.
    const TEST_CONN: &str = "connector=http addr=127.0.0.1 port=12345 hmac_key_id=100 auth_key_id=1 password=password domain=1 service=cryptex-test";

    /// Object ID reserved for the test HMAC key.
    const TEST_HMAC_KEY_ID: u16 = 100;

    /// Ensure a clean slate before each test.
    fn ensure_test_key() -> YubiHsmKeyRing {
        let ring = YubiHsmKeyRing::new(TEST_CONN)
            .expect("connect to YubiHSM — is the device plugged in and yubihsm-connector running?");

        let _ = ring
            .backend
            .client
            .delete_object(TEST_HMAC_KEY_ID, ::yubihsm::object::Type::HmacKey);

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

        let label = ::yubihsm::object::Label::from_bytes(b"cryptex-hmac")
            .map_err(super::hsm_label_err)
            .expect("create HMAC key label");
        ring.backend
            .client
            .generate_hmac_key(
                TEST_HMAC_KEY_ID,
                label,
                ring.backend.domain,
                ::yubihsm::Capability::SIGN_HMAC,
                ::yubihsm::hmac::Algorithm::Sha256,
            )
            .map_err(super::hsm_err)
            .expect("generate test HMAC key on YubiHSM");

        ring
    }

    // ── Serialization (no hardware required) ──────────────────────────────────

    // Serialization tests delegate to the kms module — no need to duplicate them here.

    // ── Hardware integration tests (require a plugged-in YubiHSM 2) ───────────

    #[test]
    #[ignore = "requires YubiHSM hardware"]
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
    #[ignore = "requires YubiHSM hardware"]
    fn test_overwrite() {
        let mut ring = ensure_test_key();
        ring.set_secret("k", b"first").expect("set first value");
        ring.set_secret("k", b"second").expect("overwrite value");
        let got = ring.get_secret("k").expect("get after overwrite");
        assert_eq!(got.as_slice(), b"second");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware"]
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
    #[ignore = "requires YubiHSM hardware"]
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
    #[ignore = "requires YubiHSM hardware"]
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
    #[ignore = "requires YubiHSM hardware"]
    fn test_binary_secret() {
        let mut ring = ensure_test_key();
        let binary: Vec<u8> = (0u8..=255).collect();
        ring.set_secret("bin-secret", &binary)
            .expect("set binary secret");
        let got = ring.get_secret("bin-secret").expect("get binary secret");
        assert_eq!(got.as_slice(), binary.as_slice());
    }

    #[test]
    #[ignore = "requires YubiHSM hardware"]
    fn test_empty_secret() {
        let mut ring = ensure_test_key();
        ring.set_secret("empty", b"").expect("set empty secret");
        let got = ring.get_secret("empty").expect("get empty secret");
        assert_eq!(got.as_slice(), b"");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware"]
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
    #[ignore = "requires YubiHSM hardware"]
    fn test_rekey_secret() {
        let mut ring = ensure_test_key();

        ring.set_secret("rekey-me", b"original value")
            .expect("set_secret");

        // Record the nonce before rekey
        let path = ring.entry_path("rekey-me");
        let (_, old_entry) =
            crate::keyring::kms::read_entry_file(&path).expect("read entry before rekey");
        let old_nonce = old_entry.nonce;

        // Rekey
        ring.rekey_secret("rekey-me").expect("rekey_secret");

        // Value should be unchanged
        let got = ring.get_secret("rekey-me").expect("get after rekey");
        assert_eq!(got.as_slice(), b"original value");

        // Nonce should have changed
        let (_, new_entry) =
            crate::keyring::kms::read_entry_file(&path).expect("read entry after rekey");
        assert_ne!(old_nonce, new_entry.nonce, "nonce must change after rekey");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware"]
    fn test_rekey_all() {
        let mut ring = ensure_test_key();

        ring.set_secret("ra", b"val-ra").expect("set ra");
        ring.set_secret("rb", b"val-rb").expect("set rb");

        ring.rekey_all().expect("rekey_all");

        assert_eq!(ring.get_secret("ra").expect("get ra").as_slice(), b"val-ra");
        assert_eq!(ring.get_secret("rb").expect("get rb").as_slice(), b"val-rb");
    }

    #[test]
    #[ignore = "requires YubiHSM hardware"]
    fn test_nonces_are_unique() {
        let ring = ensure_test_key();

        let mut seen: HashSet<[u8; 12]> = HashSet::new();
        for _ in 0..10 {
            let n = ring.generate_nonce().expect("generate_nonce");
            assert!(seen.insert(n), "duplicate nonce generated");
        }
    }
}
