/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

//! Generic KMS/HSM-backed keyring: one signing key in an external KMS, unlimited
//! AES-256-GCM secrets stored as local files under `~/.cryptex/<backend>/<service>/`.
//!
//! # Protocol
//!
//! For each secret:
//!
//! 1. **Nonce** (12 bytes):
//!    `SHA-256("cryptex-nonce" ‖ OS_rng₃₂ [‖ backend_rng₃₂])[..12]`
//!
//! 2. **K_enc** (32 bytes):
//!    `HMAC-SHA256(master_key, "cryptex-keyring" ‖ version ‖ key_id_bytes ‖ device_id(16) ‖ nonce)`
//!    — computed by the backend (on-device, in KMS, etc.)
//!
//! 3. **Ciphertext**: `AES-256-GCM(K_enc, nonce, plaintext, AAD)`
//!    where `AAD = version(1) ‖ key_id_bytes ‖ device_id(16) ‖ nonce(12)` (variable length)
//!
//! Each secret is a binary file under `~/.cryptex/<backend_name>/<service>/`.

use super::*;
use crate::error::KeyRingError;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};
use zeroize::Zeroizing;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Domain-separation tag in the HMAC input.
const CONTEXT: &[u8] = b"cryptex-keyring";

/// Domain-separation tag when mixing OS + backend randomness for the nonce.
const NONCE_DST: &[u8] = b"cryptex-nonce";

/// On-disk entry format version.
const ENTRY_VERSION: u8 = 1;

// ─── KmsBackend trait ────────────────────────────────────────────────────────

/// Abstraction over any external key-management system (YubiHSM, AWS KMS, etc.)
/// that can provide entropy and compute HMAC-SHA256 without exposing the raw key.
pub trait KmsBackend: Send + Sync {
    /// Short, filesystem-safe name for this backend (e.g. `"yubihsm"`, `"aws-kms"`).
    /// Used as a directory component under `~/.cryptex/<backend_name>/<service>/`.
    fn backend_name(&self) -> &'static str;

    /// The key identifier for the signing key in use (e.g. a YubiHSM object ID like `"2"`,
    /// an AWS KMS key ARN, or a UUID).  The raw UTF-8 bytes are bound into the HMAC input
    /// and AAD of every entry, so entries are tied to a specific key.
    fn key_id(&self) -> &str;

    /// A stable 16-byte identifier for the device / backend instance itself
    /// (e.g. derived from HSM serial number).  Bound into the HMAC input and AAD
    /// to tie entries to a specific physical device, independently of the key ID.
    fn device_id(&self) -> [u8; 16];

    /// Optional backend entropy.  Return `Ok(Vec::new())` if unavailable.
    fn get_random(&self, n: usize) -> Result<Vec<u8>>;

    /// Compute HMAC-SHA256 using the backend's secret key.
    fn hmac_sha256(&self, msg: Vec<u8>) -> Result<[u8; 32]>;
}

// ─── Entry ───────────────────────────────────────────────────────────────────

/// On-disk representation of an encrypted secret.
///
/// Serialization:
/// `version(1) || key_id_len_LE(2) || key_id(key_id_len) || device_id(16) || nonce(12) || ct_len_LE(4) || ct`
#[derive(Clone)]
pub struct Entry {
    pub version: u8,
    /// Backend key identifier (e.g. `"2"`, a UUID, or a KMS ARN).
    pub key_id: String,
    /// 16-byte device/instance identifier from [`KmsBackend::device_id`].
    pub device_id: [u8; 16],
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext (includes 16-byte authentication tag).
    pub ciphertext: Vec<u8>,
}

impl Entry {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let key_id_bytes = self.key_id.as_bytes();
        let key_id_len = key_id_bytes.len() as u16;
        let ct_len = self.ciphertext.len() as u32;
        let mut buf =
            Vec::with_capacity(1 + 2 + key_id_bytes.len() + 16 + 12 + 4 + self.ciphertext.len());
        buf.push(self.version);
        buf.extend_from_slice(&key_id_len.to_le_bytes());
        buf.extend_from_slice(key_id_bytes);
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&ct_len.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from bytes produced by [`Entry::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        // Minimum: version(1) + key_id_len(2) + device_id(16) + nonce(12) + ct_len(4) = 35
        if b.len() < 3 {
            return Err(corrupt());
        }
        let version = b[0];
        let key_id_len = u16::from_le_bytes([b[1], b[2]]) as usize;
        let key_id_end = 3 + key_id_len;
        // After key_id: device_id(16) + nonce(12) + ct_len(4) = 32
        if b.len() < key_id_end + 32 {
            return Err(corrupt());
        }
        let key_id = String::from_utf8(b[3..key_id_end].to_vec()).map_err(|_| corrupt())?;
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&b[key_id_end..key_id_end + 16]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[key_id_end + 16..key_id_end + 28]);
        let ct_len_off = key_id_end + 28;
        let ct_len = u32::from_le_bytes([
            b[ct_len_off],
            b[ct_len_off + 1],
            b[ct_len_off + 2],
            b[ct_len_off + 3],
        ]) as usize;
        let ct_start = ct_len_off + 4;
        if b.len() < ct_start + ct_len {
            return Err(corrupt());
        }
        let ciphertext = b[ct_start..ct_start + ct_len].to_vec();
        Ok(Entry {
            version,
            key_id,
            device_id,
            nonce,
            ciphertext,
        })
    }
}

// ─── KmsKeyRing ──────────────────────────────────────────────────────────────

/// Generic KMS-backed keyring.  `B` provides the HMAC oracle and entropy;
/// this struct owns the local file storage.
pub struct KmsKeyRing<B: KmsBackend> {
    pub(crate) backend: B,
    pub(crate) storage_dir: PathBuf,
}

impl<B: KmsBackend> KmsKeyRing<B> {
    /// Open (or create) a keyring for the given service.
    /// Storage directory: `~/.cryptex/<backend_name>/<service>/`.
    pub fn open(backend: B, service: &str) -> Result<Self> {
        let storage_dir = entry_dir(backend.backend_name(), service)?;
        Ok(Self {
            backend,
            storage_dir,
        })
    }

    /// List all secrets stored for this keyring's service directory.
    pub fn list_secrets(&self) -> Result<Vec<BTreeMap<String, String>>> {
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
                map.insert("key_id".to_string(), e.key_id);
                map.insert("device_id".to_string(), hex::encode(e.device_id));
                results.push(map);
            }
        }
        Ok(results)
    }

    // ── Rekey ─────────────────────────────────────────────────────────────────

    /// Re-encrypt a single secret with a freshly generated nonce.
    ///
    /// This decrypts the entry using the old nonce-derived key, generates a new
    /// nonce, derives a new key from it, re-encrypts, and writes the entry back
    /// atomically.
    pub fn rekey_secret(&mut self, id: &str) -> Result<()> {
        let path = self.entry_path(id);
        let (stored_id, old_entry) =
            read_entry_file(&path).map_err(|_| KeyRingError::ItemNotFound)?;
        let plaintext = Zeroizing::new(self.decrypt_entry(&old_entry)?);
        let new_nonce = self.generate_nonce()?;
        let new_entry = self.encrypt_entry(&plaintext, new_nonce)?;
        write_entry_file(&path, &stored_id, &new_entry)
    }

    /// Re-encrypt every secret in this keyring's service directory with fresh nonces.
    ///
    /// Iterates all `.bin` entry files and re-encrypts each one in place.
    /// Returns the first error encountered (entries already rekeyed
    /// before the failure remain rekeyed).
    pub fn rekey_all(&mut self) -> Result<()> {
        let entries = fs::read_dir(&self.storage_dir).map_err(io_err)?;
        for dir_entry in entries.flatten() {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let (stored_id, old_entry) = read_entry_file(&path)?;
            let plaintext = Zeroizing::new(self.decrypt_entry(&old_entry)?);
            let new_nonce = self.generate_nonce()?;
            let new_entry = self.encrypt_entry(&plaintext, new_nonce)?;
            write_entry_file(&path, &stored_id, &new_entry)?;
        }
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    pub(crate) fn entry_path(&self, id: &str) -> PathBuf {
        self.storage_dir.join(entry_filename(id))
    }

    /// Generate a 12-byte nonce from OS RNG mixed with optional backend entropy.
    pub(crate) fn generate_nonce(&self) -> Result<[u8; 12]> {
        let mut os_rand = Zeroizing::new([0u8; 32]);
        getrandom::fill(os_rand.as_mut()).map_err(|e| KeyRingError::GeneralError {
            msg: format!("OS RNG failed: {e}"),
        })?;

        let backend_rand = self.backend.get_random(32)?;

        let mut hasher = Sha256::new();
        hasher.update(NONCE_DST);
        hasher.update(os_rand.as_ref());
        if !backend_rand.is_empty() {
            hasher.update(&backend_rand);
        }
        let digest = hasher.finalize();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        Ok(nonce)
    }

    /// Derive K_enc:
    /// `HMAC-SHA256(master_key, "cryptex-keyring" || version || key_id_bytes || device_id(16) || nonce)`
    /// computed by the backend.
    fn derive_key(&self, entry: &Entry) -> Result<Zeroizing<[u8; 32]>> {
        let key_id_bytes = entry.key_id.as_bytes();
        let mut hmac_input = Vec::with_capacity(CONTEXT.len() + 1 + key_id_bytes.len() + 16 + 12);
        hmac_input.extend_from_slice(CONTEXT);
        hmac_input.push(entry.version);
        hmac_input.extend_from_slice(key_id_bytes);
        hmac_input.extend_from_slice(&entry.device_id);
        hmac_input.extend_from_slice(&entry.nonce);

        let raw = self.backend.hmac_sha256(hmac_input)?;
        let mut k_enc = Zeroizing::new([0u8; 32]);
        *k_enc = raw;
        Ok(k_enc)
    }

    /// Build the AAD: `version(1) || key_id_bytes || device_id(16) || nonce(12)`.
    fn build_aad(entry: &Entry) -> Vec<u8> {
        let key_id_bytes = entry.key_id.as_bytes();
        let mut aad = Vec::with_capacity(1 + key_id_bytes.len() + 16 + 12);
        aad.push(entry.version);
        aad.extend_from_slice(key_id_bytes);
        aad.extend_from_slice(&entry.device_id);
        aad.extend_from_slice(&entry.nonce);
        aad
    }

    fn encrypt_entry(&self, plaintext: &[u8], nonce: [u8; 12]) -> Result<Entry> {
        let entry = Entry {
            version: ENTRY_VERSION,
            key_id: self.backend.key_id().to_string(),
            device_id: self.backend.device_id(),
            nonce,
            ciphertext: Vec::new(),
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
                msg: "AES-256-GCM decryption failed (wrong key or corrupted data)".to_string(),
            })
    }
}

// ─── DynKeyRing impl ─────────────────────────────────────────────────────────

impl<B: KmsBackend> DynKeyRing for KmsKeyRing<B> {
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

// ─── File helpers ─────────────────────────────────────────────────────────────

/// Filename for a given secret ID: `hex(sha256(id_bytes)).bin`.
pub(crate) fn entry_filename(id: &str) -> String {
    let hash = Sha256::digest(id.as_bytes());
    format!("{}.bin", hex::encode(hash))
}

/// Write `[u16_LE id_len][id][entry_bytes]` atomically via a temp file.
pub(crate) fn write_entry_file(path: &Path, id: &str, entry: &Entry) -> Result<()> {
    let id_bytes = id.as_bytes();
    let id_len = id_bytes.len() as u16;

    let mut data = Vec::new();
    data.extend_from_slice(&id_len.to_le_bytes());
    data.extend_from_slice(id_bytes);
    data.extend_from_slice(&entry.to_bytes());

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &data).map_err(io_err)?;
    fs::rename(&tmp, path).map_err(io_err)
}

/// Read a file written by [`write_entry_file`], returning `(id, Entry)`.
pub(crate) fn read_entry_file(path: &Path) -> Result<(String, Entry)> {
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

/// Storage directory for a given backend + service.
pub(crate) fn entry_dir(backend_name: &str, service: &str) -> Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| KeyRingError::GeneralError {
        msg: "could not determine home directory".to_string(),
    })?;
    let dir = base
        .join(".cryptex")
        .join(backend_name)
        .join(sanitize_name(service));
    fs::create_dir_all(&dir).map_err(io_err)?;
    Ok(dir)
}

/// Replace filesystem-unsafe characters with `_`.
pub(crate) fn sanitize_name(s: &str) -> String {
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

pub(crate) fn corrupt() -> KeyRingError {
    KeyRingError::GeneralError {
        msg: "corrupted KMS entry file".to_string(),
    }
}

pub(crate) fn io_err(e: io::Error) -> KeyRingError {
    KeyRingError::GeneralError { msg: e.to_string() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_round_trip() {
        let entry = Entry {
            version: 1,
            key_id: "mrk-1234abcd-12ab-34cd-56ef-1234567890ab".to_string(),
            device_id: [0xEFu8; 16],
            nonce: [0xCDu8; 12],
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let bytes = entry.to_bytes();
        let decoded = Entry::from_bytes(&bytes).expect("decode entry");
        assert_eq!(decoded.version, entry.version);
        assert_eq!(decoded.key_id, entry.key_id);
        assert_eq!(decoded.device_id, entry.device_id);
        assert_eq!(decoded.nonce, entry.nonce);
        assert_eq!(decoded.ciphertext, entry.ciphertext);
    }

    #[test]
    fn test_entry_rejects_short_input() {
        assert!(Entry::from_bytes(&[]).is_err());
        assert!(Entry::from_bytes(&[0u8; 2]).is_err());
        // version + key_id_len=0 but missing device_id/nonce/ct_len
        assert!(Entry::from_bytes(&[1u8, 0u8, 0u8, 0u8]).is_err());
    }

    // ── Mock backend for unit testing ────────────────────────────────────────

    struct MockBackend {
        key: [u8; 32],
    }

    impl MockBackend {
        fn new() -> Self {
            // Fixed key for deterministic tests
            Self { key: [0xABu8; 32] }
        }
    }

    impl KmsBackend for MockBackend {
        fn backend_name(&self) -> &'static str {
            "mock"
        }

        fn key_id(&self) -> &str {
            "mock-key-1"
        }

        fn device_id(&self) -> [u8; 16] {
            [0x42u8; 16]
        }

        fn get_random(&self, n: usize) -> Result<Vec<u8>> {
            // Return pseudo-random bytes (different each call via OS RNG)
            let mut buf = vec![0u8; n];
            getrandom::fill(&mut buf).map_err(|e| KeyRingError::GeneralError {
                msg: format!("RNG failed: {e}"),
            })?;
            Ok(buf)
        }

        fn hmac_sha256(&self, msg: Vec<u8>) -> Result<[u8; 32]> {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(&msg);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            Ok(out)
        }
    }

    fn mock_ring(name: &str) -> KmsKeyRing<MockBackend> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(".test_kms_{name}"));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        KmsKeyRing {
            backend: MockBackend::new(),
            storage_dir: dir,
        }
    }

    #[test]
    fn test_rekey_secret_round_trip() {
        let mut ring = mock_ring("roundtrip");

        // Set a secret
        DynKeyRing::set_secret(&mut ring, "rekey-test", b"hello rekey").unwrap();

        // Read the nonce before rekey
        let path = ring.entry_path("rekey-test");
        let (_, old_entry) = read_entry_file(&path).unwrap();
        let old_nonce = old_entry.nonce;

        // Rekey the secret
        ring.rekey_secret("rekey-test").unwrap();

        // Verify plaintext is preserved
        let secret = DynKeyRing::get_secret(&mut ring, "rekey-test").unwrap();
        assert_eq!(secret.as_slice(), b"hello rekey");

        // Verify the nonce changed
        let (_, new_entry) = read_entry_file(&path).unwrap();
        assert_ne!(
            old_nonce, new_entry.nonce,
            "nonce should change after rekey"
        );

        // Cleanup
        let _ = fs::remove_dir_all(&ring.storage_dir);
    }

    #[test]
    fn test_rekey_secret_not_found() {
        let mut ring = mock_ring("notfound");
        let err = ring
            .rekey_secret("nonexistent")
            .expect_err("should fail for missing entry");
        assert!(
            matches!(err, KeyRingError::ItemNotFound),
            "expected ItemNotFound, got: {:?}",
            err
        );
        let _ = fs::remove_dir_all(&ring.storage_dir);
    }

    #[test]
    fn test_rekey_all() {
        let mut ring = mock_ring("rekeyall");

        DynKeyRing::set_secret(&mut ring, "a", b"alpha").unwrap();
        DynKeyRing::set_secret(&mut ring, "b", b"beta").unwrap();
        DynKeyRing::set_secret(&mut ring, "c", b"gamma").unwrap();

        // Record old nonces
        let old_nonce_a = read_entry_file(&ring.entry_path("a")).unwrap().1.nonce;
        let old_nonce_b = read_entry_file(&ring.entry_path("b")).unwrap().1.nonce;
        let old_nonce_c = read_entry_file(&ring.entry_path("c")).unwrap().1.nonce;

        ring.rekey_all().unwrap();

        // All secrets should still be readable
        assert_eq!(
            DynKeyRing::get_secret(&mut ring, "a").unwrap().as_slice(),
            b"alpha"
        );
        assert_eq!(
            DynKeyRing::get_secret(&mut ring, "b").unwrap().as_slice(),
            b"beta"
        );
        assert_eq!(
            DynKeyRing::get_secret(&mut ring, "c").unwrap().as_slice(),
            b"gamma"
        );

        // All nonces should have changed
        let new_nonce_a = read_entry_file(&ring.entry_path("a")).unwrap().1.nonce;
        let new_nonce_b = read_entry_file(&ring.entry_path("b")).unwrap().1.nonce;
        let new_nonce_c = read_entry_file(&ring.entry_path("c")).unwrap().1.nonce;
        assert_ne!(old_nonce_a, new_nonce_a);
        assert_ne!(old_nonce_b, new_nonce_b);
        assert_ne!(old_nonce_c, new_nonce_c);

        let _ = fs::remove_dir_all(&ring.storage_dir);
    }
}
