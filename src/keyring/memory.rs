/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! An encrypted, in-memory keyring.
//!
//! [`MemoryKeyring`] keeps every secret in a [`BTreeMap`] and never touches the
//! disk, so it builds for every target, including browsers and WASI. Secrets
//! only leave memory through [`MemoryKeyring::export`], which returns a single
//! AEAD-sealed blob, and return through [`MemoryKeyring::import`].
//!
//! ```
//! use cryptex::KeyRing;
//! use cryptex::memory::MemoryKeyring;
//!
//! let params: cryptex::memory::ConnectionParams =
//!     "password=1qaz2wsx3edc4rfv salt=0okm9ijn8uhb7ygv".parse().unwrap();
//! let mut keyring = MemoryKeyring::with_params(&params).unwrap();
//! keyring.set_secret("token", b"secret value").unwrap();
//!
//! // Persist the sealed blob wherever you like, then reopen it later.
//! let blob = keyring.export().unwrap();
//! // Reopening needs the same password (or raw key); the salt, cipher and
//! // Argon2 parameters come from the blob itself.
//! let mut reopened =
//!     MemoryKeyring::import(&blob, b"1qaz2wsx3edc4rfv").unwrap();
//! assert_eq!(reopened.get_secret("token").unwrap().as_slice(), b"secret value");
//! ```

use super::cipher::CipherAlgorithm;
use super::file_common::{self, derive_key_32};
use super::*;
use crate::error::KeyRingError;
use aes_gcm::aead::{Aead, KeyInit};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Connection parameters for [`MemoryKeyring`].
///
/// Accepted format:
/// ```text
/// password=mysecret salt=0okm9ijn8uhb7ygv [cipher=chacha20poly1305|aes256gcm]
/// ```
/// or, to supply the 32-byte key directly, `key=<hex>`.
pub type ConnectionParams = file_common::ConnectionParams<CipherAlgorithm>;

// Sealed blob layout. The whole header is the AEAD associated data, so the
// Argon2 parameters, salt and cipher travel with the blob and cannot be
// altered without failing the tag check.
//
// magic(8) | version(1) | kind(1) | cipher(1) | memory(4) | threads(4) |
// parallel(4) | salt_len(4) | salt(salt_len) | nonce(12) | ciphertext + tag
const BLOB_MAGIC: &[u8; 8] = b"CRYPTEX\0";
const BLOB_VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 1 + 4 + 4 + 4 + 4;
const NONCE_SIZE: usize = 12;

/// Highest Argon2 costs an imported blob may ask for.
///
/// The costs sit in an unauthenticated header, so they are checked before
/// Argon2 runs: a crafted sixteen-byte blob would otherwise ask for terabytes
/// and minutes of work before the AEAD notices it is not authentic.
const MAX_IMPORT_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_IMPORT_THREADS: u32 = 64;
const MAX_IMPORT_PARALLEL: u32 = 64;

/// How the blob's key was produced.
mod kind {
    /// Argon2id over password + salt.
    pub(super) const PASSWORD: u8 = 1;
    /// A caller-supplied 32-byte key.
    pub(super) const RAW_KEY: u8 = 2;
}

fn seal_cipher(cipher: CipherAlgorithm) -> u8 {
    match cipher {
        CipherAlgorithm::ChaCha20Poly1305 => 1,
        CipherAlgorithm::Aes256Gcm => 2,
    }
}

fn open_cipher(tag: u8) -> Result<CipherAlgorithm> {
    match tag {
        1 => Ok(CipherAlgorithm::ChaCha20Poly1305),
        2 => Ok(CipherAlgorithm::Aes256Gcm),
        other => Err(KeyRingError::GeneralError {
            msg: format!("unsupported cipher in keyring blob: {}", other),
        }),
    }
}

/// The error for a blob that will not open: wrong password or tampering.
fn invalid_blob() -> KeyRingError {
    KeyRingError::AccessDenied {
        msg: "Invalid key or corrupted keyring blob".to_string(),
    }
}

/// Authenticated encryption over a whole buffer, for either supported cipher.
enum Sealer {
    ChaCha(Box<chacha20poly1305::ChaCha20Poly1305>),
    Aes(Box<aes_gcm::Aes256Gcm>),
}

impl Sealer {
    fn new(cipher: CipherAlgorithm, key: &[u8; 32]) -> Self {
        match cipher {
            CipherAlgorithm::ChaCha20Poly1305 => Self::ChaCha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
            )),
            CipherAlgorithm::Aes256Gcm => Self::Aes(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key).expect("32-byte key"),
            )),
        }
    }

    fn nonce(bytes: &[u8]) -> Option<chacha20poly1305::Nonce> {
        chacha20poly1305::Nonce::try_from(bytes).ok()
    }

    fn seal(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Self::nonce(nonce)?;
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::ChaCha(c) => c.encrypt(&nonce, payload).ok(),
            Self::Aes(c) => c.encrypt(&nonce, payload).ok(),
        }
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = Self::nonce(nonce)?;
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::ChaCha(c) => c.decrypt(&nonce, payload).ok(),
            Self::Aes(c) => c.decrypt(&nonce, payload).ok(),
        }
    }
}

/// Length-prefixed encoding of the secret table:
/// `count(u32) | [id_len(u32) id value_len(u32) value]*`.
fn encode_secrets(secrets: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Result<Zeroizing<Vec<u8>>> {
    let too_long = |what: &str| KeyRingError::GeneralError {
        msg: format!("{} is too large to export", what),
    };
    // Size the buffer up front: a growing buffer copies the plaintext into
    // freed allocations, which zeroizing afterwards cannot reach.
    let mut len: usize = 4;
    for (id, value) in secrets {
        len = len
            .checked_add(4 + id.len() + 4 + value.len())
            .ok_or_else(|| too_long("the secret table"))?;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(
        &u32::try_from(secrets.len())
            .map_err(|_| too_long("the secret count"))?
            .to_le_bytes(),
    );
    for (id, value) in secrets {
        let id_len = u32::try_from(id.len()).map_err(|_| too_long("a secret id"))?;
        let value_len = u32::try_from(value.len()).map_err(|_| too_long("a secret value"))?;
        out.extend_from_slice(&id_len.to_le_bytes());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Read a `u32` at `pos`, advancing past it.
fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(data.get(*pos..*pos + 4)?);
    *pos += 4;
    Some(u32::from_le_bytes(raw))
}

/// Decode the plaintext table produced by [`encode_secrets`], rejecting any
/// trailing bytes.
fn decode_secrets(data: &[u8]) -> Option<BTreeMap<String, Zeroizing<Vec<u8>>>> {
    let mut pos = 0usize;
    let count = read_u32(data, &mut pos)? as usize;
    let mut secrets = BTreeMap::new();
    for _ in 0..count {
        let id_len = read_u32(data, &mut pos)? as usize;
        let id = std::str::from_utf8(data.get(pos..pos.checked_add(id_len)?)?)
            .ok()?
            .to_string();
        pos += id_len;
        let value_len = read_u32(data, &mut pos)? as usize;
        let value = Zeroizing::new(data.get(pos..pos.checked_add(value_len)?)?.to_vec());
        pos += value_len;
        secrets.insert(id, value);
    }
    (pos == data.len()).then_some(secrets)
}

/// Header fields of a sealed blob.
struct Header<'a> {
    kind: u8,
    cipher: CipherAlgorithm,
    memory: u32,
    threads: u32,
    parallel: u32,
    salt: &'a [u8],
}

/// A keyring that keeps its secrets in memory.
///
/// The key is derived once from the connection parameters and zeroized on
/// drop; [`export`](Self::export) seals everything under a fresh nonce.
pub struct MemoryKeyring {
    secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
    key: Zeroizing<[u8; 32]>,
    cipher: CipherAlgorithm,
    kind: u8,
    salt: Vec<u8>,
    memory: u32,
    threads: u32,
    parallel: u32,
}

impl MemoryKeyring {
    /// Open an empty keyring from the connection parameters.
    pub fn with_params(params: &ConnectionParams) -> Result<Self> {
        let kind = if params.key.is_empty() {
            kind::PASSWORD
        } else {
            kind::RAW_KEY
        };
        Ok(Self {
            secrets: BTreeMap::new(),
            key: derive_key_32(params)?,
            cipher: params.cipher,
            kind,
            salt: params.salt.clone(),
            memory: params.memory,
            threads: params.threads,
            parallel: params.parallel,
        })
    }

    /// Reopen a keyring from a blob returned by [`export`](Self::export).
    ///
    /// A blob made from a password derives its key from the salt and Argon2
    /// parameters stored in the blob, so it needs only the same password. A
    /// blob made from a raw key needs the same key.
    ///
    /// A wrong password or a modified blob returns
    /// [`KeyRingError::AccessDenied`].
    pub fn import(blob: &[u8], password_or_key: &[u8]) -> Result<Self> {
        let header = Self::parse_header(blob)?;
        if header.memory > MAX_IMPORT_MEMORY_KIB
            || header.threads > MAX_IMPORT_THREADS
            || header.parallel > MAX_IMPORT_PARALLEL
        {
            return Err(KeyRingError::GeneralError {
                msg: "the keyring blob asks for unreasonable Argon2 costs".to_string(),
            });
        }
        let params = ConnectionParams {
            key: if header.kind == kind::RAW_KEY {
                password_or_key.to_vec()
            } else {
                Vec::new()
            },
            password: if header.kind == kind::RAW_KEY {
                Vec::new()
            } else {
                password_or_key.to_vec()
            },
            salt: header.salt.to_vec(),
            memory: header.memory,
            threads: header.threads,
            parallel: header.parallel,
            cipher: header.cipher,
        };
        let key = derive_key_32(&params).map_err(|_| invalid_blob())?;
        let aad_end = HEADER_LEN + header.salt.len();
        let body = &blob[aad_end..];
        let sealer = Sealer::new(header.cipher, &key);
        let plaintext = Zeroizing::new(
            sealer
                .open(&body[..NONCE_SIZE], &blob[..aad_end], &body[NONCE_SIZE..])
                .ok_or_else(invalid_blob)?,
        );
        let secrets = decode_secrets(&plaintext).ok_or_else(invalid_blob)?;
        Ok(Self {
            secrets,
            key,
            cipher: header.cipher,
            kind: header.kind,
            salt: header.salt.to_vec(),
            memory: header.memory,
            threads: header.threads,
            parallel: header.parallel,
        })
    }

    fn parse_header(blob: &[u8]) -> Result<Header<'_>> {
        if blob.len() < HEADER_LEN + NONCE_SIZE {
            return Err(invalid_blob());
        }
        if blob.get(..8) != Some(BLOB_MAGIC.as_slice()) {
            return Err(invalid_blob());
        }
        if blob[8] != BLOB_VERSION {
            return Err(KeyRingError::GeneralError {
                msg: format!("unsupported keyring blob version: {}", blob[8]),
            });
        }
        let blob_kind = blob[9];
        if blob_kind != kind::PASSWORD && blob_kind != kind::RAW_KEY {
            return Err(invalid_blob());
        }
        let mut pos = 11;
        let memory = read_u32(blob, &mut pos).ok_or_else(invalid_blob)?;
        let threads = read_u32(blob, &mut pos).ok_or_else(invalid_blob)?;
        let parallel = read_u32(blob, &mut pos).ok_or_else(invalid_blob)?;
        let salt_len = read_u32(blob, &mut pos).ok_or_else(invalid_blob)? as usize;
        // `usize` is 32 bits on wasm32, so this addition can wrap before a
        // bounds check would notice.
        let salt_end = HEADER_LEN.checked_add(salt_len).ok_or_else(invalid_blob)?;
        let salt = blob.get(HEADER_LEN..salt_end).ok_or_else(invalid_blob)?;
        // The body must hold a nonce and at least the AEAD tag.
        let body_start = salt_end
            .checked_add(NONCE_SIZE + 16)
            .ok_or_else(invalid_blob)?;
        if body_start > blob.len() {
            return Err(invalid_blob());
        }
        Ok(Header {
            kind: blob_kind,
            cipher: open_cipher(blob[10]).map_err(|_| invalid_blob())?,
            memory,
            threads,
            parallel,
            salt,
        })
    }

    /// Seal every secret into a single AEAD blob.
    ///
    /// The blob carries the salt, Argon2 parameters, cipher and key kind, so
    /// [`import`](Self::import) needs only the same password (or raw key).
    pub fn export(&self) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|e| KeyRingError::GeneralError {
            msg: format!("unable to generate a nonce: {}", e),
        })?;

        let plaintext = encode_secrets(&self.secrets)?;
        let salt_len = u32::try_from(self.salt.len()).map_err(|_| KeyRingError::GeneralError {
            msg: "salt is too long to export".to_string(),
        })?;
        let mut header = Vec::with_capacity(HEADER_LEN + self.salt.len());
        header.extend_from_slice(BLOB_MAGIC);
        header.push(BLOB_VERSION);
        header.push(self.kind);
        header.push(seal_cipher(self.cipher));
        header.extend_from_slice(&self.memory.to_le_bytes());
        header.extend_from_slice(&self.threads.to_le_bytes());
        header.extend_from_slice(&self.parallel.to_le_bytes());
        header.extend_from_slice(&salt_len.to_le_bytes());
        header.extend_from_slice(&self.salt);

        let ciphertext = Sealer::new(self.cipher, &self.key)
            .seal(&nonce, &header, &plaintext)
            .ok_or_else(|| KeyRingError::GeneralError {
                msg: "unable to encrypt the keyring".to_string(),
            })?;
        let mut blob = header;
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Every id in the keyring, in order.
    pub fn keys(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// Re-encrypt under new connection parameters, optionally with a new cipher.
    ///
    /// The secrets stay in memory; only the key, salt and cipher change, so
    /// the next [`export`](Self::export) uses the new parameters.
    pub fn rekey(&mut self, new_params: &ConnectionParams) -> Result<()> {
        let key = derive_key_32(new_params)?;
        self.kind = if new_params.key.is_empty() {
            kind::PASSWORD
        } else {
            kind::RAW_KEY
        };
        self.salt = new_params.salt.clone();
        self.memory = new_params.memory;
        self.threads = new_params.threads;
        self.parallel = new_params.parallel;
        self.cipher = new_params.cipher;
        self.key = key;
        Ok(())
    }

    /// The cipher this keyring seals blobs with.
    pub fn cipher(&self) -> CipherAlgorithm {
        self.cipher
    }
}

impl NewKeyRing for MemoryKeyring {
    fn new<S: AsRef<str>>(lock_key: S) -> Result<Self> {
        let params = lock_key.as_ref().parse::<ConnectionParams>()?;
        Self::with_params(&params)
    }
}

impl DynKeyRing for MemoryKeyring {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        match self.secrets.get(id) {
            Some(value) => Ok(KeyRingSecret(value.to_vec())),
            None => Err(KeyRingError::ItemNotFound),
        }
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        self.secrets
            .insert(id.to_string(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        match self.secrets.remove(id) {
            Some(mut value) => {
                zeroize::Zeroize::zeroize(&mut *value);
                Ok(())
            }
            None => Err(KeyRingError::ItemNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    // Only `DynKeyRing` is imported, so `kr.get_secret(..)` is unambiguous.
    use super::super::DynKeyRing;
    use super::{CipherAlgorithm, ConnectionParams, HEADER_LEN, MemoryKeyring};
    use crate::error::KeyRingError;
    use argon2::Params as Argon2Params;

    const PASSWORD: &[u8] = b"1qaz2wsx3edc4rfv";

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    fn password_params(extra: &str) -> ConnectionParams {
        params(&format!(
            "password=1qaz2wsx3edc4rfv salt=0okm9ijn8uhb7ygv {extra}"
        ))
    }

    #[test]
    fn round_trip_and_persistence() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        kr.set_secret("a", b"one").unwrap();
        kr.set_secret("b", b"two").unwrap();
        kr.delete_secret("b").unwrap();
        assert_eq!(kr.get_secret("a").unwrap().as_slice(), b"one");
        assert!(matches!(
            kr.get_secret("b"),
            Err(KeyRingError::ItemNotFound)
        ));

        let blob = kr.export().unwrap();
        let mut reopened = MemoryKeyring::import(&blob, PASSWORD).unwrap();
        assert_eq!(reopened.get_secret("a").unwrap().as_slice(), b"one");
        reopened.set_secret("c", b"three").unwrap();
        assert_eq!(reopened.get_secret("c").unwrap().as_slice(), b"three");
    }

    #[test]
    fn keys_lists_the_ids_in_order() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        assert!(kr.keys().is_empty());
        kr.set_secret("b", b"two").unwrap();
        kr.set_secret("a", b"one").unwrap();
        assert_eq!(kr.keys(), ["a", "b"]);
        kr.delete_secret("a").unwrap();
        assert_eq!(kr.keys(), ["b"]);
    }

    #[test]
    fn empty_keyring_round_trips() {
        let kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        let blob = kr.export().unwrap();
        let mut reopened = MemoryKeyring::import(&blob, PASSWORD).unwrap();
        assert!(matches!(
            reopened.get_secret("missing"),
            Err(KeyRingError::ItemNotFound)
        ));
    }

    #[test]
    fn wrong_password_is_denied() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        kr.set_secret("a", b"one").unwrap();
        let blob = kr.export().unwrap();
        assert!(matches!(
            MemoryKeyring::import(&blob, b"wrong"),
            Err(KeyRingError::AccessDenied { .. })
        ));
    }

    /// A blob header with whatever Argon2 costs a hostile image would ask for.
    fn blob_with_costs(memory: u32, threads: u32, parallel: u32, salt_len: u32) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"CRYPTEX\0");
        blob.push(1); // version
        blob.push(super::kind::PASSWORD);
        blob.push(super::seal_cipher(CipherAlgorithm::default()));
        blob.extend_from_slice(&memory.to_le_bytes());
        blob.extend_from_slice(&threads.to_le_bytes());
        blob.extend_from_slice(&parallel.to_le_bytes());
        blob.extend_from_slice(&salt_len.to_le_bytes());
        blob.extend_from_slice(b"saltsalt");
        blob.extend_from_slice(&[0u8; super::NONCE_SIZE + 16]);
        blob
    }

    #[test]
    fn import_refuses_unreasonable_costs_before_deriving() {
        // These sit in an unauthenticated header, so they must be bounded
        // before Argon2 tries to honour them.
        for (memory, threads, parallel) in [
            (u32::MAX, 1, 1),
            (Argon2Params::DEFAULT_M_COST, u32::MAX, 1),
            (Argon2Params::DEFAULT_M_COST, 1, u32::MAX),
        ] {
            let blob = blob_with_costs(memory, threads, parallel, 8);
            assert!(matches!(
                MemoryKeyring::import(&blob, PASSWORD),
                Err(KeyRingError::GeneralError { .. })
            ));
        }
    }

    #[test]
    fn import_refuses_a_salt_length_that_would_overflow() {
        // `usize` is 32 bits on wasm32, where the old bounds check wrapped and
        // a debug build then panicked slicing the blob.
        let blob = blob_with_costs(
            Argon2Params::DEFAULT_M_COST,
            Argon2Params::DEFAULT_T_COST,
            Argon2Params::DEFAULT_P_COST,
            u32::MAX,
        );
        assert!(matches!(
            MemoryKeyring::import(&blob, PASSWORD),
            Err(KeyRingError::AccessDenied { .. })
        ));
    }

    #[test]
    fn a_duplicate_parameter_is_refused() {
        // A password containing ` salt=` used to silently replace the salt.
        assert!(
            "password=a salt=b salt=c"
                .parse::<ConnectionParams>()
                .is_err()
        );
        assert!("password=a password=b".parse::<ConnectionParams>().is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        kr.set_secret("a", b"one").unwrap();
        let blob = kr.export().unwrap();

        // Header, salt and body are all authenticated.
        for index in [9usize, 10, 12, HEADER_LEN + 1, blob.len() - 1] {
            let mut flipped = blob.clone();
            flipped[index] ^= 0x80;
            assert!(
                MemoryKeyring::import(&flipped, PASSWORD).is_err(),
                "flipping byte {} went undetected",
                index
            );
        }

        assert!(MemoryKeyring::import(&blob[..blob.len() - 1], PASSWORD).is_err());
        assert!(MemoryKeyring::import(b"", PASSWORD).is_err());
    }

    #[test]
    fn both_ciphers_and_rekey() {
        for (cipher, other) in [
            ("chacha20poly1305", "aes256gcm"),
            ("aes256gcm", "chacha20poly1305"),
        ] {
            let mut kr =
                MemoryKeyring::with_params(&password_params(&format!("cipher={cipher}"))).unwrap();
            kr.set_secret("a", b"one").unwrap();
            let mut reopened = MemoryKeyring::import(&kr.export().unwrap(), PASSWORD).unwrap();
            assert_eq!(reopened.get_secret("a").unwrap().as_slice(), b"one");

            reopened
                .rekey(&params(&format!(
                    "password=new_password salt=another_salt_value cipher={other}"
                )))
                .unwrap();
            assert_eq!(
                reopened.cipher(),
                if other == "aes256gcm" {
                    CipherAlgorithm::Aes256Gcm
                } else {
                    CipherAlgorithm::ChaCha20Poly1305
                }
            );

            let rekeyed = reopened.export().unwrap();
            assert!(MemoryKeyring::import(&rekeyed, PASSWORD).is_err());
            let mut again = MemoryKeyring::import(&rekeyed, b"new_password").unwrap();
            assert_eq!(again.get_secret("a").unwrap().as_slice(), b"one");
        }
    }

    #[test]
    fn raw_key_blobs_need_the_key() {
        let key = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let mut kr =
            MemoryKeyring::with_params(&params(&format!("key={} salt=ignored_salt_value", key)))
                .unwrap();
        kr.set_secret("a", b"one").unwrap();
        let blob = kr.export().unwrap();

        let key_bytes = hex::decode(key).unwrap();
        let mut reopened = MemoryKeyring::import(&blob, &key_bytes).unwrap();
        assert_eq!(reopened.get_secret("a").unwrap().as_slice(), b"one");
        assert!(MemoryKeyring::import(&blob, PASSWORD).is_err());

        // A raw-key blob carries no password, so the password path must fail.
        assert!(MemoryKeyring::import(&blob, b"anything").is_err());
    }

    #[test]
    fn blobs_carry_no_plaintext() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        kr.set_secret("account", b"super-secret-value").unwrap();
        let blob = kr.export().unwrap();
        assert!(!blob.windows(18).any(|w| w == b"super-secret-value"));
        assert!(!blob.windows(7).any(|w| w == b"account"));
    }

    #[test]
    fn ids_and_values_survive_odd_characters() {
        let mut kr = MemoryKeyring::with_params(&password_params("")).unwrap();
        kr.set_secret("ünïcode/ключ", b"\x00\x01\x02bytes").unwrap();
        let blob = kr.export().unwrap();
        let mut reopened = MemoryKeyring::import(&blob, PASSWORD).unwrap();
        assert_eq!(
            reopened.get_secret("ünïcode/ключ").unwrap().as_slice(),
            b"\x00\x01\x02bytes"
        );
    }
}
