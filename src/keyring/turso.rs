/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! A keyring stored in a [Turso](https://github.com/tursodatabase/turso)
//! database using Turso's native page encryption.
//!
//! Turso's encryption is experimental upstream and the database format may
//! change between Turso releases.

use super::*;
use ::turso::{Builder, EncryptionOpts};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use super::file_common::{self, CipherParam, derive_key_32, file_keyring, secure_file};
use super::turso_common::TursoFile;
use crate::error::KeyRingError;

/// The cipher Turso uses to encrypt database pages.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum TursoCipher {
    /// AEGIS-256 (default)
    #[default]
    Aegis256,
    /// AES-256-GCM
    Aes256Gcm,
}

impl TursoCipher {
    fn as_turso_name(self) -> &'static str {
        match self {
            TursoCipher::Aegis256 => "aegis256",
            TursoCipher::Aes256Gcm => "aes256gcm",
        }
    }
}

impl Zeroize for TursoCipher {
    fn zeroize(&mut self) {
        *self = TursoCipher::default();
    }
}

impl CipherParam for TursoCipher {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "aegis256" | "aegis" => Ok(TursoCipher::Aegis256),
            "aes256gcm" | "aes" => Ok(TursoCipher::Aes256Gcm),
            other => Err(KeyRingError::GeneralError {
                msg: format!("unknown cipher '{}'; use aegis256 or aes256gcm", other),
            }),
        }
    }
}

/// Connection parameters for [`TursoKeyring`].
///
/// Accepted format:
/// ```text
/// password=mysecret salt=0okm9ijn8uhb7ygv [cipher=aegis256|aes256gcm]
/// ```
pub type ConnectionParams = file_common::ConnectionParams<TursoCipher>;

/// A keyring stored in a Turso database encrypted with Turso's native page
/// encryption. The default file is `~/.cryptex/keyring-turso.db3`.
///
/// Turso keeps its own copy of the hex-encoded key for the life of the
/// database; cryptex zeroizes only the copies it owns.
pub struct TursoKeyring {
    file: TursoFile,
}

file_keyring!(TursoKeyring, file);

impl TursoKeyring {
    /// Open (or create) the keyring in `path` (default `~/.cryptex`).
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let file = TursoFile::open(path, builder(connection)?)?;
        secure_file(file.db_path())?;
        Ok(Self { file })
    }

    /// Re-encrypt the keyring with a new key (and optionally a different cipher).
    ///
    /// Consumes the keyring and returns it reopened under `new_params`. If
    /// rekeying fails the original file is left intact and can be reopened
    /// with the old parameters.
    pub fn rekey(self, new_params: &ConnectionParams) -> Result<Self> {
        let file = self.file.rekey(builder(new_params)?)?;
        secure_file(file.db_path())?;
        Ok(Self { file })
    }
}

/// A closure building an encrypted Turso [`Builder`] for a database path.
fn builder(params: &ConnectionParams) -> Result<impl Fn(&str) -> Builder> {
    let hexkey = Zeroizing::new(hex::encode(*derive_key_32(params)?));
    let cipher = params.cipher.as_turso_name();
    Ok(move |path: &str| {
        Builder::new_local(path)
            .experimental_encryption(true)
            .with_encryption(EncryptionOpts {
                cipher: cipher.to_string(),
                hexkey: hexkey.to_string(),
            })
    })
}

#[cfg(test)]
mod tests {
    use super::{ConnectionParams, TursoCipher, TursoKeyring};
    use crate::KeyRing;
    use crate::error::KeyRingError;
    use crate::file_common::test_support::TestDir;
    use std::fs;

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    #[test]
    fn cipher_param_parses() {
        assert_eq!(params("password=a").cipher, TursoCipher::Aegis256);
        assert_eq!(
            params("password=a cipher=aes256gcm").cipher,
            TursoCipher::Aes256Gcm
        );
        assert!("cipher=chacha20".parse::<ConnectionParams>().is_err());
    }

    #[test]
    fn works() {
        let dir = TestDir::new(".test-turso-works");
        let p = params("password=works_test salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = TursoKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            kr.set_secret("k1", b"value1").unwrap();
            assert_eq!(kr.get_secret("k1").unwrap().0, b"value1");
            kr.set_secret("k1", b"value2").unwrap();
            assert_eq!(kr.get_secret("k1").unwrap().0, b"value2");
            kr.delete_secret("k1").unwrap();
            assert!(matches!(
                kr.get_secret("k1"),
                Err(KeyRingError::ItemNotFound)
            ));
            kr.set_secret("persist", b"persisted").unwrap();
        }

        {
            let mut kr = TursoKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            assert_eq!(kr.get_secret("persist").unwrap().0, b"persisted");
        }

        let raw = fs::read(dir.join("keyring-turso.db3")).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"persisted"));
        assert!(!raw.windows(13).any(|w| w == b"SQLite format"));
    }

    #[test]
    fn wrong_key_and_concurrent_open_fail() {
        let dir = TestDir::new(".test-turso-wrongkey");
        let correct = params("password=correct_password salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=wrong_password salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = TursoKeyring::with_params(&correct, dir.keyring_dir()).unwrap();
            kr.set_secret("x", b"secret").unwrap();
            assert!(matches!(
                TursoKeyring::with_params(&correct, dir.keyring_dir()),
                Err(KeyRingError::AccessDenied { .. })
            ));
        }

        assert!(TursoKeyring::with_params(&wrong, dir.keyring_dir()).is_err());
    }

    #[test]
    fn rekey_works() {
        let dir = TestDir::new(".test-turso-rekey");
        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_ cipher=aes256gcm");

        {
            let mut kr = TursoKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            for i in 0..50 {
                kr.set_secret(format!("key_{i}"), format!("value_{i}"))
                    .unwrap();
            }
            let mut kr = kr.rekey(&new_params).unwrap();
            // The returned keyring keeps working on the rekeyed file.
            kr.set_secret("after", b"after_rekey").unwrap();
            assert_eq!(kr.get_secret("key_7").unwrap().0, b"value_7");
        }

        {
            let mut kr = TursoKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            for i in 0..50 {
                assert_eq!(
                    kr.get_secret(format!("key_{i}")).unwrap().0,
                    format!("value_{i}").as_bytes()
                );
            }
            assert_eq!(kr.get_secret("after").unwrap().0, b"after_rekey");
        }

        assert!(TursoKeyring::with_params(&old_params, dir.keyring_dir()).is_err());
    }
}
