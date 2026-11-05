/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! A keyring stored in a [Turso](https://github.com/tursodatabase/turso)
//! database whose file I/O passes through a custom encrypting [`IO`] backend
//! — the Turso counterpart of [`encrypted_vfs`](crate::encrypted_vfs).
//!
//! Every file Turso opens (the database and its WAL) is stored with the same
//! page layout as the encrypted VFS: `[ciphertext(4096) | nonce(12) | tag(16)]`.

use super::*;
use ::turso::Builder;
use ::turso::core::io::FileSyncType;
use ::turso::core::io::clock::DefaultClock;
use ::turso::core::{
    Buffer, Clock, Completion, File as TursoFileIo, IO, LimboError, MonotonicInstant, OpenFlags,
    WallClockInstant, io_error,
};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use super::file_common::{self, derive_key_32, file_keyring, private_open_options};
use super::page_cipher::{self, ActiveCipher};
use super::turso_common::TursoFile;

pub use super::page_cipher::CipherAlgorithm;

/// Connection parameters for [`TursoEncryptedIoKeyring`].
///
/// Accepted format:
/// ```text
/// password=mysecret salt=0okm9ijn8uhb7ygv [cipher=chacha20poly1305|aes256gcm]
/// ```
pub type ConnectionParams = file_common::ConnectionParams<CipherAlgorithm>;

type TursoResult<T> = std::result::Result<T, LimboError>;

/// Turso IO backend that encrypts every page it writes and decrypts every
/// page it reads.
struct EncryptedIo {
    cipher: Arc<ActiveCipher>,
}

impl IO for EncryptedIo {
    fn open_file(
        &self,
        path: &str,
        flags: OpenFlags,
        _direct: bool,
    ) -> TursoResult<Arc<dyn TursoFileIo>> {
        let mut opts = private_open_options();
        opts.read(true);
        if !flags.contains(OpenFlags::ReadOnly) {
            opts.write(true)
                .create(flags.contains(OpenFlags::Create))
                .truncate(false);
        }
        let file = opts.open(path).map_err(|e| io_error(e, "open"))?;
        Ok(Arc::new(EncryptedFile {
            file: Mutex::new(file),
            cipher: Arc::clone(&self.cipher),
        }))
    }

    fn remove_file(&self, path: &str) -> TursoResult<()> {
        fs::remove_file(path).map_err(|e| io_error(e, "remove_file"))
    }
}

impl Clock for EncryptedIo {
    fn current_time_monotonic(&self) -> MonotonicInstant {
        DefaultClock.current_time_monotonic()
    }

    fn current_time_wall_clock(&self) -> WallClockInstant {
        DefaultClock.current_time_wall_clock()
    }
}

struct EncryptedFile {
    file: Mutex<File>,
    cipher: Arc<ActiveCipher>,
}

impl EncryptedFile {
    fn file(&self) -> TursoResult<MutexGuard<'_, File>> {
        self.file
            .lock()
            .map_err(|_| LimboError::InternalError("encrypted file lock poisoned".to_string()))
    }
}

fn to_usize(n: u64) -> TursoResult<usize> {
    usize::try_from(n).map_err(|_| LimboError::InternalError("offset overflows usize".into()))
}

fn to_i32(n: usize) -> TursoResult<i32> {
    i32::try_from(n).map_err(|_| LimboError::InternalError("I/O length overflows i32".into()))
}

impl TursoFileIo for EncryptedFile {
    // Exclusivity comes from the keyring's sidecar lock, as with the encrypted VFS.
    fn lock_file(&self, _exclusive: bool) -> TursoResult<()> {
        Ok(())
    }

    fn unlock_file(&self) -> TursoResult<()> {
        Ok(())
    }

    fn pread(&self, pos: u64, c: Completion) -> TursoResult<Completion> {
        let mut file = self.file()?;
        let available = page_cipher::logical_size(&file)
            .map_err(|e| io_error(e, "pread"))?
            .saturating_sub(pos);
        let read = {
            let buf = c.as_read().buf().as_mut_slice();
            let n = buf.len().min(to_usize(available)?);
            self.cipher
                .read_at(&mut file, to_usize(pos)?, &mut buf[..n])
                .map_err(|e| io_error(e, "pread"))?
        };
        c.complete(to_i32(read)?);
        Ok(c)
    }

    fn pwrite(&self, pos: u64, buffer: Arc<Buffer>, c: Completion) -> TursoResult<Completion> {
        let written = self
            .cipher
            .write_at(&mut *self.file()?, to_usize(pos)?, buffer.as_slice())
            .map_err(|e| io_error(e, "pwrite"))?;
        c.complete(to_i32(written)?);
        Ok(c)
    }

    fn sync(&self, c: Completion, _sync_type: FileSyncType) -> TursoResult<Completion> {
        self.file()?.sync_all().map_err(|e| io_error(e, "sync"))?;
        c.complete(0);
        Ok(c)
    }

    fn size(&self) -> TursoResult<u64> {
        page_cipher::logical_size(&*self.file()?).map_err(|e| io_error(e, "size"))
    }

    fn truncate(&self, len: u64, c: Completion) -> TursoResult<Completion> {
        page_cipher::truncate(&*self.file()?, to_usize(len)?)
            .map_err(|e| io_error(e, "truncate"))?;
        c.complete(0);
        Ok(c)
    }
}

/// A keyring stored in a Turso database whose pages are encrypted by
/// cryptex's own ChaCha20-Poly1305 / AES-256-GCM IO layer rather than Turso's
/// built-in encryption. The default file is `~/.cryptex/keyring-turso.db3`.
pub struct TursoEncryptedIoKeyring {
    file: TursoFile,
}

file_keyring!(TursoEncryptedIoKeyring, file);

impl TursoEncryptedIoKeyring {
    /// Open (or create) the keyring in `path` (default `~/.cryptex`).
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            file: TursoFile::open(path, builder(connection)?)?,
        })
    }

    /// Re-encrypt the keyring with a new key (and optionally a different cipher).
    ///
    /// Consumes the keyring and returns it reopened under `new_params`. If
    /// rekeying fails the original file is left intact and can be reopened
    /// with the old parameters.
    pub fn rekey(self, new_params: &ConnectionParams) -> Result<Self> {
        Ok(Self {
            file: self.file.rekey(builder(new_params)?)?,
        })
    }
}

/// A closure building a Turso [`Builder`] that routes all file I/O through
/// an [`EncryptedIo`] keyed from `params`.
fn builder(params: &ConnectionParams) -> Result<impl Fn(&str) -> Builder> {
    let key = derive_key_32(params)?;
    let io: Arc<dyn IO> = Arc::new(EncryptedIo {
        cipher: Arc::new(ActiveCipher::from_key(params.cipher, &key)),
    });
    Ok(move |path: &str| Builder::new_local(path).with_io_impl(Arc::clone(&io)))
}

#[cfg(test)]
mod tests {
    use super::{CipherAlgorithm, ConnectionParams, TursoEncryptedIoKeyring};
    use crate::KeyRing;
    use crate::error::KeyRingError;
    use crate::file_common::test_support::TestDir;
    use std::fs;

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    #[test]
    fn works_with_both_ciphers() {
        for (name, cipher) in [
            ("chacha20poly1305", CipherAlgorithm::ChaCha20Poly1305),
            ("aes256gcm", CipherAlgorithm::Aes256Gcm),
        ] {
            let dir = TestDir::new(&format!(".test-turso-io-works-{name}"));
            let p = params(&format!(
                "password=works_test salt=1qaz2wsx3edc4rfv5tgb cipher={name}"
            ));
            assert_eq!(p.cipher, cipher);

            {
                let mut kr = TursoEncryptedIoKeyring::with_params(&p, dir.keyring_dir()).unwrap();
                for i in 0..50 {
                    kr.set_secret(format!("key_{i}"), format!("value_{i}"))
                        .unwrap();
                }
                kr.delete_secret("key_0").unwrap();
                assert!(matches!(
                    kr.get_secret("key_0"),
                    Err(KeyRingError::ItemNotFound)
                ));
            }

            {
                let mut kr = TursoEncryptedIoKeyring::with_params(&p, dir.keyring_dir()).unwrap();
                for i in 1..50 {
                    assert_eq!(
                        kr.get_secret(format!("key_{i}")).unwrap().0,
                        format!("value_{i}").as_bytes()
                    );
                }
            }

            for entry in fs::read_dir(&*dir).unwrap() {
                let raw = fs::read(entry.unwrap().path()).unwrap();
                assert!(!raw.windows(8).any(|w| w == b"value_42"));
                assert!(!raw.windows(13).any(|w| w == b"SQLite format"));
            }
        }
    }

    #[test]
    fn wrong_key_and_concurrent_open_fail() {
        let dir = TestDir::new(".test-turso-io-wrongkey");
        let correct = params("password=correct_password salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=wrong_password salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = TursoEncryptedIoKeyring::with_params(&correct, dir.keyring_dir()).unwrap();
            kr.set_secret("x", b"secret").unwrap();
            assert!(matches!(
                TursoEncryptedIoKeyring::with_params(&correct, dir.keyring_dir()),
                Err(KeyRingError::AccessDenied { .. })
            ));
        }

        assert!(TursoEncryptedIoKeyring::with_params(&wrong, dir.keyring_dir()).is_err());
    }

    #[test]
    fn rekey_works() {
        let dir = TestDir::new(".test-turso-io-rekey");
        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_ cipher=aes256gcm");

        {
            let mut kr =
                TursoEncryptedIoKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            kr.set_secret("data", b"important").unwrap();
            let mut kr = kr.rekey(&new_params).unwrap();
            kr.set_secret("after", b"after_rekey").unwrap();
            assert_eq!(kr.get_secret("data").unwrap().0, b"important");
        }

        {
            let mut kr =
                TursoEncryptedIoKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert_eq!(kr.get_secret("data").unwrap().0, b"important");
            assert_eq!(kr.get_secret("after").unwrap().0, b"after_rekey");
        }

        assert!(TursoEncryptedIoKeyring::with_params(&old_params, dir.keyring_dir()).is_err());
    }
}
