/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use rusqlite::{Connection, OpenFlags};
use sqlite_plugin::flags::{AccessFlags, LockLevel, OpenOpts};
use sqlite_plugin::vfs::{RegisterOpts, Vfs, VfsHandle, VfsResult, register_static};
use std::ffi::CString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use zeroize::Zeroizing;

use super::file_common::{
    acquire_single_opener_lock, derive_key_32, file_keyring, get_keyring_file, private_open_options,
};
use super::page_cipher::{ActiveCipher, LOGICAL_PAGE_SIZE, logical_size, truncate};
use super::sqlite_common::{KEYRING_FILE, init_schema, lock_connection};
use crate::error::KeyRingError;

pub use super::page_cipher::CipherAlgorithm;

/// Connection parameters for [`EncryptedVfsKeyring`].
///
/// Accepted format:
/// ```text
/// password=mysecret salt=0okm9ijn8uhb7ygv [cipher=chacha20poly1305|aes256gcm]
/// ```
pub type ConnectionParams = file_common::ConnectionParams<CipherAlgorithm>;

static VFS_COUNTER: AtomicU32 = AtomicU32::new(0);

// ─── VFS state ────────────────────────────────────────────────────────────────

/// A SQLite VFS that encrypts every page with the current cipher. The cipher
/// sits behind a lock so `rekey` can rotate it under the open connection.
#[derive(Clone)]
pub(crate) struct EncryptedVfs {
    cipher: Arc<RwLock<ActiveCipher>>,
}

impl EncryptedVfs {
    fn new(cipher: ActiveCipher) -> Self {
        Self {
            cipher: Arc::new(RwLock::new(cipher)),
        }
    }

    fn rotate(&self, cipher: ActiveCipher) -> Result<()> {
        *self.cipher.write().map_err(|_| vfs_poisoned())? = cipher;
        Ok(())
    }
}

fn vfs_poisoned() -> KeyRingError {
    KeyRingError::GeneralError {
        msg: "VFS state lock poisoned".to_string(),
    }
}

// ─── File handle ──────────────────────────────────────────────────────────────

pub(crate) struct EncryptedHandle {
    file: File,
    delete_on_close: bool,
    path: PathBuf,
}

impl VfsHandle for EncryptedHandle {
    fn readonly(&self) -> bool {
        false
    }
    fn in_memory(&self) -> bool {
        false
    }
}

// ─── Vfs implementation ───────────────────────────────────────────────────────

impl Vfs for EncryptedVfs {
    type Handle = EncryptedHandle;

    fn open(&self, path: Option<&str>, opts: OpenOpts) -> VfsResult<Self::Handle> {
        let is_readonly = opts.mode().is_readonly();
        let mut file_opts = private_open_options();
        file_opts.read(true);

        let path = match path {
            Some(p) => {
                file_opts
                    .write(!is_readonly)
                    .create(!is_readonly)
                    .truncate(false);
                PathBuf::from(p)
            }
            None => {
                // Unpredictable name + O_EXCL (`create_new`) + 0600 defeats symlink
                // and pre-creation attacks on the shared temp directory.
                let mut rand = [0u8; 16];
                getrandom::fill(&mut rand).map_err(|_| sqlite_plugin::vars::SQLITE_CANTOPEN)?;
                file_opts.write(true).create_new(true);
                std::env::temp_dir().join(format!(
                    "cryptex-tmp-{}-{}-{}.db",
                    std::process::id(),
                    VFS_COUNTER.fetch_add(1, Ordering::Relaxed),
                    hex::encode(rand)
                ))
            }
        };
        let file = file_opts
            .open(&path)
            .map_err(|_| sqlite_plugin::vars::SQLITE_CANTOPEN)?;

        Ok(EncryptedHandle {
            file,
            delete_on_close: opts.delete_on_close(),
            path,
        })
    }

    fn close(&self, handle: Self::Handle) -> VfsResult<()> {
        if handle.delete_on_close {
            let _ = fs::remove_file(&handle.path);
        }
        Ok(())
    }

    fn delete(&self, path: &str) -> VfsResult<()> {
        fs::remove_file(path).map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_DELETE)
    }

    fn access(&self, path: &str, _flags: AccessFlags) -> VfsResult<bool> {
        Ok(Path::new(path).exists())
    }

    fn file_size(&self, handle: &mut Self::Handle) -> VfsResult<usize> {
        logical_size(&handle.file)
            .map(|n| n as usize)
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_FSTAT)
    }

    fn truncate(&self, handle: &mut Self::Handle, logical_size: usize) -> VfsResult<()> {
        truncate(&handle.file, logical_size).map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_TRUNCATE)
    }

    fn read(&self, handle: &mut Self::Handle, offset: usize, data: &mut [u8]) -> VfsResult<usize> {
        self.cipher
            .read()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?
            .read_at(&mut handle.file, offset, data)
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)
    }

    fn write(&self, handle: &mut Self::Handle, offset: usize, data: &[u8]) -> VfsResult<usize> {
        self.cipher
            .read()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?
            .write_at(&mut handle.file, offset, data)
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)
    }

    fn sync(&self, handle: &mut Self::Handle) -> VfsResult<()> {
        handle
            .file
            .sync_all()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_FSYNC)
    }

    fn lock(&self, _handle: &mut Self::Handle, _level: LockLevel) -> VfsResult<()> {
        Ok(())
    }

    fn unlock(&self, _handle: &mut Self::Handle, _level: LockLevel) -> VfsResult<()> {
        Ok(())
    }

    fn check_reserved_lock(&self, _handle: &mut Self::Handle) -> VfsResult<bool> {
        Ok(false)
    }
}

// ─── VFS registration ─────────────────────────────────────────────────────────

fn register_encrypted_vfs(vfs: EncryptedVfs) -> Result<String> {
    let name = format!(
        "cryptex-evfs-{}",
        VFS_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let cname = CString::new(name.as_str())
        .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
    register_static(
        cname,
        vfs,
        RegisterOpts {
            make_default: false,
        },
    )
    .map_err(|e| KeyRingError::GeneralError {
        msg: format!("VFS registration failed (code {})", e),
    })?;
    Ok(name)
}

// ─── EncryptedVfsKeyring ──────────────────────────────────────────────────────

/// A keyring stored in a bundled SQLite database whose pages are encrypted
/// by a custom VFS. The default file is `~/.cryptex/keyring.db3`.
pub struct EncryptedVfsKeyring {
    /// `Connection` is `Send` but not `Sync`; the mutex makes the keyring
    /// `Sync` and lets `rekey` swap the connection through `&self`.
    conn: Mutex<Connection>,
    vfs: EncryptedVfs,
    vfs_name: String,
    db_path: PathBuf,
    /// Exclusive advisory lock on a sidecar file, held for the keyring's
    /// lifetime. Guarantees a single opener: the encrypted VFS performs no
    /// SQLite-level locking, so concurrent opens would otherwise corrupt the
    /// database. Released automatically when the keyring is dropped. A sidecar
    /// (not the db file) is locked so the lock survives `rekey`'s atomic rename.
    _lock: File,
}

file_keyring!(EncryptedVfsKeyring, conn);

impl EncryptedVfsKeyring {
    /// Open (or create) the keyring in `path` (default `~/.cryptex`).
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let key = derive_key_32(connection)?;
        let vfs = EncryptedVfs::new(ActiveCipher::from_key(connection.cipher, &key));
        let vfs_name = register_encrypted_vfs(vfs.clone())?;
        let db_path = get_keyring_file(path, KEYRING_FILE)?;

        // Fail fast if another opener already holds the keyring, before touching
        // the database. The encrypted VFS does no SQLite-level locking.
        let lock = acquire_single_opener_lock(&db_path)?;
        let conn = open_connection(&db_path, &vfs_name)?;

        Ok(Self {
            conn: Mutex::new(conn),
            vfs,
            vfs_name,
            db_path,
            _lock: lock,
        })
    }

    /// Re-encrypt the database with a new key (and optionally a different cipher).
    ///
    /// Writes to a temp file first, then atomically renames — original is
    /// untouched until the rename succeeds. The connection is closed before
    /// the rename and reopened on the rekeyed file, so the keyring stays
    /// usable afterwards. The connection lock is held throughout, so no other
    /// thread can write while pages are being copied.
    pub fn rekey(&self, new_params: &ConnectionParams) -> Result<()> {
        let new_key = derive_key_32(new_params)?;
        let new_cipher = ActiveCipher::from_key(new_params.cipher, &new_key);

        let mut conn = lock_connection(&self.conn)?;
        let page_count: u32 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;

        let tmp_path = self.db_path.with_extension("cryptex-rekey-tmp");
        if let Err(e) = self.reencrypt_into(&tmp_path, &new_cipher, page_count as usize) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Close the connection before replacing the file: its handle would
        // otherwise keep pointing at the old file (and Windows refuses to
        // rename over an open file).
        *conn = Connection::open_in_memory()?;

        if let Err(e) = fs::rename(&tmp_path, &self.db_path) {
            let _ = fs::remove_file(&tmp_path);
            *conn = open_connection(&self.db_path, &self.vfs_name)?;
            return Err(KeyRingError::GeneralError {
                msg: format!("unable to replace keyring file: {}", e),
            });
        }

        self.vfs.rotate(new_cipher)?;
        *conn = open_connection(&self.db_path, &self.vfs_name)?;

        Ok(())
    }

    /// Copy the first `page_count` pages of the database into `dst_path`,
    /// decrypting with the current cipher and encrypting with `new_cipher`.
    fn reencrypt_into(
        &self,
        dst_path: &Path,
        new_cipher: &ActiveCipher,
        page_count: usize,
    ) -> Result<()> {
        let mut src = File::open(&self.db_path)?;
        let mut dst = private_open_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst_path)?;
        let cipher = self.vfs.cipher.read().map_err(|_| vfs_poisoned())?;
        let mut page = Zeroizing::new([0u8; LOGICAL_PAGE_SIZE]);
        for offset in (0..page_count).map(|n| n * LOGICAL_PAGE_SIZE) {
            cipher.read_at(&mut src, offset, &mut *page)?;
            new_cipher.write_at(&mut dst, offset, &*page)?;
        }
        dst.sync_all()?;
        Ok(())
    }
}

/// Open the keyring database through the registered encrypted VFS, verify the
/// key can read it, and ensure the `secrets` table exists.
fn open_connection(db_path: &Path, vfs_name: &str) -> Result<Connection> {
    let conn = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        vfs_name,
    )?;
    init_schema(&conn)?;
    Ok(conn)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{CipherAlgorithm, ConnectionParams, EncryptedVfsKeyring};
    use crate::KeyRing;
    use crate::file_common::test_support::TestDir;

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    #[test]
    fn works() {
        let dir = TestDir::new(".test-evfs-works");

        let p = params("password=works_test salt=1qaz2wsx3edc4rfv5tgb");

        {
            let res = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir());
            assert!(res.is_ok(), "open failed: {:?}", res.err());
            let mut kr = res.unwrap();

            assert!(kr.set_secret("k1", b"value1").is_ok());
            let got = kr.get_secret("k1").unwrap();
            assert_eq!(got.0, b"value1");

            assert!(kr.delete_secret("k1").is_ok());
            assert!(kr.get_secret("k1").is_err());

            assert!(kr.set_secret("persist", b"persisted").is_ok());
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            let got = kr.get_secret("persist").unwrap();
            assert_eq!(got.0, b"persisted");
        }
    }

    #[test]
    fn concurrent_open_is_rejected() {
        let dir = TestDir::new(".test-evfs-concurrent");

        let p = params("password=concurrent_test salt=1qaz2wsx3edc4rfv5tgb");

        let first = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();

        // A second opener must be rejected while the first is alive.
        let second = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir());
        assert!(
            matches!(second, Err(crate::error::KeyRingError::AccessDenied { .. })),
            "expected AccessDenied for concurrent open, got: {:?}",
            second.err()
        );

        // After the first is dropped, the lock releases and reopening succeeds.
        drop(first);
        let reopened = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir());
        assert!(
            reopened.is_ok(),
            "reopen after drop failed: {:?}",
            reopened.err()
        );
    }

    #[test]
    fn wrong_key_fails() {
        let dir = TestDir::new(".test-evfs-wrongkey");

        let correct = params("password=correct_password salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=wrong_password salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = EncryptedVfsKeyring::with_params(&correct, dir.keyring_dir()).unwrap();
            kr.set_secret("x", b"secret").unwrap();
        }

        {
            let result = EncryptedVfsKeyring::with_params(&wrong, dir.keyring_dir());
            assert!(result.is_err(), "expected error with wrong key");
        }
    }

    #[test]
    fn invalid_hex_key_is_an_error() {
        let result = "key=not-hex".parse::<ConnectionParams>();
        assert!(result.is_err());
    }

    #[test]
    fn rekey_works() {
        let dir = TestDir::new(".test-evfs-rekey");

        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_");

        {
            let mut kr = EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            kr.set_secret("data", b"important").unwrap();
            kr.rekey(&new_params).unwrap();
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert_eq!(kr.get_secret("data").unwrap().0, b"important");
        }

        {
            let result = EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir());
            assert!(result.is_err(), "old key should fail after rekey");
        }
    }

    #[test]
    fn rekey_allows_continued_use_on_same_connection() {
        let dir = TestDir::new(".test-evfs-rekey-continue");

        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_ cipher=aes256gcm");

        {
            let mut kr = EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            for i in 0..50 {
                kr.set_secret(format!("before_{i}"), format!("value_{i}"))
                    .unwrap();
            }
            kr.rekey(&new_params).unwrap();

            // Reads, writes and deletes on the same keyring must hit the
            // rekeyed file, not the replaced one.
            for i in 0..50 {
                kr.set_secret(format!("after_{i}"), format!("value_{i}"))
                    .unwrap();
            }
            assert_eq!(kr.get_secret("before_7").unwrap().0, b"value_7");
            kr.delete_secret("before_0").unwrap();
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert!(kr.get_secret("before_0").is_err());
            for i in 1..50 {
                assert_eq!(
                    kr.get_secret(format!("before_{i}")).unwrap().0,
                    format!("value_{i}").as_bytes()
                );
            }
            for i in 0..50 {
                assert_eq!(
                    kr.get_secret(format!("after_{i}")).unwrap().0,
                    format!("value_{i}").as_bytes()
                );
            }
        }

        assert!(EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir()).is_err());
    }

    #[test]
    fn rekey_through_shared_reference_on_another_thread() {
        let dir = TestDir::new(".test-evfs-rekey-shared");

        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_");

        let mut kr = EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
        kr.set_secret("shared", b"value").unwrap();

        let kr = std::sync::Arc::new(kr);
        let worker = std::sync::Arc::clone(&kr);
        std::thread::spawn(move || worker.rekey(&new_params))
            .join()
            .unwrap()
            .unwrap();

        let mut kr = std::sync::Arc::try_unwrap(kr).ok().unwrap();
        assert_eq!(kr.get_secret("shared").unwrap().0, b"value");
        drop(kr);

        assert!(EncryptedVfsKeyring::with_params(&old_params, dir.keyring_dir()).is_err());
    }

    #[test]
    fn bulk_insert_and_retrieve() {
        let dir = TestDir::new(".test-evfs-bulk");

        let p = params("password=bulk_test salt=bulk_salt_value_here_");

        let entries: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| {
                (
                    format!("key_{:02}", i),
                    format!("value_{:06}", i).into_bytes(),
                )
            })
            .collect();

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            for (k, v) in &entries {
                kr.set_secret(k, v).unwrap();
            }
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            for (k, v) in &entries {
                let got = kr.get_secret(k).unwrap();
                assert_eq!(&got.0, v, "mismatch for {k}");
            }
        }
    }

    #[test]
    fn aes_bulk_insert_and_retrieve() {
        let dir = TestDir::new(".test-evfs-aes-bulk");

        let p = params("password=aes_bulk_test salt=aes_bulk_salt_here_ cipher=aes256gcm");
        assert_eq!(p.cipher, CipherAlgorithm::Aes256Gcm);

        let entries: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| {
                (
                    format!("key_{:02}", i),
                    format!("value_{:06}", i).into_bytes(),
                )
            })
            .collect();

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            for (k, v) in &entries {
                kr.set_secret(k, v).unwrap();
            }
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, dir.keyring_dir()).unwrap();
            for (k, v) in &entries {
                let got = kr.get_secret(k).unwrap();
                assert_eq!(&got.0, v, "mismatch for {k}");
            }
        }
    }
}
