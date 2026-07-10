/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, OpenFlags, params};
use sqlite_plugin::flags::{AccessFlags, LockLevel, OpenOpts};
use sqlite_plugin::vfs::{RegisterOpts, Vfs, VfsHandle, VfsResult, register_static};
use std::ffi::CString;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read as IoRead, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::{fs, iter};
use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyRingError;

// ─── Page constants ───────────────────────────────────────────────────────────

const LOGICAL_PAGE_SIZE: usize = 4096;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
/// Physical block on disk = [ciphertext(4096) | nonce(12) | tag(16)]
const PHYSICAL_PAGE_SIZE: usize = LOGICAL_PAGE_SIZE + NONCE_SIZE + TAG_SIZE; // 4124

static VFS_COUNTER: AtomicU32 = AtomicU32::new(0);

// ─── Cipher selection ─────────────────────────────────────────────────────────

/// Selects the AEAD algorithm used by [`EncryptedVfsKeyring`].
///
/// `Aes256Gcm` uses AES-NI hardware acceleration on x86/x86_64/AArch64 when
/// available; on hardware without AES-NI it falls back to a constant-time
/// software implementation that is slower than ChaCha20-Poly1305.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum CipherAlgorithm {
    #[default]
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl Zeroize for CipherAlgorithm {
    fn zeroize(&mut self) {
        *self = CipherAlgorithm::default();
    }
}

// Internal dispatch — one variant per algorithm.  Both use 12-byte nonces and
// 16-byte tags so the physical page layout is identical regardless of choice.
enum ActiveCipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<Aes256Gcm>),
}

impl ActiveCipher {
    fn from_key(alg: CipherAlgorithm, key: &[u8; 32]) -> Self {
        match alg {
            CipherAlgorithm::ChaCha20Poly1305 => Self::ChaCha(ChaCha20Poly1305::new(key.into())),
            CipherAlgorithm::Aes256Gcm => Self::Aes(Box::new(Aes256Gcm::new(key.into()))),
        }
    }

    fn encrypt_page(
        &self,
        page_no: u64,
        plaintext: &[u8; LOGICAL_PAGE_SIZE],
    ) -> io::Result<[u8; PHYSICAL_PAGE_SIZE]> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(e.to_string()))?;

        let nonce = chacha20poly1305::Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| io::Error::other("invalid nonce length"))?;
        let aad = page_no.to_le_bytes();

        let ct = match self {
            Self::ChaCha(c) => c.encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            ),
            Self::Aes(c) => c.encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            ),
        }
        .map_err(|_| io::Error::other("encryption failed"))?;

        // Layout: [ciphertext(4096) | nonce(12) | tag(16)]
        let mut block = [0u8; PHYSICAL_PAGE_SIZE];
        block[..LOGICAL_PAGE_SIZE].copy_from_slice(&ct[..LOGICAL_PAGE_SIZE]);
        block[LOGICAL_PAGE_SIZE..LOGICAL_PAGE_SIZE + NONCE_SIZE].copy_from_slice(&nonce_bytes);
        block[LOGICAL_PAGE_SIZE + NONCE_SIZE..].copy_from_slice(&ct[LOGICAL_PAGE_SIZE..]);
        Ok(block)
    }

    fn decrypt_page(
        &self,
        page_no: u64,
        block: &[u8; PHYSICAL_PAGE_SIZE],
    ) -> io::Result<[u8; LOGICAL_PAGE_SIZE]> {
        let ciphertext_part = &block[..LOGICAL_PAGE_SIZE];
        let nonce_bytes = &block[LOGICAL_PAGE_SIZE..LOGICAL_PAGE_SIZE + NONCE_SIZE];
        let tag = &block[LOGICAL_PAGE_SIZE + NONCE_SIZE..];

        let mut ct_with_tag = Vec::with_capacity(LOGICAL_PAGE_SIZE + TAG_SIZE);
        ct_with_tag.extend_from_slice(ciphertext_part);
        ct_with_tag.extend_from_slice(tag);

        let nonce = chacha20poly1305::Nonce::try_from(nonce_bytes)
            .map_err(|_| io::Error::other("invalid nonce length"))?;
        let aad = page_no.to_le_bytes();

        let pt = match self {
            Self::ChaCha(c) => c.decrypt(
                &nonce,
                Payload {
                    msg: &ct_with_tag,
                    aad: &aad,
                },
            ),
            Self::Aes(c) => c.decrypt(
                &nonce,
                Payload {
                    msg: &ct_with_tag,
                    aad: &aad,
                },
            ),
        }
        .map_err(|_| io::Error::other("decryption failed"))?;

        let mut result = [0u8; LOGICAL_PAGE_SIZE];
        result.copy_from_slice(&pt);
        Ok(result)
    }
}

// ─── VFS state ────────────────────────────────────────────────────────────────

struct VfsState {
    alg: CipherAlgorithm,
    cipher: ActiveCipher,
}

#[derive(Clone)]
pub(crate) struct EncryptedVfs {
    state: Arc<RwLock<VfsState>>,
}

impl EncryptedVfs {
    fn new(alg: CipherAlgorithm, key: &[u8; 32]) -> Self {
        Self {
            state: Arc::new(RwLock::new(VfsState {
                alg,
                cipher: ActiveCipher::from_key(alg, key),
            })),
        }
    }

    fn rotate_key(&self, alg: CipherAlgorithm, key: &[u8; 32]) -> Result<()> {
        let mut state = self.state.write().map_err(|_| KeyRingError::GeneralError {
            msg: "VFS state lock poisoned".to_string(),
        })?;
        state.alg = alg;
        state.cipher = ActiveCipher::from_key(alg, key);
        Ok(())
    }
}

// ─── File handle ──────────────────────────────────────────────────────────────

pub(crate) struct EncryptedHandle {
    file: File,
    delete_on_close: bool,
    path: Option<PathBuf>,
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
        let delete_on_close = opts.delete_on_close();

        let (file, canonical_path) = match path {
            Some(p) => {
                let pb = PathBuf::from(p);
                let mut opts = OpenOptions::new();
                opts.read(true).write(!is_readonly).create(!is_readonly);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let f = opts
                    .open(p)
                    .map_err(|_| sqlite_plugin::vars::SQLITE_CANTOPEN)?;
                (f, Some(pb))
            }
            None => {
                // Unpredictable name + O_EXCL (`create_new`) + 0600 defeats symlink
                // and pre-creation attacks on the shared temp directory.
                let mut rand = [0u8; 16];
                getrandom::fill(&mut rand).map_err(|_| sqlite_plugin::vars::SQLITE_CANTOPEN)?;
                let mut tmp = std::env::temp_dir();
                tmp.push(format!(
                    "cryptex-tmp-{}-{}-{}.db",
                    std::process::id(),
                    VFS_COUNTER.fetch_add(1, Ordering::Relaxed),
                    hex::encode(rand)
                ));
                let mut opts = OpenOptions::new();
                opts.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let f = opts
                    .open(&tmp)
                    .map_err(|_| sqlite_plugin::vars::SQLITE_CANTOPEN)?;
                (f, Some(tmp))
            }
        };

        Ok(EncryptedHandle {
            file,
            delete_on_close,
            path: canonical_path,
        })
    }

    fn close(&self, handle: Self::Handle) -> VfsResult<()> {
        if handle.delete_on_close
            && let Some(p) = &handle.path
        {
            let _ = fs::remove_file(p);
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
        let phys = handle
            .file
            .metadata()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_FSTAT)?
            .len() as usize;
        Ok((phys / PHYSICAL_PAGE_SIZE) * LOGICAL_PAGE_SIZE)
    }

    fn truncate(&self, handle: &mut Self::Handle, logical_size: usize) -> VfsResult<()> {
        let num_pages = logical_size.div_ceil(LOGICAL_PAGE_SIZE);
        handle
            .file
            .set_len((num_pages * PHYSICAL_PAGE_SIZE) as u64)
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_TRUNCATE)
    }

    fn read(&self, handle: &mut Self::Handle, offset: usize, data: &mut [u8]) -> VfsResult<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?;

        let mut bytes_read = 0usize;
        let mut remaining = data.len();
        let mut logical_off = offset;
        let mut buf_pos = 0usize;

        while remaining > 0 {
            let page_no = logical_off / LOGICAL_PAGE_SIZE;
            let intra = logical_off % LOGICAL_PAGE_SIZE;
            let take = remaining.min(LOGICAL_PAGE_SIZE - intra);

            let physical_offset = (page_no * PHYSICAL_PAGE_SIZE) as u64;
            let file_len = handle
                .file
                .metadata()
                .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?
                .len();

            if physical_offset >= file_len {
                data[buf_pos..buf_pos + take].fill(0);
            } else {
                let mut block = [0u8; PHYSICAL_PAGE_SIZE];
                handle
                    .file
                    .seek(SeekFrom::Start(physical_offset))
                    .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?;
                handle
                    .file
                    .read_exact(&mut block)
                    .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?;

                let plaintext = state
                    .cipher
                    .decrypt_page(page_no as u64, &block)
                    .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_READ)?;

                data[buf_pos..buf_pos + take].copy_from_slice(&plaintext[intra..intra + take]);
            }

            bytes_read += take;
            buf_pos += take;
            logical_off += take;
            remaining -= take;
        }

        Ok(bytes_read)
    }

    fn write(&self, handle: &mut Self::Handle, offset: usize, data: &[u8]) -> VfsResult<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;

        let mut bytes_written = 0usize;
        let mut remaining = data.len();
        let mut logical_off = offset;
        let mut buf_pos = 0usize;

        while remaining > 0 {
            let page_no = logical_off / LOGICAL_PAGE_SIZE;
            let intra = logical_off % LOGICAL_PAGE_SIZE;
            let take = remaining.min(LOGICAL_PAGE_SIZE - intra);

            let plaintext: [u8; LOGICAL_PAGE_SIZE] = if intra == 0 && take == LOGICAL_PAGE_SIZE {
                let mut p = [0u8; LOGICAL_PAGE_SIZE];
                p.copy_from_slice(&data[buf_pos..buf_pos + LOGICAL_PAGE_SIZE]);
                p
            } else {
                let physical_offset = (page_no * PHYSICAL_PAGE_SIZE) as u64;
                let file_len = handle
                    .file
                    .metadata()
                    .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?
                    .len();

                let mut p = [0u8; LOGICAL_PAGE_SIZE];
                if physical_offset < file_len {
                    let mut block = [0u8; PHYSICAL_PAGE_SIZE];
                    handle
                        .file
                        .seek(SeekFrom::Start(physical_offset))
                        .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;
                    handle
                        .file
                        .read_exact(&mut block)
                        .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;
                    p = state
                        .cipher
                        .decrypt_page(page_no as u64, &block)
                        .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;
                }
                p[intra..intra + take].copy_from_slice(&data[buf_pos..buf_pos + take]);
                p
            };

            let block = state
                .cipher
                .encrypt_page(page_no as u64, &plaintext)
                .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;

            let physical_offset = (page_no * PHYSICAL_PAGE_SIZE) as u64;
            handle
                .file
                .seek(SeekFrom::Start(physical_offset))
                .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;
            handle
                .file
                .write_all(&block)
                .map_err(|_| sqlite_plugin::vars::SQLITE_IOERR_WRITE)?;

            bytes_written += take;
            buf_pos += take;
            logical_off += take;
            remaining -= take;
        }

        Ok(bytes_written)
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
    let id = VFS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("cryptex-evfs-{}", id);
    let cname = CString::new(name.clone())
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

pub struct EncryptedVfsKeyring {
    conn: Connection,
    vfs: EncryptedVfs,
    db_path: PathBuf,
    /// Exclusive advisory lock on a sidecar file, held for the keyring's
    /// lifetime. Guarantees a single opener: the encrypted VFS performs no
    /// SQLite-level locking, so concurrent opens would otherwise corrupt the
    /// database. Released automatically when the keyring is dropped. A sidecar
    /// (not the db file) is locked so the lock survives `rekey`'s atomic rename.
    _lock: File,
}

unsafe impl Send for EncryptedVfsKeyring {}
unsafe impl Sync for EncryptedVfsKeyring {}

impl DynKeyRing for EncryptedVfsKeyring {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        let mut stmt = self.conn.prepare("SELECT value FROM secrets WHERE id=?")?;
        let val = stmt.query_row(params![id], |row| {
            let s: String = row.get(0)?;
            hex::decode(s).map_err(|_| rusqlite::Error::InvalidQuery)
        })?;
        Ok(KeyRingSecret(val))
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        let encoded = hex::encode(secret);
        let mut stmt = self.conn.prepare(
            "INSERT INTO secrets(id, value) VALUES(?, ?) \
             ON CONFLICT(id) DO UPDATE SET value=?",
        )?;
        stmt.execute(params![id, encoded.clone(), encoded])?;
        Ok(())
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        let mut stmt = self.conn.prepare("DELETE FROM secrets WHERE id=?")?;
        stmt.execute(params![id])?;
        Ok(())
    }
}

impl NewKeyRing for EncryptedVfsKeyring {
    fn new<S: AsRef<str>>(lock_key: S) -> Result<Self> {
        let connection = lock_key.as_ref().parse::<ConnectionParams>()?;
        Self::with_params(&connection, None)
    }
}

impl EncryptedVfsKeyring {
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let key_zeroizing = derive_key(connection)?;
        if key_zeroizing.len() != 32 {
            return Err(KeyRingError::GeneralError {
                msg: "derived key must be 32 bytes".to_string(),
            });
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_zeroizing);

        let vfs = EncryptedVfs::new(connection.cipher, &key_bytes);
        key_bytes.zeroize();

        let vfs_for_keyring = vfs.clone();
        let vfs_name = register_encrypted_vfs(vfs)?;
        let db_path = get_keyring_file(path)?;

        // Fail fast if another opener already holds the keyring, before touching
        // the database. The encrypted VFS does no SQLite-level locking.
        let lock = acquire_single_opener_lock(&db_path)?;

        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            &*vfs_name,
        )
        .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

        conn.query_row("SELECT COUNT(*) FROM `sqlite_master`;", params![], |_| {
            Ok(())
        })
        .map_err(|_| KeyRingError::AccessDenied {
            msg: "Invalid key or corrupted database".to_string(),
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS secrets \
             (id TEXT UNIQUE NOT NULL, value TEXT NOT NULL)",
            (),
        )
        .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

        Ok(Self {
            conn,
            vfs: vfs_for_keyring,
            db_path,
            _lock: lock,
        })
    }

    /// Re-encrypt the database with a new key (and optionally a different cipher).
    ///
    /// Writes to a temp file first, then atomically renames — original is
    /// untouched until the rename succeeds.
    pub fn rekey(&self, new_params: &ConnectionParams) -> Result<()> {
        let new_key_zeroizing = derive_key(new_params)?;
        if new_key_zeroizing.len() != 32 {
            return Err(KeyRingError::GeneralError {
                msg: "new key must be 32 bytes".to_string(),
            });
        }
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&new_key_zeroizing);
        let new_cipher = ActiveCipher::from_key(new_params.cipher, &new_key);

        let page_count: u32 = self
            .conn
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

        let tmp_path = self.db_path.with_extension("cryptex-rekey-tmp");
        let src = File::open(&self.db_path)
            .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
        let mut dst_opts = OpenOptions::new();
        dst_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            dst_opts.mode(0o600);
        }
        let mut dst = dst_opts
            .open(&tmp_path)
            .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

        let state = self
            .vfs
            .state
            .read()
            .map_err(|_| KeyRingError::GeneralError {
                msg: "VFS state lock poisoned".to_string(),
            })?;

        let mut src_block = [0u8; PHYSICAL_PAGE_SIZE];
        let mut src_seekable = src;

        for page_no in 0..page_count as u64 {
            let physical_offset = page_no * PHYSICAL_PAGE_SIZE as u64;

            src_seekable
                .seek(SeekFrom::Start(physical_offset))
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
            src_seekable
                .read_exact(&mut src_block)
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

            let plaintext = state
                .cipher
                .decrypt_page(page_no, &src_block)
                .map_err(|e| KeyRingError::GeneralError {
                    msg: format!("rekey decrypt page {}: {}", page_no, e),
                })?;

            let new_block = new_cipher.encrypt_page(page_no, &plaintext).map_err(|e| {
                KeyRingError::GeneralError {
                    msg: format!("rekey encrypt page {}: {}", page_no, e),
                }
            })?;

            dst.seek(SeekFrom::Start(physical_offset))
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
            dst.write_all(&new_block)
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
        }

        drop(state);

        dst.sync_all()
            .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
        drop(dst);

        fs::rename(&tmp_path, &self.db_path)
            .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;

        self.vfs.rotate_key(new_params.cipher, &new_key)?;
        new_key.zeroize();

        Ok(())
    }
}

// ─── Key derivation & path helpers ───────────────────────────────────────────

fn derive_key(params: &ConnectionParams) -> Result<Zeroizing<Vec<u8>>> {
    if params.key.is_empty() {
        let argon2_params = Argon2Params::new(
            params.memory,
            params.threads,
            params.parallel,
            Some(Argon2Params::DEFAULT_OUTPUT_LEN),
        )
        .map_err(|e| KeyRingError::GeneralError {
            msg: format!("invalid Argon2 parameters: {}", e),
        })?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        let mut okm = [0u8; 32];
        argon2
            .hash_password_into(&params.password, &params.salt, &mut okm)
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("Argon2 key derivation failed: {}", e),
            })?;
        let result = Zeroizing::new(okm.to_vec());
        okm.zeroize();
        Ok(result)
    } else {
        Ok(Zeroizing::new(params.key.to_vec()))
    }
}

/// Acquire an exclusive advisory lock guaranteeing a single opener of the
/// keyring. A sidecar `<db>.lock` file is locked (not the database itself) so
/// the lock is unaffected by `rekey`'s atomic rename of the database file. The
/// returned handle must be kept alive for the keyring's lifetime; the OS
/// releases the lock when the handle is dropped or the process exits, so a
/// crashed process never leaves a stale lock behind.
fn acquire_single_opener_lock(db_path: &Path) -> Result<File> {
    let mut lock_path = db_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(&lock_path)
        .map_err(|e| KeyRingError::GeneralError {
            msg: format!(
                "unable to open keyring lock file {}: {}",
                lock_path.display(),
                e
            ),
        })?;

    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(KeyRingError::AccessDenied {
            msg: "keyring is already open by another process".to_string(),
        }),
        Err(TryLockError::Error(e)) => Err(KeyRingError::GeneralError {
            msg: format!("unable to lock keyring: {}", e),
        }),
    }
}

fn get_keyring_file(in_path: Option<PathBuf>) -> Result<PathBuf> {
    let mut path = match in_path {
        None => {
            let mut p = dirs::home_dir().unwrap_or_else(|| {
                dirs::document_dir().unwrap_or_else(|| {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
                })
            });
            p.push(format!(".{}", env!("CARGO_PKG_NAME")));
            p
        }
        Some(p) => p,
    };

    if !path.is_dir() {
        fs::create_dir_all(&path).map_err(|e| KeyRingError::GeneralError {
            msg: format!("unable to create folder {}: {}", path.display(), e),
        })?;
    }
    secure_dir(&path)?;
    make_hidden(&path);
    path.push("keyring.db3");
    Ok(path)
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
        KeyRingError::GeneralError {
            msg: format!("unable to secure folder {}: {}", path.display(), e),
        }
    })
}

#[cfg(not(unix))]
fn secure_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn make_hidden(path: &Path) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

    unsafe extern "system" {
        fn SetFileAttributesW(lpfilename: *const u16, dwfileattributes: u32) -> i32;
    }

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    unsafe {
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN);
    }
}

#[cfg(not(target_os = "windows"))]
fn make_hidden(_path: &Path) {}

// ─── ConnectionParams ─────────────────────────────────────────────────────────

/// Connection parameters for [`EncryptedVfsKeyring`].
///
/// Accepted format:
/// ```text
/// password=mysecret salt=0okm9ijn8uhb7ygv [cipher=chacha20poly1305|aes256gcm]
/// ```
pub struct ConnectionParams {
    pub key: Vec<u8>,
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    /// The Argon2 memory cost in KiB blocks.
    pub memory: u32,
    pub threads: u32,
    pub parallel: u32,
    /// Cipher algorithm — default is `ChaCha20Poly1305`.
    pub cipher: CipherAlgorithm,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        let m_cost = default_memory_cost();
        let threads = default_threads();
        let parallel = default_parallel();
        Self {
            key: vec![],
            password: vec![],
            salt: vec![],
            memory: m_cost,
            threads,
            parallel,
            cipher: CipherAlgorithm::default(),
        }
    }
}

impl Drop for ConnectionParams {
    fn drop(&mut self) {
        self.key.zeroize();
        self.password.zeroize();
        self.salt.zeroize();
    }
}

impl FromStr for ConnectionParams {
    type Err = KeyRingError;

    fn from_str(s: &str) -> Result<Self> {
        Parser::parse(s)
    }
}

impl ConnectionParams {
    fn param(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "key" => {
                self.key = hex::decode(value).map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid hex key: {}", e),
                })?
            }
            "password" => self.password = value.as_bytes().to_vec(),
            "salt" => self.salt = value.as_bytes().to_vec(),
            "cipher" => {
                self.cipher = match value {
                    "chacha20poly1305" | "chacha20" => CipherAlgorithm::ChaCha20Poly1305,
                    "aes256gcm" | "aes" => CipherAlgorithm::Aes256Gcm,
                    other => {
                        return Err(KeyRingError::GeneralError {
                            msg: format!(
                                "unknown cipher '{}'; use chacha20poly1305 or aes256gcm",
                                other
                            ),
                        });
                    }
                };
            }
            "memory" => {
                let m = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected integer for memory: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_M_COST..Argon2Params::MAX_M_COST).contains(&m) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "memory must be between {} and {}",
                            Argon2Params::DEFAULT_M_COST,
                            Argon2Params::MAX_M_COST
                        ),
                    });
                }
                self.memory = m;
            }
            "threads" => {
                let t = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected integer for threads: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_T_COST..Argon2Params::MAX_T_COST).contains(&t) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "threads must be between {} and {}",
                            Argon2Params::DEFAULT_T_COST,
                            Argon2Params::MAX_T_COST
                        ),
                    });
                }
                self.threads = t;
            }
            "parallel" => {
                let p = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected integer for parallel: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_P_COST..Argon2Params::MAX_P_COST).contains(&p) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "parallel must be between {} and {}",
                            Argon2Params::DEFAULT_P_COST,
                            Argon2Params::MAX_P_COST
                        ),
                    });
                }
                self.parallel = p;
            }
            _ => {
                return Err(KeyRingError::GeneralError {
                    msg: format!("unknown parameter: {}", key),
                });
            }
        };
        Ok(())
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

struct Parser<'a> {
    s: &'a str,
    it: iter::Peekable<std::str::CharIndices<'a>>,
}

impl<'a> Parser<'a> {
    fn parse(s: &'a str) -> Result<ConnectionParams> {
        let mut parser = Parser {
            s,
            it: s.char_indices().peekable(),
        };
        let mut params = ConnectionParams::default();
        while let Some((key, value)) = parser.parameter()? {
            params.param(key, &value)?;
        }
        Ok(params)
    }

    fn skip_ws(&mut self) {
        self.take_while(char::is_whitespace);
    }

    fn take_while<F>(&mut self, f: F) -> &'a str
    where
        F: Fn(char) -> bool,
    {
        let start = match self.it.peek() {
            Some(&(i, _)) => i,
            None => return "",
        };
        loop {
            match self.it.peek() {
                Some(&(_, c)) if f(c) => {
                    self.it.next();
                }
                Some(&(i, _)) => return &self.s[start..i],
                None => return &self.s[start..],
            }
        }
    }

    fn consume(&mut self, target: char) -> Result<()> {
        match self.it.next() {
            Some((_, c)) if c == target => Ok(()),
            Some((i, c)) => Err(KeyRingError::GeneralError {
                msg: format!(
                    "unexpected char at byte {}: expected `{}` but got `{}`",
                    i, target, c
                ),
            }),
            None => Err(KeyRingError::GeneralError {
                msg: "unexpected EOF".to_string(),
            }),
        }
    }

    fn consume_if(&mut self, target: char) -> bool {
        match self.it.peek() {
            Some(&(_, c)) if c == target => {
                self.it.next();
                true
            }
            _ => false,
        }
    }

    fn keyword(&mut self) -> Option<&'a str> {
        let s = self.take_while(|c| !c.is_whitespace() && c != '=');
        if s.is_empty() { None } else { Some(s) }
    }

    fn value(&mut self) -> Result<String> {
        if self.consume_if('\'') {
            let v = self.quoted_value()?;
            self.consume('\'')?;
            Ok(v)
        } else {
            self.simple_value()
        }
    }

    fn simple_value(&mut self) -> Result<String> {
        let mut value = String::new();
        while let Some(&(_, c)) = self.it.peek() {
            if c.is_whitespace() {
                break;
            }
            self.it.next();
            if c == '\\' {
                if let Some((_, c2)) = self.it.next() {
                    value.push(c2);
                }
            } else {
                value.push(c);
            }
        }
        if value.is_empty() {
            return Err(KeyRingError::GeneralError {
                msg: "unexpected EOF".to_string(),
            });
        }
        Ok(value)
    }

    fn quoted_value(&mut self) -> Result<String> {
        let mut value = String::new();
        while let Some(&(_, c)) = self.it.peek() {
            if c == '\'' {
                return Ok(value);
            }
            self.it.next();
            if c == '\\' {
                if let Some((_, c2)) = self.it.next() {
                    value.push(c2);
                }
            } else {
                value.push(c);
            }
        }
        Err(KeyRingError::GeneralError {
            msg: "unterminated quoted connection parameter value".to_string(),
        })
    }

    fn parameter(&mut self) -> Result<Option<(&'a str, String)>> {
        self.skip_ws();
        let keyword = match self.keyword() {
            Some(k) => k,
            None => return Ok(None),
        };
        self.skip_ws();
        self.consume('=')?;
        self.skip_ws();
        let value = self.value()?;
        Ok(Some((keyword, value)))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{CipherAlgorithm, ConnectionParams, EncryptedVfsKeyring};
    use crate::KeyRing;
    use std::fs;
    use std::path::PathBuf;

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    #[test]
    fn works() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-works");
        let _ = fs::remove_dir_all(&path);

        let p = params("password=works_test salt=1qaz2wsx3edc4rfv5tgb");

        {
            let res = EncryptedVfsKeyring::with_params(&p, Some(path.clone()));
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
            let mut kr = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();
            let got = kr.get_secret("persist").unwrap();
            assert_eq!(got.0, b"persisted");
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn concurrent_open_is_rejected() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-concurrent");
        let _ = fs::remove_dir_all(&path);

        let p = params("password=concurrent_test salt=1qaz2wsx3edc4rfv5tgb");

        let first = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();

        // A second opener must be rejected while the first is alive.
        let second = EncryptedVfsKeyring::with_params(&p, Some(path.clone()));
        assert!(
            matches!(second, Err(crate::error::KeyRingError::AccessDenied { .. })),
            "expected AccessDenied for concurrent open, got: {:?}",
            second.err()
        );

        // After the first is dropped, the lock releases and reopening succeeds.
        drop(first);
        let reopened = EncryptedVfsKeyring::with_params(&p, Some(path.clone()));
        assert!(
            reopened.is_ok(),
            "reopen after drop failed: {:?}",
            reopened.err()
        );

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn wrong_key_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-wrongkey");
        let _ = fs::remove_dir_all(&path);

        let correct = params("password=correct_password salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=wrong_password salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = EncryptedVfsKeyring::with_params(&correct, Some(path.clone())).unwrap();
            kr.set_secret("x", b"secret").unwrap();
        }

        {
            let result = EncryptedVfsKeyring::with_params(&wrong, Some(path.clone()));
            assert!(result.is_err(), "expected error with wrong key");
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn invalid_hex_key_is_an_error() {
        let result = "key=not-hex".parse::<ConnectionParams>();
        assert!(result.is_err());
    }

    #[test]
    fn rekey_works() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-rekey");
        let _ = fs::remove_dir_all(&path);

        let old_params = params("password=old_pass salt=old_salt_value_here_");
        let new_params = params("password=new_pass salt=new_salt_value_here_");

        {
            let mut kr = EncryptedVfsKeyring::with_params(&old_params, Some(path.clone())).unwrap();
            kr.set_secret("data", b"important").unwrap();
            kr.rekey(&new_params).unwrap();
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&new_params, Some(path.clone())).unwrap();
            assert_eq!(kr.get_secret("data").unwrap().0, b"important");
        }

        {
            let result = EncryptedVfsKeyring::with_params(&old_params, Some(path.clone()));
            assert!(result.is_err(), "old key should fail after rekey");
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn bulk_insert_and_retrieve() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-bulk");
        let _ = fs::remove_dir_all(&path);

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
            let mut kr = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();
            for (k, v) in &entries {
                kr.set_secret(k, v).unwrap();
            }
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();
            for (k, v) in &entries {
                let got = kr.get_secret(k).unwrap();
                assert_eq!(&got.0, v, "mismatch for {k}");
            }
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn aes_bulk_insert_and_retrieve() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-evfs-aes-bulk");
        let _ = fs::remove_dir_all(&path);

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
            let mut kr = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();
            for (k, v) in &entries {
                kr.set_secret(k, v).unwrap();
            }
        }

        {
            let mut kr = EncryptedVfsKeyring::with_params(&p, Some(path.clone())).unwrap();
            for (k, v) in &entries {
                let got = kr.get_secret(k).unwrap();
                assert_eq!(&got.0, v, "mismatch for {k}");
            }
        }

        let _ = fs::remove_dir_all(&path);
    }
}
