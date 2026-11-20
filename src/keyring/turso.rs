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
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use super::file_common::{self, CipherParam, derive_key_32, file_keyring, secure_file};
#[cfg(feature = "opfs")]
use super::opfs::OpfsIo;
use super::turso_common::TursoFile;
use super::turso_web::{WebIo, unique_db_path};
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

/// Turso's builder, re-exported so callers construct matching types.
pub use ::turso::Builder as TursoBuilder;
/// The Turso connection type a keyring can adopt.
///
/// Use the `turso` crate cryptex was built against (the same version as
/// [`Builder`]), or a type mismatch will result.
pub use ::turso::Connection;
/// Turso's low-level crate, for implementing a custom `IO` such as OPFS.
pub use ::turso::core;

/// A keyring stored in a Turso database encrypted with Turso's native page
/// encryption. The default file is `~/.cryptex/keyring-turso.db3`.
///
/// Turso keeps its own copy of the hex-encoded key for the life of the
/// database; cryptex zeroizes only the copies it owns.
///
/// Three ways to get one:
/// - [`with_params`](Self::with_params) opens the file itself, as before.
/// - [`from_connection`](Self::from_connection) adopts a connection the caller
///   already opened, so key storage and application tables can share one
///   database and one key.
/// - [`with_io`](Self::with_io) opens through a caller-supplied Turso `IO`,
///   such as the Origin Private File System in a browser worker.
pub struct TursoKeyring {
    file: TursoFile,
    /// Set on keyrings whose database lives in memory, so it can be copied out.
    web: Option<Arc<WebIo>>,
}

file_keyring!(TursoKeyring, file);

impl TursoKeyring {
    /// Open (or create) the keyring in `path` (default `~/.cryptex`).
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let file = TursoFile::open(path, builder(connection)?)?;
        if let Some(db_path) = file.db_path() {
            secure_file(db_path)?;
        }
        Ok(Self { file, web: None })
    }

    /// Adopt an already-open Turso connection.
    ///
    /// The keyring creates and owns its `secrets` table and uses the
    /// connection as given, so an application can keep its own tables in the
    /// same database and share one key derivation. Nothing about the
    /// connection is reconfigured: encryption, IO and the clock are the
    /// caller's.
    ///
    /// The caller is responsible for opening the database with the right key
    /// and, in a browser, for holding the single-writer storage handle.
    ///
    /// [`rekey`](Self::rekey) is not available on an adopted keyring because
    /// cryptex does not own the storage; copy the secrets into a new keyring
    /// instead.
    ///
    /// ```no_run
    /// # use cryptex::turso::{TursoKeyring, TursoBuilder};
    /// # async fn example(conn: cryptex::turso::Connection) -> Result<(), Box<dyn std::error::Error>> {
    /// // The caller opened the database, e.g. with its own IO and encryption.
    /// let mut keyring = TursoKeyring::from_connection(conn)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_connection(conn: Connection) -> Result<Self> {
        Ok(Self {
            file: TursoFile::adopt(conn)?,
            web: None,
        })
    }

    /// Open (or create) the keyring through a caller-supplied Turso `IO`.
    ///
    /// `io` supplies every page: for example an OPFS-backed `IO` in a browser
    /// worker. `path` is the database path passed to that IO. The key is
    /// derived from `params` and applied with Turso's native page encryption,
    /// exactly as [`with_params`](Self::with_params) does.
    ///
    /// No lock file is created and [`rekey`](Self::rekey) is unavailable; the
    /// caller owns single-writer access, which for OPFS means holding the one
    /// sync access handle for the database.
    pub fn with_io(io: Arc<dyn core::IO>, path: &str, params: &ConnectionParams) -> Result<Self> {
        Ok(Self {
            file: TursoFile::open_with(builder(params)?(path).with_io_impl(io))?,
            web: None,
        })
    }

    /// Open a keyring whose database lives in process memory.
    ///
    /// Nothing reaches the filesystem, so this works in a browser. Copy the
    /// database out with [`export`](Self::export) to persist it and reopen
    /// with [`from_bytes`](Self::from_bytes).
    pub fn in_memory(params: &ConnectionParams) -> Result<Self> {
        let io = WebIo::in_memory();
        let path = unique_db_path();
        Self::open_web(Arc::clone(&io), &path, params).map(|k| Self { web: Some(io), ..k })
    }

    /// Reopen a keyring from an image produced by [`export`](Self::export).
    pub fn from_bytes(bytes: &[u8], params: &ConnectionParams) -> Result<Self> {
        let io = WebIo::restore(bytes)?;
        // The image remembers the path it was written under; Turso keys open
        // databases by path, so it has to be opened as that path.
        let path = io.db_path().ok_or_else(|| KeyRingError::AccessDenied {
            msg: "Invalid key or corrupted keyring image".to_string(),
        })?;
        Self::open_web(Arc::clone(&io), &path, params).map(|k| Self { web: Some(io), ..k })
    }

    fn open_web(io: Arc<WebIo>, path: &str, params: &ConnectionParams) -> Result<Self> {
        let io: Arc<dyn core::IO> = io;
        // The image was already parsed, so the only thing left that can refuse
        // the open is the key: an image written under another key looks like a
        // corrupt one. Report both the way [`MemoryKeyring::import`] does.
        Self::with_io(io, path, params).map_err(|_| KeyRingError::AccessDenied {
            msg: "Invalid key or corrupted keyring image".to_string(),
        })
    }

    /// Open (or create) the keyring in the origin private file system.
    ///
    /// Only available in a browser worker: OPFS sync access handles exist
    /// nowhere else. The database and its WAL live under `cryptex/<name>.db3`.
    #[cfg(feature = "opfs")]
    pub async fn open_opfs(params: &ConnectionParams, name: &str) -> Result<Self> {
        let io: Arc<dyn core::IO> = Arc::new(OpfsIo::open(name).await?);
        let keyring = Self::with_io(io, &format!("{name}.db3"), params)?;
        Ok(keyring)
    }

    /// Copy every secret into a new in-memory keyring under `params`.
    ///
    /// The caller's keyring is left untouched, so a failed rekey changes
    /// nothing. This is how a keyring without a file of its own is rekeyed.
    pub fn copy_under(&self, params: &ConnectionParams) -> Result<Self> {
        let io = WebIo::in_memory();
        let path = unique_db_path();
        let mut copy = Self::open_web(Arc::clone(&io), &path, params)?;
        copy.web = Some(io);
        self.file.copy_into(&copy.file)?;
        Ok(copy)
    }

    /// Copy the whole in-memory database into one encrypted blob.
    ///
    /// Fails for a keyring opened from a path or from a caller's connection:
    /// the caller owns that storage, so it owns copying it.
    pub fn export(&self) -> Result<Vec<u8>> {
        self.web
            .as_ref()
            .ok_or_else(|| KeyRingError::GeneralError {
                msg: "export is only available for an in-memory keyring".to_string(),
            })?
            .snapshot()
    }

    /// Every id in the keyring, in order.
    pub fn keys(&self) -> Result<Vec<String>> {
        self.file.ids()
    }

    /// Re-encrypt the keyring with a new key (and optionally a different cipher).
    ///
    /// Consumes the keyring and returns it reopened under `new_params`. If
    /// rekeying fails the original file is left intact and can be reopened
    /// with the old parameters.
    pub fn rekey(self, new_params: &ConnectionParams) -> Result<Self> {
        let file = self.file.rekey(builder(new_params)?)?;
        if let Some(db_path) = file.db_path() {
            secure_file(db_path)?;
        }
        Ok(Self { file, web: None })
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
    use crate::keyring::turso_common::block_on;
    use std::fs;
    use std::sync::Arc;

    fn params(s: &str) -> ConnectionParams {
        s.parse().unwrap()
    }

    /// Rewrite a snapshot so its files sit under `base`, as two sessions do
    /// when each names its first keyring the same thing.
    fn with_paths(image: &[u8], base: &str) -> Vec<u8> {
        let count = u32::from_le_bytes(image[11..15].try_into().unwrap());
        let mut rest = &image[15..];
        let mut out = image[..15].to_vec();
        for _ in 0..count {
            let path_len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            let path = std::str::from_utf8(&rest[..path_len]).unwrap();
            rest = &rest[path_len..];
            let data_len = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
            let data = &rest[8..8 + data_len];
            rest = &rest[8 + data_len..];

            let path = if path.ends_with("-wal") {
                format!("{base}-wal")
            } else {
                base.to_string()
            };
            out.extend_from_slice(&(path.len() as u32).to_le_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(&(data_len as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
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
    fn in_memory_round_trips_through_an_image() {
        let p = params("password=in_memory salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=nope salt=1qaz2wsx3edc4rfv5tgb");

        let image = {
            let mut kr = TursoKeyring::in_memory(&p).unwrap();
            kr.set_secret("k1", b"value1").unwrap();
            kr.set_secret("shared", b"kept").unwrap();
            let image = kr.export().unwrap();
            assert!(!image.windows(6).any(|w| w == b"value1"));
            image
        };

        let mut restored = TursoKeyring::from_bytes(&image, &p).unwrap();
        assert_eq!(restored.get_secret("k1").unwrap().0, b"value1");
        assert_eq!(restored.get_secret("shared").unwrap().0, b"kept");
        assert_eq!(restored.keys().unwrap(), ["k1", "shared"]);

        assert!(matches!(
            TursoKeyring::from_bytes(&image, &wrong),
            Err(KeyRingError::AccessDenied { .. })
        ));
        assert!(TursoKeyring::from_bytes(b"not a snapshot", &p).is_err());
    }

    #[test]
    fn a_snapshot_claiming_huge_counts_is_refused() {
        use crate::keyring::turso_web::WebIo;

        // Fifteen bytes used to size a HashMap from an unauthenticated count
        // and abort the process on allocation failure.
        let mut blob = b"CRYPTEX-IO".to_vec();
        blob.push(1);
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(WebIo::restore(&blob).is_err());

        // A count of two with no entries is malformed, not a panic.
        let mut blob = b"CRYPTEX-IO".to_vec();
        blob.push(1);
        blob.extend_from_slice(&2u32.to_le_bytes());
        assert!(WebIo::restore(&blob).is_err());
    }

    #[test]
    fn two_ios_never_share_a_file_id() {
        use crate::keyring::turso_web::WebIo;
        use ::turso::core::IO;

        // Turso looks open databases up by `file_id`. Two IOs holding the same
        // path - an OPFS keyring named `cryptex-1` and an in-memory image - must
        // not resolve to one database, or one keyring writes into the other.
        let a = WebIo::in_memory();
        let b = WebIo::in_memory();
        assert_ne!(
            a.file_id("cryptex-1.db3").unwrap(),
            b.file_id("cryptex-1.db3").unwrap()
        );
        assert_eq!(
            a.file_id("cryptex-1.db3").unwrap(),
            a.file_id("cryptex-1.db3").unwrap()
        );
    }

    #[test]
    fn restored_images_do_not_reuse_the_recorded_path() {
        // Turso keys its open databases by `file_id`, so two images recorded
        // under one path used to share one open database: the second keyring
        // read the first one's secrets and wrote into it.
        let p = params("password=collide salt=1qaz2wsx3edc4rfv5tgb");

        let mut first = TursoKeyring::in_memory(&p).unwrap();
        first.set_secret("first", b"one").unwrap();
        let image_a = first.export().unwrap();

        let mut second = TursoKeyring::in_memory(&p).unwrap();
        second.set_secret("second", b"two").unwrap();
        let image_b = second.export().unwrap();

        // Both images claim the same database path, as two page loads would
        // when each named its first keyring the same thing.
        let mut a = TursoKeyring::from_bytes(&with_paths(&image_a, "shared.db3"), &p).unwrap();
        let mut b = TursoKeyring::from_bytes(&with_paths(&image_b, "shared.db3"), &p).unwrap();

        assert_eq!(a.get_secret("first").unwrap().0, b"one");
        assert_eq!(b.get_secret("second").unwrap().0, b"two");
        assert!(matches!(
            b.get_secret("first"),
            Err(KeyRingError::ItemNotFound)
        ));

        // A write for one must not land in the other.
        b.set_secret("later", b"kept").unwrap();
        assert!(matches!(
            a.get_secret("later"),
            Err(KeyRingError::ItemNotFound)
        ));
    }

    #[test]
    fn copy_under_rekeys_without_touching_the_original() {
        let a = params("password=first salt=1qaz2wsx3edc4rfv5tgb");
        let b = params("password=second salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=third salt=1qaz2wsx3edc4rfv5tgb");

        let mut original = TursoKeyring::in_memory(&a).unwrap();
        original.set_secret("k1", b"value1").unwrap();

        let copy = original.copy_under(&b).unwrap();
        let image = copy.export().unwrap();

        let mut reopened = TursoKeyring::from_bytes(&image, &b).unwrap();
        assert_eq!(reopened.get_secret("k1").unwrap().0, b"value1");
        assert!(TursoKeyring::from_bytes(&image, &wrong).is_err());

        // The original still opens with its own key.
        assert_eq!(original.get_secret("k1").unwrap().0, b"value1");
    }

    #[test]
    fn export_needs_an_in_memory_keyring() {
        let dir = TestDir::new(".test-turso-export");
        let p = params("password=export_test salt=1qaz2wsx3edc4rfv5tgb");
        let kr = TursoKeyring::with_params(&p, dir.keyring_dir()).unwrap();
        assert!(kr.export().is_err());
    }

    #[test]
    fn wrong_key_and_concurrent_open_fail() {
        let dir = TestDir::new(".test-turso-wrongkey");
        let correct = params("password=correct_password salt=1qaz2wsx3edc4rfv5tgb");
        let wrong = params("password=wrong_password salt=1qaz2wsx3edc4rfv5tgb");

        {
            let mut kr = TursoKeyring::with_params(&correct, dir.keyring_dir()).unwrap();
            kr.set_secret("x", b"secret").unwrap();
            // WASI has no file locking, so a second opener is not refused
            // there; callers keep a single writer instead.
            #[cfg(not(target_os = "wasi"))]
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

    /// A connection opened by the caller, as a browser worker would.
    fn caller_connection(
        path: std::path::PathBuf,
        params: &ConnectionParams,
    ) -> ::turso::Connection {
        let hexkey = hex::encode(*crate::file_common::derive_key_32(params).unwrap());
        let db = block_on::<_, _, KeyRingError>(async {
            ::turso::Builder::new_local(path.to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(::turso::EncryptionOpts {
                    cipher: params.cipher.as_turso_name().to_string(),
                    hexkey,
                })
                .build()
                .await
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })
        })
        .unwrap();
        db.connect().unwrap()
    }

    #[test]
    fn adopts_an_existing_connection() {
        let dir = TestDir::new(".test-turso-from-connection");
        let p = params("password=adopt_pass salt=1qaz2wsx3edc4rfv5tgb");
        fs::create_dir_all(&*dir).unwrap();
        let conn = caller_connection(dir.join("shared.db3"), &p);

        // The application owns its own table on the same connection.
        block_on(conn.execute("CREATE TABLE audit (event TEXT NOT NULL)", ())).unwrap();

        {
            let mut kr = TursoKeyring::from_connection(conn.clone()).unwrap();
            kr.set_secret("k1", b"value1").unwrap();
            kr.set_secret("k2", b"value2").unwrap();
            assert_eq!(kr.get_secret("k1").unwrap().0, b"value1");
            kr.delete_secret("k2").unwrap();
            assert!(matches!(
                kr.get_secret("k2"),
                Err(KeyRingError::ItemNotFound)
            ));
        }

        // Reopening through another connection to the same file sees the data,
        // and the application table survived.
        let mut kr =
            TursoKeyring::from_connection(caller_connection(dir.join("shared.db3"), &p)).unwrap();
        assert_eq!(kr.get_secret("k1").unwrap().0, b"value1");

        let mut rows = block_on(conn.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
            (),
        ))
        .unwrap();
        let mut tables = Vec::new();
        while let Some(row) = block_on(rows.next()).unwrap() {
            tables.push(row.get::<String>(0).unwrap());
        }
        assert_eq!(tables, vec!["audit", "secrets"]);
    }

    #[test]
    fn adopted_keyring_cannot_rekey() {
        let dir = TestDir::new(".test-turso-adopt-rekey");
        let p = params("password=adopt_pass salt=1qaz2wsx3edc4rfv5tgb");
        fs::create_dir_all(&*dir).unwrap();
        let kr =
            TursoKeyring::from_connection(caller_connection(dir.join("shared.db3"), &p)).unwrap();
        assert!(kr.rekey(&p).is_err());
    }

    #[test]
    fn opens_through_a_custom_io() {
        // A caller-supplied IO stands in for OPFS in a browser worker.
        let io = Arc::new(::turso::core::MemoryIO::new());
        let p = params("password=io_pass salt=1qaz2wsx3edc4rfv5tgb");
        let db_name = "keyring.db3";

        {
            let mut kr = TursoKeyring::with_io(io.clone(), db_name, &p).unwrap();
            kr.set_secret("k1", b"value1").unwrap();
        }

        {
            let mut kr = TursoKeyring::with_io(io.clone(), db_name, &p).unwrap();
            assert_eq!(kr.get_secret("k1").unwrap().0, b"value1");
        }

        // A different key on the same pages is refused.
        let wrong = params("password=wrong_pass salt=1qaz2wsx3edc4rfv5tgb");
        assert!(TursoKeyring::with_io(io, db_name, &wrong).is_err());
    }
}
