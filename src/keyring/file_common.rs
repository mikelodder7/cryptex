/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Pieces shared by every file-backed keyring: connection-string parsing,
//! Argon2id key derivation, and keyring file/directory helpers.

use super::*;
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};

use crate::error::KeyRingError;
#[cfg(any(
    feature = "encrypted-vfs",
    feature = "turso",
    feature = "turso-encrypted-io"
))]
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, iter};
use zeroize::{Zeroize, Zeroizing};

// SQL shared by every file-backed keyring. Numbered parameters and
// `excluded.value` work with both SQLite and Turso.
pub(crate) const VERIFY_KEY_SQL: &str = "SELECT COUNT(*) FROM sqlite_master";
pub(crate) const CREATE_SECRETS_SQL: &str =
    "CREATE TABLE IF NOT EXISTS secrets (id TEXT UNIQUE NOT NULL, value TEXT NOT NULL)";
pub(crate) const SELECT_SECRET_SQL: &str = "SELECT value FROM secrets WHERE id = ?1";
pub(crate) const UPSERT_SECRET_SQL: &str = "INSERT INTO secrets(id, value) VALUES(?1, ?2) \
     ON CONFLICT(id) DO UPDATE SET value = excluded.value";
pub(crate) const DELETE_SECRET_SQL: &str = "DELETE FROM secrets WHERE id = ?1";

/// Storage behind a file-backed keyring. Secrets are stored hex-encoded.
pub(crate) trait SecretStore {
    /// Fetch the secret stored under `id`.
    fn get(&self, id: &str) -> Result<KeyRingSecret>;
    /// Insert or replace the secret stored under `id`.
    fn set(&self, id: &str, secret: &[u8]) -> Result<()>;
    /// Remove the secret stored under `id`, if any.
    fn delete(&self, id: &str) -> Result<()>;
}

/// Decode a stored hex value, or report [`KeyRingError::ItemNotFound`].
pub(crate) fn decode_secret(value: Option<Zeroizing<String>>) -> Result<KeyRingSecret> {
    let value = value.ok_or(KeyRingError::ItemNotFound)?;
    hex::decode(value.as_str())
        .map(KeyRingSecret)
        .map_err(|e| KeyRingError::GeneralError {
            msg: format!("corrupt secret encoding: {}", e),
        })
}

/// The error for a database the derived key cannot read.
pub(crate) fn invalid_key() -> KeyRingError {
    KeyRingError::AccessDenied {
        msg: "Invalid key or corrupted database".to_string(),
    }
}

/// Implements [`DynKeyRing`] by delegating to the [`SecretStore`] in field
/// `$store`, and [`NewKeyRing`] by parsing the calling module's
/// `ConnectionParams` and calling `with_params(&params, None)`.
macro_rules! file_keyring {
    ($keyring:ty, $store:ident) => {
        impl $crate::DynKeyRing for $keyring {
            fn get_secret(&mut self, id: &str) -> $crate::Result<$crate::KeyRingSecret> {
                $crate::file_common::SecretStore::get(&self.$store, id)
            }

            fn set_secret(&mut self, id: &str, secret: &[u8]) -> $crate::Result<()> {
                $crate::file_common::SecretStore::set(&self.$store, id, secret)
            }

            fn delete_secret(&mut self, id: &str) -> $crate::Result<()> {
                $crate::file_common::SecretStore::delete(&self.$store, id)
            }
        }

        impl $crate::NewKeyRing for $keyring {
            fn new<S: AsRef<str>>(lock_key: S) -> $crate::Result<Self> {
                let params = lock_key.as_ref().parse::<ConnectionParams>()?;
                Self::with_params(&params, None)
            }
        }
    };
}
pub(crate) use file_keyring;

/// A cipher choice that can be set with `cipher=<name>` in a connection string.
pub trait CipherParam: Copy + Default + Zeroize {
    /// Parse the value of a `cipher=` connection parameter.
    fn parse(value: &str) -> Result<Self>;
}

/// Placeholder cipher for keyrings whose cipher is not configurable.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct NoCipher;

impl CipherParam for NoCipher {
    fn parse(_value: &str) -> Result<Self> {
        Err(KeyRingError::GeneralError {
            msg: "cipher is not configurable for this keyring".to_string(),
        })
    }
}

/// The connection params for file-backed keyrings
///
/// [`ConnectionParams`] supports passing the values as a string
/// similar to postgres.
///
/// ```
/// use cryptex::sqlcipher::ConnectionParams;
///
/// let params = "password=1qaz2wsx3edc4rfv salt=0okm9ijn8uhb7ygv".parse::<ConnectionParams>().unwrap();
/// ```
///
/// or with extra parameters. `memory` is Argon2's memory cost in KiB blocks.
///
/// ```
/// use cryptex::sqlcipher::ConnectionParams;
///
/// let params = "password=1qaz2wsx3edc4rfv salt=0okm9ijn8uhb7ygv memory=32768 threads=3 parallel=2".parse::<ConnectionParams>().unwrap();
/// ```
#[derive(Zeroize)]
pub struct ConnectionParams<C: CipherParam = NoCipher> {
    /// The key used to open the keyring. This is used mutually exclusive
    /// with password and salt
    pub key: Vec<u8>,
    /// The password to use to open the keyring
    pub password: Vec<u8>,
    /// The salt to use when hashing the password
    pub salt: Vec<u8>,
    /// The Argon2 memory cost in KiB blocks
    pub memory: u32,
    /// The number of iterations or threads requirement
    pub threads: u32,
    /// The parallel requirement
    pub parallel: u32,
    /// The cipher used to encrypt the keyring, if the keyring supports a choice
    pub cipher: C,
}

impl<C: CipherParam> Default for ConnectionParams<C> {
    fn default() -> Self {
        Self {
            key: vec![],
            password: vec![],
            salt: vec![],
            memory: default_memory_cost(),
            threads: default_threads(),
            parallel: default_parallel(),
            cipher: C::default(),
        }
    }
}

impl<C: CipherParam> Drop for ConnectionParams<C> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.password.zeroize();
        self.salt.zeroize();
    }
}

impl<C: CipherParam> FromStr for ConnectionParams<C> {
    type Err = KeyRingError;

    fn from_str(s: &str) -> Result<Self> {
        Parser::parse(s)
    }
}

impl<C: CipherParam> ConnectionParams<C> {
    fn param(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "key" => {
                self.key = hex::decode(value).map_err(|e| KeyRingError::GeneralError {
                    msg: format!("invalid hex key: {}", e),
                })?
            }
            "password" => self.password = value.as_bytes().to_vec(),
            "salt" => self.salt = value.as_bytes().to_vec(),
            "cipher" => self.cipher = C::parse(value)?,
            "memory" => {
                self.memory = parse_cost(
                    "memory",
                    value,
                    Argon2Params::DEFAULT_M_COST,
                    Argon2Params::MAX_M_COST,
                )?
            }
            "threads" => {
                self.threads = parse_cost(
                    "threads",
                    value,
                    Argon2Params::DEFAULT_T_COST,
                    Argon2Params::MAX_T_COST,
                )?
            }
            "parallel" => {
                self.parallel = parse_cost(
                    "parallel",
                    value,
                    Argon2Params::DEFAULT_P_COST,
                    Argon2Params::MAX_P_COST,
                )?
            }
            _ => {
                return Err(KeyRingError::GeneralError {
                    msg: format!("unknown parameter: {}", key),
                });
            }
        };
        Ok(())
    }

    /// Set the key
    pub fn key(&mut self, key: &[u8]) -> &mut Self {
        self.key = key.to_vec();
        self
    }

    /// Set the password
    pub fn password(&mut self, password: &[u8]) -> &mut Self {
        self.password = password.to_vec();
        self
    }

    /// Set the salt
    pub fn salt(&mut self, salt: &[u8]) -> &mut Self {
        self.salt = salt.to_vec();
        self
    }

    /// Set the memory cost
    pub fn memory(&mut self, cost: u32) -> &mut Self {
        self.memory = cost;
        self
    }

    /// Set the time cost
    pub fn time(&mut self, cost: u32) -> &mut Self {
        self.threads = cost;
        self
    }

    /// Set the parallel cost
    pub fn parallel(&mut self, cost: u32) -> &mut Self {
        self.parallel = cost;
        self
    }
}

/// Parse an Argon2 cost and check it lies in `[min, max)`.
fn parse_cost(name: &str, value: &str, min: u32, max: u32) -> Result<u32> {
    let cost = value
        .parse::<u32>()
        .map_err(|e| KeyRingError::GeneralError {
            msg: format!("expected an integer for {}: {}", name, e),
        })?;
    if !(min..max).contains(&cost) {
        return Err(KeyRingError::GeneralError {
            msg: format!(
                "invalid value for {} must be between {} and {}",
                name, min, max
            ),
        });
    }
    Ok(cost)
}

/// Derive the raw encryption key from [`ConnectionParams`].
///
/// If `params.key` is set, returns it directly; otherwise derives a 32-byte
/// key from the password + salt via Argon2id.
pub(crate) fn derive_key<C: CipherParam>(
    params: &ConnectionParams<C>,
) -> Result<Zeroizing<Vec<u8>>> {
    if !params.key.is_empty() {
        return Ok(Zeroizing::new(params.key.to_vec()));
    }
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
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(&params.password, &params.salt, &mut okm)
        .map_err(|e| KeyRingError::GeneralError {
            msg: format!("Argon2 key derivation failed: {}", e),
        })?;
    Ok(okm)
}

/// Derive a key with [`derive_key`] and require it to be exactly 32 bytes.
#[cfg(any(
    feature = "encrypted-vfs",
    feature = "turso",
    feature = "turso-encrypted-io"
))]
pub(crate) fn derive_key_32<C: CipherParam>(
    params: &ConnectionParams<C>,
) -> Result<Zeroizing<[u8; 32]>> {
    let key = derive_key(params)?;
    let mut out = Zeroizing::new([0u8; 32]);
    if key.len() != out.len() {
        return Err(KeyRingError::GeneralError {
            msg: "key must be 32 bytes".to_string(),
        });
    }
    out.copy_from_slice(&key);
    Ok(out)
}

/// Resolve the keyring file `file_name` inside `in_path` (default
/// `~/.cryptex`), creating and securing the directory.
pub(crate) fn get_keyring_file(in_path: Option<PathBuf>, file_name: &str) -> Result<PathBuf> {
    let mut path = match in_path {
        None => {
            let mut path = dirs::home_dir().unwrap_or_else(|| {
                dirs::document_dir().unwrap_or_else(|| {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
                })
            });
            path.push(format!(".{}", env!("CARGO_PKG_NAME")));
            path
        }
        Some(path) => path,
    };

    if !path.is_dir() {
        fs::create_dir_all(&path).map_err(|e| KeyRingError::GeneralError {
            msg: format!("unable to create folder {}: {}", path.display(), e),
        })?;
    }
    secure_dir(&path)?;
    make_hidden(&path);
    path.push(file_name);
    Ok(path)
}

/// [`OpenOptions`] that create files readable and writable by the owner only.
#[cfg(any(
    feature = "encrypted-vfs",
    feature = "turso",
    feature = "turso-encrypted-io"
))]
pub(crate) fn private_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    restrict_to_owner(&mut opts);
    opts
}

#[cfg(all(
    unix,
    any(
        feature = "encrypted-vfs",
        feature = "turso",
        feature = "turso-encrypted-io"
    )
))]
fn restrict_to_owner(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

#[cfg(all(
    not(unix),
    any(
        feature = "encrypted-vfs",
        feature = "turso",
        feature = "turso-encrypted-io"
    )
))]
fn restrict_to_owner(_opts: &mut OpenOptions) {}

/// Acquire an exclusive advisory lock guaranteeing a single opener of the
/// keyring. A sidecar `<db>.lock` file is locked (not the database itself) so
/// the lock is unaffected by `rekey`'s atomic rename of the database file. The
/// returned handle must be kept alive for the keyring's lifetime; the OS
/// releases the lock when the handle is dropped or the process exits, so a
/// crashed process never leaves a stale lock behind.
#[cfg(any(
    feature = "encrypted-vfs",
    feature = "turso",
    feature = "turso-encrypted-io"
))]
pub(crate) fn acquire_single_opener_lock(db_path: &Path) -> Result<File> {
    let lock_path = sibling_path(db_path, ".lock");

    let file = private_open_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
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

/// `path` with `suffix` appended to its file name, e.g. `keyring.db3` + `-wal`.
#[cfg(any(
    feature = "encrypted-vfs",
    feature = "turso",
    feature = "turso-encrypted-io"
))]
pub(crate) fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
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

/// Restrict the database file itself to owner-only access (defense in depth
/// beyond the `0o700` parent directory).
#[cfg(all(unix, any(feature = "file", feature = "turso")))]
pub(crate) fn secure_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        KeyRingError::GeneralError {
            msg: format!("unable to secure keyring file {}: {}", path.display(), e),
        }
    })
}

#[cfg(all(not(unix), any(feature = "file", feature = "turso")))]
pub(crate) fn secure_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn make_hidden(path: &Path) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

    // SAFETY: matches the Win32 `SetFileAttributesW` signature in kernel32.
    unsafe extern "system" {
        fn SetFileAttributesW(lpfilename: *const u16, dwfileattributes: u32) -> i32;
    }

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call,
    // and SetFileAttributesW only reads it. Failure is harmless (the folder is
    // just not hidden), so the return value is ignored.
    unsafe {
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN);
    }
}

#[cfg(not(target_os = "windows"))]
fn make_hidden(_path: &Path) {}

struct Parser<'a> {
    s: &'a str,
    it: iter::Peekable<std::str::CharIndices<'a>>,
}

impl<'a> Parser<'a> {
    fn parse<C: CipherParam>(s: &'a str) -> Result<ConnectionParams<C>> {
        let mut parser = Parser {
            s,
            it: s.char_indices().peekable(),
        };

        let mut connection_string = ConnectionParams::default();

        while let Some((key, value)) = parser.parameter()? {
            connection_string.param(key, &value)?;
        }
        Ok(connection_string)
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
                    "unexpected character at byte {}: expected `{}` but got `{}`",
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
            let value = self.quoted_value()?;
            self.consume('\'')?;
            Ok(value)
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
            Some(keyword) => keyword,
            None => return Ok(None),
        };
        self.skip_ws();
        self.consume('=')?;
        self.skip_ws();
        let value = self.value()?;

        Ok(Some((keyword, value)))
    }
}

/// Helpers shared by the file-backed keyring tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::ops::Deref;
    use std::path::{Path, PathBuf};

    /// A scratch keyring directory under the crate root. It is emptied when
    /// created and removed when dropped, even if the test panics.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(name: &str) -> Self {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        /// The directory as the `path` argument of `with_params`.
        pub(crate) fn keyring_dir(&self) -> Option<PathBuf> {
            Some(self.0.clone())
        }
    }

    impl Deref for TestDir {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionParams, NoCipher, derive_key};

    #[test]
    fn parses_all_fields() {
        let p: ConnectionParams = "password=pw salt='a b' memory=32768 threads=3 parallel=2"
            .parse()
            .unwrap();
        assert_eq!(p.password, b"pw");
        assert_eq!(p.salt, b"a b");
        assert_eq!((p.memory, p.threads, p.parallel), (32768, 3, 2));
        assert_eq!(p.cipher, NoCipher);
    }

    #[test]
    fn rejects_bad_input() {
        for s in [
            "key=not-hex",
            "cipher=aes256gcm",
            "unknown=1",
            "memory=abc",
            "threads=0",
            "password='unterminated",
            "password",
        ] {
            assert!(s.parse::<ConnectionParams>().is_err(), "accepted: {s}");
        }
    }

    #[test]
    fn raw_key_bypasses_argon2() {
        let p: ConnectionParams = "key=aabb".parse().unwrap();
        assert_eq!(&*derive_key(&p).unwrap(), &[0xaa, 0xbb]);
    }

    #[test]
    fn password_derivation_is_deterministic() {
        let a: ConnectionParams = "password=pw salt=saltsaltsalt".parse().unwrap();
        let b: ConnectionParams = "password=pw salt=saltsaltsalt".parse().unwrap();
        let c: ConnectionParams = "password=pw2 salt=saltsaltsalt".parse().unwrap();
        let ka = derive_key(&a).unwrap();
        assert_eq!(ka.len(), 32);
        assert_eq!(ka, derive_key(&b).unwrap());
        assert_ne!(ka, derive_key(&c).unwrap());
    }
}
