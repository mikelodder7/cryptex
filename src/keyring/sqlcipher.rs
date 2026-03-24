/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use rusqlite::{Connection, params};

use crate::error::KeyRingError;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, iter};
use zeroize::{Zeroize, Zeroizing};

pub struct SqlCipherKeyring {
    conn: Connection,
}

unsafe impl Send for SqlCipherKeyring {}

unsafe impl Sync for SqlCipherKeyring {}

impl DynKeyRing for SqlCipherKeyring {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM secrets WHERE id=?")
            .unwrap();
        let val = stmt.query_row(params![id], |row| {
            let s: String = row.get(0)?;
            hex::decode(s).map_err(|_e| rusqlite::Error::InvalidQuery)
        })?;
        Ok(KeyRingSecret(val))
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        let secret = hex::encode(secret);
        let mut stmt = self
            .conn
            .prepare(
                "INSERT INTO secrets(id, value) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET value=?",
            )
            .expect("SQL statement to work");
        stmt.execute(params![id, secret.clone(), secret])?;
        Ok(())
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("DELETE FROM secrets WHERE id=?")
            .expect("SQL statement to work");
        stmt.execute(params![id])?;
        Ok(())
    }
}

impl NewKeyRing for SqlCipherKeyring {
    fn new<S: AsRef<str>>(lock_key: S) -> Result<Self> {
        let connection = lock_key.as_ref().parse::<ConnectionParams>()?;
        Self::with_params(&connection, None)
    }
}

impl SqlCipherKeyring {
    /// Re-encrypt the entire database with a new key derived from `new_params`.
    ///
    /// The keyring must already be open (authenticated with the current key).
    /// After a successful rekey the current connection uses the new key;
    /// any future opens must use `new_params`.
    pub fn rekey(&self, new_params: &ConnectionParams) -> Result<()> {
        let new_key = derive_key(new_params);
        let mut hex_key = hex::encode(&*new_key);
        let result = self
            .conn
            .pragma_update(None, "rekey", &hex_key)
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("PRAGMA rekey failed: {}", e),
            });
        hex_key.zeroize();
        result
    }

    /// Create a new keyring with the connection params
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let key = derive_key(connection);
        let conn = Connection::open(get_keyring_file(path)).expect("Unable to open keyring file");
        let mut hex_key = hex::encode(&*key);
        conn.pragma_update(None, "key", &hex_key)
            .expect("Unable to set keyring key");
        hex_key.zeroize();
        conn.pragma_update(None, "cipher_memory_security", "ON")
            .expect("Cannot set memory sanitization");
        conn.query_row("SELECT COUNT(*) FROM `sqlite_master`;", params![], |_row| {
            Ok(())
        })?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS secrets (id TEXT UNIQUE NOT NULL, value TEXT NOT NULL)",
            (),
        )
        .expect("Unable to create keyring table");
        Ok(Self { conn })
    }
}

/// Derive the raw encryption key from [`ConnectionParams`].
///
/// If `params.key` is set, returns it directly; otherwise derives a 32-byte
/// key from the password + salt via Argon2id.
fn derive_key(params: &ConnectionParams) -> Zeroizing<Vec<u8>> {
    if params.key.is_empty() {
        let argon2_params = Argon2Params::new(
            params.memory,
            params.threads,
            params.parallel,
            Some(Argon2Params::DEFAULT_OUTPUT_LEN),
        )
        .unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        let mut okm = [0u8; 32];
        argon2
            .hash_password_into(&params.password, &params.salt, &mut okm)
            .unwrap();
        let result = Zeroizing::new(okm.to_vec());
        okm.zeroize();
        result
    } else {
        Zeroizing::new(params.key.to_vec())
    }
}

fn get_keyring_file(in_path: Option<PathBuf>) -> PathBuf {
    let mut path = match in_path {
        None => {
            let mut path = dirs::home_dir().unwrap_or_else(|| {
                dirs::document_dir().unwrap_or_else(|| {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR").to_string()))
                })
            });
            path.push(format!(".{}", env!("CARGO_PKG_NAME")));
            path
        }
        Some(path) => path,
    };

    if !path.is_dir() {
        fs::create_dir_all(&path)
            .unwrap_or_else(|_| panic!("Unable to create folder: {}", path.to_str().unwrap()));
    }
    make_hidden(&path);
    path.push("keyring.db3");
    path
}

#[cfg(target_os = "windows")]
fn make_hidden(path: &Path) {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

    unsafe extern "system" {
        fn SetFileAttributesW(lpfilename: *const u16, dwfileattributes: u32) -> i32;
    }

    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
    unsafe {
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN);
    }
}

#[cfg(not(target_os = "windows"))]
fn make_hidden(_path: &Path) {}

/// The connection params for SqlCipherKeyRing
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
/// or with extra parameters
///
/// ```
/// use cryptex::sqlcipher::ConnectionParams;
///
/// let params = "password=1qaz2wsx3edc4rfv salt=0okm9ijn8uhb7ygv memory=19917824 threads=2 parallel=1".parse::<ConnectionParams>().unwrap();
/// ```
#[derive(Zeroize)]
pub struct ConnectionParams {
    /// The key used to open the keyring. This is used mutually exclusive
    /// with password and salt
    pub key: Vec<u8>,
    /// The password to use to open the keyring
    pub password: Vec<u8>,
    /// The salt to use when hashing the password
    pub salt: Vec<u8>,
    /// The memory requirement
    pub memory: u32,
    /// The number of iterations or threads requirement
    pub threads: u32,
    /// The parallel requirement
    pub parallel: u32,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        let m_cost = get_default_memory_cost();
        Self {
            key: vec![],
            password: vec![],
            salt: vec![],
            memory: m_cost,
            threads: Argon2Params::DEFAULT_T_COST,
            parallel: Argon2Params::DEFAULT_P_COST,
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
            "key" => self.key = hex::decode(value).unwrap(),
            "password" => self.password = value.as_bytes().to_vec(),
            "salt" => self.salt = value.as_bytes().to_vec(),
            "memory" => {
                let m_cost = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected an integer for memory: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_M_COST..Argon2Params::MAX_M_COST).contains(&m_cost) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "invalid value for memory must be between {} and {}",
                            Argon2Params::DEFAULT_M_COST,
                            Argon2Params::MAX_M_COST
                        ),
                    });
                }
                self.memory = m_cost;
            }
            "threads" => {
                let t_cost = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected an integer for threads: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_T_COST..Argon2Params::MAX_T_COST).contains(&t_cost) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "invalid value for threads must be between {} and {}",
                            Argon2Params::DEFAULT_T_COST,
                            Argon2Params::MAX_T_COST
                        ),
                    });
                }
                self.threads = t_cost;
            }
            "parallel" => {
                let p_cost = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected an integer for degree of parallelism: {}", e),
                    })?;
                if !(Argon2Params::DEFAULT_P_COST..Argon2Params::MAX_P_COST).contains(&p_cost) {
                    return Err(KeyRingError::GeneralError {
                        msg: format!(
                            "invalid value for degree of parallelism must be between {} and {}",
                            Argon2Params::DEFAULT_P_COST,
                            Argon2Params::MAX_P_COST
                        ),
                    });
                }
                self.parallel = p_cost;
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

#[cfg(test)]
fn get_default_memory_cost() -> u32 {
    Argon2Params::DEFAULT_M_COST
}

#[cfg(not(test))]
fn get_default_memory_cost() -> u32 {
    19_917_824 // 19456 KiB converted to bytes
}

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
        let s = self.take_while(|c| match c {
            c if c.is_whitespace() => false,
            '=' => false,
            _ => true,
        });

        if s.is_empty() { None } else { Some(s) }
    }

    fn value(&mut self) -> Result<String> {
        let value = if self.consume_if('\'') {
            let value = self.quoted_value()?;
            self.consume('\'')?;
            value
        } else {
            self.simple_value()?
        };

        Ok(value)
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

#[cfg(test)]
mod tests {
    use super::{ConnectionParams, SqlCipherKeyring, get_keyring_file};
    use crate::{KeyRing, NewKeyRing};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn works() {
        {
            let file = get_keyring_file(None);
            let _ = fs::remove_dir_all(file);
        }
        {
            let res_keyring =
                SqlCipherKeyring::new("password=works_test salt=1qaz2wsx3edc4rfv5tgb6yhn");
            assert!(res_keyring.is_ok());
            let mut keyring = res_keyring.unwrap();
            let res = keyring.set_secret("test_key", b"letmeinplease!");
            assert!(res.is_ok());
            let res = keyring.get_secret("test_key");
            assert!(res.is_ok());
            assert_eq!(res.unwrap().0, b"letmeinplease!");
            let res = keyring.delete_secret("test_key");
            assert!(res.is_ok());
            let res = keyring.get_secret("test_key");
            assert!(res.is_err());
            let res = keyring.set_secret("test_key2", b"bonuskey");
            assert!(res.is_ok());
        }
        {
            let res_keyring =
                SqlCipherKeyring::new("password=works_test salt=1qaz2wsx3edc4rfv5tgb6yhn");
            assert!(res_keyring.is_ok());
            let mut keyring = res_keyring.unwrap();
            let res = keyring.get_secret("test_key2");
            assert!(res.is_ok());
            assert_eq!(res.unwrap().0, b"bonuskey");
        }
        {
            let res_keyring =
                SqlCipherKeyring::new("password=badpassword salt=somethingelselikesalt");
            assert!(res_keyring.is_err());
        }
        {
            let file = get_keyring_file(None);
            let _ = fs::remove_dir_all(file);
        }
    }

    #[test]
    fn rekey_works() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test_rekey");
        let _ = fs::remove_dir_all(&path);

        let old_params = "password=old_password salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_password salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        // Open with old key, store a secret, then rekey
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, Some(path.clone())).unwrap();
            keyring.set_secret("rekey_test", b"my_secret_data").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        // Reopen with new key — secret should still be accessible
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, Some(path.clone())).unwrap();
            let secret = keyring.get_secret("rekey_test").unwrap();
            assert_eq!(secret.0, b"my_secret_data");
        }

        // Old key should fail to open the rekeyed database
        {
            let result = SqlCipherKeyring::with_params(&old_params, Some(path.clone()));
            assert!(result.is_err());
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn rekey_preserves_multiple_secrets() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test_rekey_multi");
        let _ = fs::remove_dir_all(&path);

        let old_params = "password=old_pass salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_pass salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, Some(path.clone())).unwrap();
            keyring.set_secret("alpha", b"secret_alpha").unwrap();
            keyring.set_secret("beta", b"secret_beta").unwrap();
            keyring.set_secret("gamma", b"secret_gamma").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, Some(path.clone())).unwrap();
            assert_eq!(keyring.get_secret("alpha").unwrap().0, b"secret_alpha");
            assert_eq!(keyring.get_secret("beta").unwrap().0, b"secret_beta");
            assert_eq!(keyring.get_secret("gamma").unwrap().0, b"secret_gamma");
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn rekey_allows_continued_use_on_same_connection() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test_rekey_continue");
        let _ = fs::remove_dir_all(&path);

        let old_params = "password=old_pass salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_pass salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, Some(path.clone())).unwrap();
            keyring.set_secret("before", b"before_rekey").unwrap();
            keyring.rekey(&new_params).unwrap();

            // Writes and reads should still work on the same connection after rekey
            keyring.set_secret("after", b"after_rekey").unwrap();
            assert_eq!(keyring.get_secret("before").unwrap().0, b"before_rekey");
            assert_eq!(keyring.get_secret("after").unwrap().0, b"after_rekey");
            keyring.delete_secret("before").unwrap();
            assert!(keyring.get_secret("before").is_err());
        }

        // Reopen with new params to confirm persistence
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, Some(path.clone())).unwrap();
            assert!(keyring.get_secret("before").is_err());
            assert_eq!(keyring.get_secret("after").unwrap().0, b"after_rekey");
        }

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn rekey_sequential() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test_rekey_seq");
        let _ = fs::remove_dir_all(&path);

        let params_a = "password=pass_a salt=salt_value_a_here_"
            .parse::<ConnectionParams>()
            .unwrap();
        let params_b = "password=pass_b salt=salt_value_b_here_"
            .parse::<ConnectionParams>()
            .unwrap();
        let params_c = "password=pass_c salt=salt_value_c_here_"
            .parse::<ConnectionParams>()
            .unwrap();

        // Create with A, rekey to B, then rekey to C
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&params_a, Some(path.clone())).unwrap();
            keyring.set_secret("seq", b"sequential_data").unwrap();
            keyring.rekey(&params_b).unwrap();
            keyring.rekey(&params_c).unwrap();
        }

        // Only C should work
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&params_c, Some(path.clone())).unwrap();
            assert_eq!(keyring.get_secret("seq").unwrap().0, b"sequential_data");
        }

        // A and B should fail
        assert!(SqlCipherKeyring::with_params(&params_a, Some(path.clone())).is_err());
        assert!(SqlCipherKeyring::with_params(&params_b, Some(path.clone())).is_err());

        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn rekey_with_raw_key() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test_rekey_rawkey");
        let _ = fs::remove_dir_all(&path);

        let old_params = "password=raw_old salt=raw_old_salt_value"
            .parse::<ConnectionParams>()
            .unwrap();
        let mut new_params = "password=unused salt=unused_salt_value_"
            .parse::<ConnectionParams>()
            .unwrap();
        // Set a raw key directly — derive_key should use it instead of Argon2
        new_params.key = vec![0xAA; 32];

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, Some(path.clone())).unwrap();
            keyring.set_secret("raw", b"raw_key_data").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, Some(path.clone())).unwrap();
            assert_eq!(keyring.get_secret("raw").unwrap().0, b"raw_key_data");
        }

        assert!(SqlCipherKeyring::with_params(&old_params, Some(path.clone())).is_err());

        let _ = fs::remove_dir_all(&path);
    }
}
