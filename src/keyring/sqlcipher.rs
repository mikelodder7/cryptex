/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use rusqlite::{params, Connection};

use crate::error::KeyRingError;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, iter};
use zeroize::Zeroize;

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
    /// Create a new keyring with the connection params
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let params = Argon2Params::new(
            connection.memory,
            connection.threads,
            connection.parallel,
            Some(Argon2Params::DEFAULT_OUTPUT_LEN),
        )
        .unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut okm = [0u8; 32];
        argon2
            .hash_password_into(&connection.password, &connection.salt, &mut okm)
            .unwrap();
        let conn = Connection::open(get_keyring_file(path)).expect("Unable to open keyring file");
        conn.pragma_update(None, "key", hex::encode(okm))
            .expect("Unable to set keyring key");
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
    use std::ffi::CString;
    unsafe {
        let file_name = path.to_str().unwrap();
        winapi::um::fileapi::SetFileAttributesA(
            file_name.as_ptr(),
            0x2, // Hidden
        );
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
            "password" => self.password = value.as_bytes().to_vec(),
            "salt" => self.salt = value.as_bytes().to_vec(),
            "memory" => {
                let m_cost = value
                    .parse::<u32>()
                    .map_err(|e| KeyRingError::GeneralError {
                        msg: format!("expected an integer for memory: {}", e.to_string()),
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
                        msg: format!("expected an integer for threads: {}", e.to_string()),
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
                        msg: format!(
                            "expected an integer for degree of parallelism: {}",
                            e.to_string()
                        ),
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
                })
            }
        };
        Ok(())
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

        if s.is_empty() {
            None
        } else {
            Some(s)
        }
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
    use super::{get_keyring_file, SqlCipherKeyring};
    use crate::{KeyRing, NewKeyRing};
    use std::fs;

    #[test]
    fn works() {
        {
            let file = get_keyring_file();
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
            let file = get_keyring_file();
            let _ = fs::remove_dir_all(file);
        }
    }
}
