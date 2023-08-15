/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use rusqlite::{params, Connection};

use std::fs;
use std::path::PathBuf;

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
        let params = Argon2Params::new(
            #[cfg(test)]
            {
                Argon2Params::DEFAULT_M_COST
            },
            #[cfg(not(test))]
            {
                1_9917_824 // 19456 KiB converted to bytes
            },
            Argon2Params::DEFAULT_T_COST,
            Argon2Params::DEFAULT_P_COST,
            Some(Argon2Params::DEFAULT_OUTPUT_LEN),
        )
        .unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = [0xFF; 32];
        let mut okm = [0u8; 32];
        argon2
            .hash_password_into(lock_key.as_ref().as_bytes(), &salt, &mut okm)
            .unwrap();
        let conn = Connection::open(get_keyring_file()).expect("Unable to open keyring file");
        conn.pragma_update(None, "key", hex::encode(okm))
            .expect("Unable to set keyring key");
        conn.pragma_update(None, "cipher_memory_security", "ON")
            .expect("Cannot set memory sanitization");
        conn.query_row("SELECT COUNT(*) FROM `sqlite_master`;", params![], |_row| {
            Ok(())
        })
        .expect("Keyring key was incorrect");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS secrets (id TEXT UNIQUE NOT NULL, value TEXT NOT NULL)",
            (),
        )
        .expect("Unable to create keyring table");

        Ok(Self { conn })
    }
}

fn get_keyring_file() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| {
        dirs::document_dir().unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR").to_string()))
        })
    });
    path.push(format!(".{}", env!("CARGO_PKG_NAME")));

    if !path.is_dir() {
        fs::create_dir_all(&path).expect(&format!(
            "Unable to create folder: {}",
            path.to_str().unwrap()
        ));
    }
    make_hidden(&path);
    path.push("keyring.db3");
    path
}

#[cfg(target_os = "windows")]
fn make_hidden(path: &PathBuf) {
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
fn make_hidden(_path: &PathBuf) {}

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
            let res_keyring = SqlCipherKeyring::new("works_test");
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
            let res_keyring = SqlCipherKeyring::new("works_test");
            assert!(res_keyring.is_ok());
            let mut keyring = res_keyring.unwrap();
            let res = keyring.get_secret("test_key2");
            assert!(res.is_ok());
            assert_eq!(res.unwrap().0, b"bonuskey");
        }
        {
            let file = get_keyring_file();
            let _ = fs::remove_dir_all(file);
        }
    }
}
