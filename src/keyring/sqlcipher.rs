/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

use super::file_common::{NoCipher, derive_key, file_keyring, get_keyring_file, secure_file};
use super::sqlite_common::{KEYRING_FILE, init_schema, lock_connection};
use crate::error::KeyRingError;

/// The connection params for [`SqlCipherKeyring`]. The cipher is fixed by
/// SQLCipher and cannot be chosen.
pub type ConnectionParams = file_common::ConnectionParams<NoCipher>;

/// A keyring stored in a [SQLCipher](https://www.zetetic.net/sqlcipher/)
/// database. The default file is `~/.cryptex/keyring.db3`.
pub struct SqlCipherKeyring {
    /// `Connection` is `Send` but not `Sync`; the mutex makes the keyring
    /// `Sync` and lets `rekey` take `&self`.
    conn: Mutex<Connection>,
}

file_keyring!(SqlCipherKeyring, conn);

impl SqlCipherKeyring {
    /// Re-encrypt the entire database with a new key derived from `new_params`.
    ///
    /// The keyring must already be open (authenticated with the current key).
    /// After a successful rekey the current connection uses the new key;
    /// any future opens must use `new_params`.
    pub fn rekey(&self, new_params: &ConnectionParams) -> Result<()> {
        let hex_key = Zeroizing::new(hex::encode(&*derive_key(new_params)?));
        lock_connection(&self.conn)?
            .pragma_update(None, "rekey", hex_key.as_str())
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("PRAGMA rekey failed: {}", e),
            })
    }

    /// Open (or create) the keyring in `path` (default `~/.cryptex`).
    pub fn with_params(connection: &ConnectionParams, path: Option<PathBuf>) -> Result<Self> {
        let hex_key = Zeroizing::new(hex::encode(&*derive_key(connection)?));
        let db_path = get_keyring_file(path, KEYRING_FILE)?;
        let conn = Connection::open(&db_path)?;
        secure_file(&db_path)?;
        conn.pragma_update(None, "key", hex_key.as_str())
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("unable to set keyring key: {}", e),
            })?;
        conn.pragma_update(None, "cipher_memory_security", "ON")
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("cannot set memory sanitization: {}", e),
            })?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionParams, KEYRING_FILE, SqlCipherKeyring, get_keyring_file};
    use crate::file_common::test_support::TestDir;
    use crate::{KeyRing, NewKeyRing};
    use std::fs;

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher overflows the Windows test stack in CI"
    )]
    fn works() {
        {
            let file = get_keyring_file(None, KEYRING_FILE).unwrap();
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
            let file = get_keyring_file(None, KEYRING_FILE).unwrap();
            let _ = fs::remove_dir_all(file);
        }
    }

    #[test]
    fn invalid_hex_key_is_an_error() {
        let result = "key=not-hex".parse::<ConnectionParams>();
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher rekey overflows the Windows test stack in CI"
    )]
    fn rekey_works() {
        let dir = TestDir::new(".test_rekey");

        let old_params = "password=old_password salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_password salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        // Open with old key, store a secret, then rekey
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            keyring.set_secret("rekey_test", b"my_secret_data").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        // Reopen with new key — secret should still be accessible
        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            let secret = keyring.get_secret("rekey_test").unwrap();
            assert_eq!(secret.0, b"my_secret_data");
        }

        // Old key should fail to open the rekeyed database
        {
            let result = SqlCipherKeyring::with_params(&old_params, dir.keyring_dir());
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher rekey overflows the Windows test stack in CI"
    )]
    fn rekey_preserves_multiple_secrets() {
        let dir = TestDir::new(".test_rekey_multi");

        let old_params = "password=old_pass salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_pass salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            keyring.set_secret("alpha", b"secret_alpha").unwrap();
            keyring.set_secret("beta", b"secret_beta").unwrap();
            keyring.set_secret("gamma", b"secret_gamma").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert_eq!(keyring.get_secret("alpha").unwrap().0, b"secret_alpha");
            assert_eq!(keyring.get_secret("beta").unwrap().0, b"secret_beta");
            assert_eq!(keyring.get_secret("gamma").unwrap().0, b"secret_gamma");
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher rekey overflows the Windows test stack in CI"
    )]
    fn rekey_allows_continued_use_on_same_connection() {
        let dir = TestDir::new(".test_rekey_continue");

        let old_params = "password=old_pass salt=old_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();
        let new_params = "password=new_pass salt=new_salt_value_here"
            .parse::<ConnectionParams>()
            .unwrap();

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
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
                SqlCipherKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert!(keyring.get_secret("before").is_err());
            assert_eq!(keyring.get_secret("after").unwrap().0, b"after_rekey");
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher rekey overflows the Windows test stack in CI"
    )]
    fn rekey_sequential() {
        let dir = TestDir::new(".test_rekey_seq");

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
            let mut keyring = SqlCipherKeyring::with_params(&params_a, dir.keyring_dir()).unwrap();
            keyring.set_secret("seq", b"sequential_data").unwrap();
            keyring.rekey(&params_b).unwrap();
            keyring.rekey(&params_c).unwrap();
        }

        // Only C should work
        {
            let mut keyring = SqlCipherKeyring::with_params(&params_c, dir.keyring_dir()).unwrap();
            assert_eq!(keyring.get_secret("seq").unwrap().0, b"sequential_data");
        }

        // A and B should fail
        assert!(SqlCipherKeyring::with_params(&params_a, dir.keyring_dir()).is_err());
        assert!(SqlCipherKeyring::with_params(&params_b, dir.keyring_dir()).is_err());
    }

    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "SQLCipher rekey overflows the Windows test stack in CI"
    )]
    fn rekey_with_raw_key() {
        let dir = TestDir::new(".test_rekey_rawkey");

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
                SqlCipherKeyring::with_params(&old_params, dir.keyring_dir()).unwrap();
            keyring.set_secret("raw", b"raw_key_data").unwrap();
            keyring.rekey(&new_params).unwrap();
        }

        {
            let mut keyring =
                SqlCipherKeyring::with_params(&new_params, dir.keyring_dir()).unwrap();
            assert_eq!(keyring.get_secret("raw").unwrap().0, b"raw_key_data");
        }

        assert!(SqlCipherKeyring::with_params(&old_params, dir.keyring_dir()).is_err());
    }
}
