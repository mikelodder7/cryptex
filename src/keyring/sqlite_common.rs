/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! SQLite plumbing shared by the SQLCipher and encrypted-VFS keyrings.

use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use super::file_common::{
    CREATE_SECRETS_SQL, DELETE_SECRET_SQL, SELECT_SECRET_SQL, SecretStore, UPSERT_SECRET_SQL,
    VERIFY_KEY_SQL, decode_secret, invalid_key,
};
use crate::error::KeyRingError;

/// Default file name for the SQLite-format keyrings.
pub(crate) const KEYRING_FILE: &str = "keyring.db3";

/// Lock a keyring's connection. A poisoned lock is reported as an error
/// rather than recovered, since the connection may be mid-rekey.
pub(crate) fn lock_connection(conn: &Mutex<Connection>) -> Result<MutexGuard<'_, Connection>> {
    conn.lock().map_err(|_| KeyRingError::GeneralError {
        msg: "keyring connection lock poisoned".to_string(),
    })
}

/// Check the key can read the database, then ensure the `secrets` table exists.
pub(crate) fn init_schema(conn: &Connection) -> Result<()> {
    conn.query_row(VERIFY_KEY_SQL, [], |_| Ok(()))
        .map_err(|_| invalid_key())?;
    conn.execute(CREATE_SECRETS_SQL, [])?;
    Ok(())
}

impl SecretStore for Mutex<Connection> {
    fn get(&self, id: &str) -> Result<KeyRingSecret> {
        let value = lock_connection(self)?
            .query_row(SELECT_SECRET_SQL, [id], |row| {
                row.get::<_, String>(0).map(Zeroizing::new)
            })
            .optional()?;
        decode_secret(value)
    }

    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        let encoded = Zeroizing::new(hex::encode(secret));
        lock_connection(self)?.execute(UPSERT_SECRET_SQL, params![id, encoded.as_str()])?;
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<()> {
        lock_connection(self)?.execute(DELETE_SECRET_SQL, [id])?;
        Ok(())
    }
}
