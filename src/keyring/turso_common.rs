/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Storage and rekey logic shared by the Turso-backed keyrings.
//!
//! Turso's API is async but local databases need no runtime, so each call is
//! driven to completion on the current thread with [`block_on`].

use super::*;
use ::turso::{Builder, Connection, Database};
use std::fs::{self, File};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use super::file_common::{
    CREATE_SECRETS_SQL, DELETE_SECRET_SQL, SELECT_SECRET_SQL, SecretStore, UPSERT_SECRET_SQL,
    VERIFY_KEY_SQL, acquire_single_opener_lock, decode_secret, get_keyring_file, invalid_key,
    sibling_path,
};
use crate::error::KeyRingError;
use zeroize::Zeroizing;

/// Default file name for Turso-backed keyrings. Distinct from the SQLite-format
/// `keyring.db3` so the backends never try to open each other's files.
pub(crate) const KEYRING_FILE: &str = "keyring-turso.db3";

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive `fut` to completion on the current thread.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        thread::park();
    }
}

/// An open Turso database holding the `secrets` table.
struct TursoStore {
    conn: Connection,
    _db: Database,
}

impl TursoStore {
    fn open(builder: Builder) -> Result<Self> {
        block_on(async {
            let db = builder.build().await?;
            let conn = db.connect()?;
            let mut rows = conn
                .query(VERIFY_KEY_SQL, ())
                .await
                .map_err(|_| invalid_key())?;
            rows.next().await.map_err(|_| invalid_key())?;
            drop(rows);
            conn.execute(CREATE_SECRETS_SQL, ()).await?;
            Ok(Self { conn, _db: db })
        })
    }

    fn get(&self, id: &str) -> Result<KeyRingSecret> {
        block_on(async {
            let mut rows = self.conn.query(SELECT_SECRET_SQL, [id]).await?;
            let value = match rows.next().await? {
                Some(row) => Some(Zeroizing::new(row.get::<String>(0)?)),
                None => None,
            };
            decode_secret(value)
        })
    }

    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        let encoded = Zeroizing::new(hex::encode(secret));
        block_on(self.conn.execute(UPSERT_SECRET_SQL, [id, encoded.as_str()]))?;
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<()> {
        block_on(self.conn.execute(DELETE_SECRET_SQL, [id]))?;
        Ok(())
    }

    /// Copy every secret into `dst` inside a single transaction.
    fn copy_into(&self, dst: &TursoStore) -> Result<()> {
        block_on(async {
            let mut rows = self.conn.query("SELECT id, value FROM secrets", ()).await?;
            dst.conn.execute("BEGIN", ()).await?;
            while let Some(row) = rows.next().await? {
                let id = row.get::<String>(0)?;
                let value = Zeroizing::new(row.get::<String>(1)?);
                dst.conn
                    .execute(UPSERT_SECRET_SQL, [id.as_str(), value.as_str()])
                    .await?;
            }
            dst.conn.execute("COMMIT", ()).await?;
            Ok(())
        })
    }

    /// Flush the WAL into the main database file and empty the WAL.
    fn checkpoint(&self) -> Result<()> {
        block_on(async {
            let mut rows = self
                .conn
                .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
                .await?;
            while rows.next().await?.is_some() {}
            Ok(())
        })
    }
}

/// A Turso keyring file: the open store, its path, and the single-opener lock.
///
/// Backends pass a closure that builds a [`Builder`] for a database path,
/// carrying their encryption configuration.
pub(crate) struct TursoFile {
    store: TursoStore,
    db_path: PathBuf,
    /// Exclusive advisory lock on a sidecar file, held for the keyring's
    /// lifetime so `rekey`'s rename never races another opener.
    _lock: File,
}

impl TursoFile {
    /// Open (or create) the keyring in `path`, using `builder` to configure Turso.
    pub(crate) fn open<B>(path: Option<PathBuf>, builder: B) -> Result<Self>
    where
        B: Fn(&str) -> Builder,
    {
        let db_path = get_keyring_file(path, KEYRING_FILE)?;
        let lock = acquire_single_opener_lock(&db_path)?;
        let store = TursoStore::open(builder(path_str(&db_path)?))?;
        Ok(Self {
            store,
            db_path,
            _lock: lock,
        })
    }

    /// Path of the main database file.
    #[cfg(feature = "turso")]
    pub(crate) fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Re-encrypt the keyring under the configuration produced by `builder`.
    ///
    /// Secrets are copied into a temporary database opened with the new
    /// configuration, which then atomically replaces the original. The
    /// original is untouched if anything fails before the rename.
    pub(crate) fn rekey<B>(self, builder: B) -> Result<Self>
    where
        B: Fn(&str) -> Builder,
    {
        let tmp_path = self.db_path.with_extension("cryptex-rekey-tmp");
        remove_db_files(&tmp_path)?;

        let copied = TursoStore::open(builder(path_str(&tmp_path)?)).and_then(|tmp| {
            self.store.copy_into(&tmp)?;
            tmp.checkpoint()
        });
        if let Err(e) = copied {
            remove_db_files(&tmp_path)?;
            return Err(e);
        }
        self.store.checkpoint()?;

        let Self {
            store,
            db_path,
            _lock,
        } = self;
        drop(store);
        remove_file_if_exists(&sibling_path(&tmp_path, "-wal"))?;
        remove_file_if_exists(&sibling_path(&db_path, "-wal"))?;
        fs::rename(&tmp_path, &db_path).map_err(|e| KeyRingError::GeneralError {
            msg: format!("unable to replace keyring file: {}", e),
        })?;

        let store = TursoStore::open(builder(path_str(&db_path)?))?;
        Ok(Self {
            store,
            db_path,
            _lock,
        })
    }
}

impl SecretStore for TursoFile {
    fn get(&self, id: &str) -> Result<KeyRingSecret> {
        self.store.get(id)
    }

    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        self.store.set(id, secret)
    }

    fn delete(&self, id: &str) -> Result<()> {
        self.store.delete(id)
    }
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| KeyRingError::GeneralError {
        msg: format!("keyring path is not valid UTF-8: {}", path.display()),
    })
}

/// Remove a database file and its WAL, ignoring files that do not exist.
fn remove_db_files(db_path: &Path) -> Result<()> {
    remove_file_if_exists(db_path)?;
    remove_file_if_exists(&sibling_path(db_path, "-wal"))
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(KeyRingError::GeneralError {
            msg: format!("unable to remove {}: {}", path.display(), e),
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::block_on;

    #[test]
    fn block_on_drives_pending_future() {
        let mut polled = false;
        let fut = std::future::poll_fn(|cx| {
            if polled {
                std::task::Poll::Ready(7)
            } else {
                polled = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        });
        assert_eq!(block_on(fut), 7);
    }
}
