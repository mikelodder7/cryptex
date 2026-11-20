/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! A Turso [`IO`] whose files live in process memory, for browsers and for
//! tests.
//!
//! Turso opens the database and its WAL as ordinary files. This backend keeps
//! each one in a [`PageStore`] buffer, so a whole database can be copied out
//! as one blob ([`WebIo::snapshot`]), stored somewhere durable such as
//! IndexedDB, and put back later ([`WebIo::restore`]). OPFS uses the same
//! shape with a synchronous access handle in place of the buffer.
//!
//! Reads and writes complete in place, so Turso never needs to park a thread —
//! which a wasm build cannot do.
//!
//! [`IO`]: ::turso::core::IO

use super::page_store::{MemPages, PageStore};
use super::web_time::WebClock;
use ::turso::core::io::FileId;
use ::turso::core::io::FileSyncType;
use ::turso::core::{
    Buffer, Clock, Completion, File as TursoFileIo, IO, LimboError, MonotonicInstant, OpenFlags,
    WallClockInstant, io_error,
};
use crate::error::KeyRingError;
use crate::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

type TursoResult<T> = std::result::Result<T, LimboError>;

const SNAPSHOT_MAGIC: &[u8; 10] = b"CRYPTEX-IO";
const SNAPSHOT_VERSION: u8 = 1;

/// Files held by [`WebIo`], keyed by the path Turso opened them with.
pub(crate) struct WebIo {
    files: Mutex<HashMap<String, Arc<WebFile>>>,
}

impl WebIo {
    /// Create an empty IO backed by process memory.
    pub(crate) fn in_memory() -> Arc<Self> {
        Arc::new(Self {
            files: Mutex::new(HashMap::new()),
        })
    }

    /// Copy every file into one blob.
    ///
    /// Layout: `magic (10) | version (1) | count (u32 LE)` then, per file in
    /// path order, `path_len (u32 LE) | path | len (u64 LE) | bytes`.
    pub(crate) fn snapshot(&self) -> Result<Vec<u8>> {
        let files = self.files()?;
        let mut entries: Vec<(&String, &Arc<WebFile>)> = files.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (path, file) in entries {
            let store = file.store().map_err(|_| poisoned())?;
            let size = store
                .len()
                .map_err(|e| KeyRingError::GeneralError { msg: e.to_string() })?;
            out.extend_from_slice(&(path.len() as u32).to_le_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(store.as_slice());
        }
        Ok(out)
    }

    /// Rebuild an IO from a blob produced by [`WebIo::snapshot`].
    pub(crate) fn restore(bytes: &[u8]) -> Result<Arc<Self>> {
        let malformed = || KeyRingError::GeneralError {
            msg: "the keyring image is not a cryptex database snapshot".to_string(),
        };
        let mut rest = bytes;
        if rest.len() < 11 || &rest[..10] != SNAPSHOT_MAGIC {
            return Err(malformed());
        }
        rest = &rest[10..];
        if rest[0] != SNAPSHOT_VERSION {
            return Err(malformed());
        }
        rest = &rest[1..];
        let (count, tail) = take::<4>(rest).ok_or_else(malformed)?;
        rest = tail;
        let mut files = HashMap::with_capacity(u32::from_le_bytes(count) as usize);
        for _ in 0..u32::from_le_bytes(count) {
            let (len, tail) = take::<4>(rest).ok_or_else(malformed)?;
            rest = tail;
            let path_len = u32::from_le_bytes(len) as usize;
            if rest.len() < path_len {
                return Err(malformed());
            }
            let path = String::from_utf8(rest[..path_len].to_vec()).map_err(|_| malformed())?;
            rest = &rest[path_len..];

            let (len, tail) = take::<8>(rest).ok_or_else(malformed)?;
            rest = tail;
            let data_len = usize::try_from(u64::from_le_bytes(len)).map_err(|_| malformed())?;
            if rest.len() < data_len {
                return Err(malformed());
            }
            let store = MemPages::from_vec(rest[..data_len].to_vec());
            rest = &rest[data_len..];
            files.insert(path, Arc::new(WebFile::new(store)));
        }
        Ok(Arc::new(Self {
            files: Mutex::new(files),
        }))
    }

    fn files(&self) -> Result<MutexGuard<'_, HashMap<String, Arc<WebFile>>>> {
        self.files.lock().map_err(|_| poisoned())
    }
}

fn poisoned() -> KeyRingError {
    KeyRingError::GeneralError {
        msg: "the in-memory database lock is poisoned".to_string(),
    }
}

fn take<const N: usize>(bytes: &[u8]) -> Option<([u8; N], &[u8])> {
    let head = bytes.get(..N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Some((out, &bytes[N..]))
}

impl IO for WebIo {
    fn open_file(
        &self,
        path: &str,
        flags: OpenFlags,
        _direct: bool,
    ) -> TursoResult<Arc<dyn TursoFileIo>> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| LimboError::InternalError("database lock poisoned".to_string()))?;
        if let Some(file) = files.get(path) {
            let existing: Arc<WebFile> = Arc::clone(file);
            return Ok(existing);
        }
        if !flags.contains(OpenFlags::Create) {
            return Err(io_error(
                std::io::Error::from(std::io::ErrorKind::NotFound),
                "open_file",
            ));
        }
        let file = Arc::new(WebFile::new(MemPages::new()));
        files.insert(path.to_string(), Arc::clone(&file));
        let opened: Arc<WebFile> = file;
        Ok(opened)
    }

    fn remove_file(&self, path: &str) -> TursoResult<()> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| LimboError::InternalError("database lock poisoned".to_string()))?;
        files.remove(path);
        Ok(())
    }

    fn file_id(&self, path: &str) -> TursoResult<FileId> {
        Ok(FileId::from_path_hash(path))
    }

    fn is_memory(&self) -> bool {
        true
    }
}

impl Clock for WebIo {
    fn current_time_monotonic(&self) -> MonotonicInstant {
        WebClock.current_time_monotonic()
    }

    fn current_time_wall_clock(&self) -> WallClockInstant {
        WebClock.current_time_wall_clock()
    }
}

struct WebFile {
    store: Mutex<MemPages>,
}

impl WebFile {
    fn new(store: MemPages) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    fn store(&self) -> TursoResult<MutexGuard<'_, MemPages>> {
        self.store
            .lock()
            .map_err(|_| LimboError::InternalError("database file lock poisoned".to_string()))
    }
}

fn to_i32(n: usize) -> TursoResult<i32> {
    i32::try_from(n).map_err(|_| LimboError::InternalError("I/O length overflows i32".into()))
}

impl TursoFileIo for WebFile {
    // A single opener per database is enforced by the caller, as in the
    // browser storage and IndexedDB stores.
    fn lock_file(&self, _exclusive: bool) -> TursoResult<()> {
        Ok(())
    }

    fn unlock_file(&self) -> TursoResult<()> {
        Ok(())
    }

    fn pread(&self, pos: u64, c: Completion) -> TursoResult<Completion> {
        let mut store = self.store()?;
        let size = store.len().map_err(|e| io_error(e, "pread"))?;
        let buf = c.as_read().buf().as_mut_slice();
        let n = (buf.len() as u64).min(size.saturating_sub(pos)) as usize;
        store
            .read_exact_at(pos, &mut buf[..n])
            .map_err(|e| io_error(e, "pread"))?;
        c.complete(to_i32(n)?);
        Ok(c)
    }

    fn pwrite(&self, pos: u64, buffer: Arc<Buffer>, c: Completion) -> TursoResult<Completion> {
        let mut store = self.store()?;
        store
            .write_all_at(pos, buffer.as_slice())
            .map_err(|e| io_error(e, "pwrite"))?;
        c.complete(to_i32(buffer.as_slice().len())?);
        Ok(c)
    }

    fn sync(&self, c: Completion, _sync_type: FileSyncType) -> TursoResult<Completion> {
        self.store()?.sync().map_err(|e| io_error(e, "sync"))?;
        c.complete(0);
        Ok(c)
    }

    fn size(&self) -> TursoResult<u64> {
        self.store()?.len().map_err(|e| io_error(e, "size"))
    }

    fn truncate(&self, len: u64, c: Completion) -> TursoResult<Completion> {
        self.store()?
            .set_len(len)
            .map_err(|e| io_error(e, "truncate"))?;
        c.complete(0);
        Ok(c)
    }
}
