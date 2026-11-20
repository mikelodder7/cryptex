/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Origin Private File System storage for a Turso keyring.
//!
//! OPFS is a real filesystem owned by the origin. Its synchronous access
//! handles are the only way to read and write files without awaiting every
//! call, and browsers only hand them out inside a worker — which is exactly
//! where a keyring belongs, since deriving a key with Argon2 would otherwise
//! freeze the page.
//!
//! ```no_run
//! # use cryptex::turso::TursoKeyring;
//! # use cryptex::KeyRing;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let params = "password=mysecret salt=0okm9ijn8uhb7ygv".parse()?;
//! let mut keyring = TursoKeyring::open_opfs(&params, "settings").await?;
//! keyring.set_secret("api-token", b"secret")?;
//! # Ok(())
//! # }
//! ```
//!
//! Files live under `cryptex/` in the origin's private filesystem, as
//! `<name>.db3` plus the `<name>.db3-wal` Turso keeps next to it. Holding the
//! sync access handle is itself exclusive: a second tab or worker that tries
//! to open the same keyring gets an error from the browser instead of
//! corrupting the file, so no separate lock file is needed.
//!
//! Like every browser store, OPFS is readable by any script on the origin, so
//! the pages stay encrypted and the key never leaves the password.

use super::page_store::PageStore;
use super::web_time::WebClock;
use crate::Result;
use crate::error::KeyRingError;
use ::turso::core::io::FileId;
use ::turso::core::{
    Clock, File as TursoFileIo, LimboError, MonotonicInstant, WallClockInstant, io_error,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemGetDirectoryOptions, FileSystemGetFileOptions,
    FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
};

/// Directory inside the origin's private filesystem.
const DIRECTORY: &str = "cryptex";

thread_local! {
    /// Handles are `!Send`, so they live here and the store keeps only an id.
    /// Wasm runs one thread, so a thread-local is the whole registry.
    static HANDLES: RefCell<HashMap<u32, FileSystemSyncAccessHandle>> =
        RefCell::new(HashMap::new());
    static NEXT_ID: Cell<u32> = const { Cell::new(1) };
}

/// A [`PageStore`] over one OPFS file's synchronous access handle.
pub(crate) struct OpfsPages {
    id: u32,
}

impl OpfsPages {
    /// Open (creating if needed) `name` inside the cryptex directory.
    async fn open(name: &str) -> Result<Self> {
        let directory = open_directory().await?;
        let options = FileSystemGetFileOptions::new();
        options.set_create(true);
        let handle: web_sys::FileSystemFileHandle =
            JsFuture::from(directory.get_file_handle_with_options(name, &options))
                .await
                .map_err(js_error)?
                .dyn_into()
                .map_err(js_error)?;

        let access: FileSystemSyncAccessHandle =
            JsFuture::from(handle.create_sync_access_handle())
                .await
                .map_err(|e| {
                    KeyRingError::AccessDenied {
                        msg: format!(
                            "unable to take exclusive access to {name} in OPFS (is another tab or worker using it?): {}",
                            js_message(e)
                        ),
                    }
                })?
                .dyn_into()
                .map_err(js_error)?;

        let id = NEXT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1));
            id
        });
        HANDLES.with(|handles| handles.borrow_mut().insert(id, access));
        Ok(Self { id })
    }

    /// Release the handle, closing the file.
    pub(crate) fn close(&self) {
        if let Some(handle) = HANDLES.with(|handles| handles.borrow_mut().remove(&self.id)) {
            handle.close();
        }
    }

    fn with_handle<T>(
        &self,
        op: &str,
        f: impl FnOnce(&FileSystemSyncAccessHandle) -> std::result::Result<T, wasm_bindgen::JsValue>,
    ) -> io::Result<T> {
        HANDLES.with(|handles| {
            let handles = handles.borrow();
            let handle = handles.get(&self.id).ok_or_else(|| {
                io::Error::other(format!("the OPFS handle is closed, cannot {op}"))
            })?;
            f(handle).map_err(|e| io::Error::other(js_message(e)))
        })
    }
}

impl PageStore for OpfsPages {
    fn len(&self) -> io::Result<u64> {
        self.with_handle("size the file", |handle| handle.get_size())
            .map(|size| size as u64)
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let options = FileSystemReadWriteOptions::new();
            options.set_at((offset as usize + filled) as f64);
            let read = self.with_handle("read", |handle| {
                handle.read_with_u8_array_and_options(&mut buf[filled..], &options)
            })? as usize;
            if read == 0 {
                // Past the end of the file: zero-fill, like a sparse file.
                buf[filled..].fill(0);
                return Ok(());
            }
            filled += read;
        }
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let options = FileSystemReadWriteOptions::new();
            options.set_at((offset as usize + written) as f64);
            let n = self.with_handle("write", |handle| {
                handle.write_with_u8_array_and_options(&buf[written..], &options)
            })? as usize;
            if n == 0 {
                return Err(io::Error::other("OPFS accepted no bytes"));
            }
            written += n;
        }
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.with_handle("resize the file", |handle| {
            handle.truncate_with_f64(len as f64)
        })
    }

    fn sync(&mut self) -> io::Result<()> {
        self.with_handle("flush the file", |handle| handle.flush())
    }
}

/// The Turso [`IO`](::turso::core::IO) backed by OPFS.
///
/// Both files Turso needs are opened up front, because a sync access handle is
/// obtained asynchronously: `open_file` itself cannot await.
pub(crate) struct OpfsIo {
    files: HashMap<String, Arc<OpfsFile>>,
}

impl OpfsIo {
    /// Open `<name>.db3` and its WAL under `cryptex/`.
    pub(crate) async fn open(name: &str) -> Result<Self> {
        let db = format!("{name}.db3");
        let wal = format!("{db}-wal");
        let mut files = HashMap::new();
        for path in [db, wal] {
            let pages = OpfsPages::open(&path).await?;
            files.insert(path, Arc::new(OpfsFile::new(pages)));
        }
        Ok(Self { files })
    }

    /// Flush both files to disk and release their handles.
    pub(crate) fn close(&mut self) {
        for file in self.files.values() {
            file.close();
        }
        self.files.clear();
    }
}

impl Drop for OpfsIo {
    fn drop(&mut self) {
        self.close();
    }
}

impl Clock for OpfsIo {
    fn current_time_monotonic(&self) -> MonotonicInstant {
        WebClock.current_time_monotonic()
    }

    fn current_time_wall_clock(&self) -> WallClockInstant {
        WebClock.current_time_wall_clock()
    }
}

impl ::turso::core::IO for OpfsIo {
    fn open_file(
        &self,
        path: &str,
        _flags: ::turso::core::OpenFlags,
        _direct: bool,
    ) -> std::result::Result<Arc<dyn TursoFileIo>, LimboError> {
        // Only the database and its WAL are ever opened: the handle for each
        // had to exist before Turso asked, so an unknown path is a bug in the
        // caller's configuration, not a file to create.
        match self.files.get(path) {
            Some(file) => {
                let file: Arc<OpfsFile> = Arc::clone(file);
                Ok(file)
            }
            None => Err(LimboError::InternalError(format!(
                "the OPFS keyring did not prepare '{path}'; it opens only the database and its WAL"
            ))),
        }
    }

    fn remove_file(&self, _path: &str) -> std::result::Result<(), LimboError> {
        Err(LimboError::InternalError(
            "an OPFS keyring is removed through the file system, not Turso".to_string(),
        ))
    }

    fn is_memory(&self) -> bool {
        false
    }

    fn file_id(&self, path: &str) -> std::result::Result<FileId, LimboError> {
        Ok(FileId::from_path_hash(path))
    }
}

/// The Turso file view of one prepared OPFS file.
struct OpfsFile {
    store: Mutex<OpfsPages>,
}

impl OpfsFile {
    fn new(pages: OpfsPages) -> Self {
        Self {
            store: Mutex::new(pages),
        }
    }

    /// Flush and close the handle. The store stays usable but fails every call.
    fn close(&self) {
        if let Ok(mut store) = self.store.lock() {
            let _ = store.sync();
            store.close();
        }
    }

    fn store(&self) -> std::result::Result<MutexGuard<'_, OpfsPages>, LimboError> {
        self.store
            .lock()
            .map_err(|_| LimboError::InternalError("OPFS file lock poisoned".to_string()))
    }
}

fn to_i32(n: usize) -> std::result::Result<i32, LimboError> {
    i32::try_from(n).map_err(|_| LimboError::InternalError("I/O length overflows i32".into()))
}

impl TursoFileIo for OpfsFile {
    // The sync access handle is already exclusive.
    fn lock_file(&self, _exclusive: bool) -> std::result::Result<(), LimboError> {
        Ok(())
    }

    fn unlock_file(&self) -> std::result::Result<(), LimboError> {
        Ok(())
    }

    fn pread(
        &self,
        pos: u64,
        c: ::turso::core::Completion,
    ) -> std::result::Result<::turso::core::Completion, LimboError> {
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

    fn pwrite(
        &self,
        pos: u64,
        buffer: Arc<::turso::core::Buffer>,
        c: ::turso::core::Completion,
    ) -> std::result::Result<::turso::core::Completion, LimboError> {
        let mut store = self.store()?;
        store
            .write_all_at(pos, buffer.as_slice())
            .map_err(|e| io_error(e, "pwrite"))?;
        c.complete(to_i32(buffer.as_slice().len())?);
        Ok(c)
    }

    fn sync(
        &self,
        c: ::turso::core::Completion,
        _sync_type: ::turso::core::io::FileSyncType,
    ) -> std::result::Result<::turso::core::Completion, LimboError> {
        self.store()?.sync().map_err(|e| io_error(e, "sync"))?;
        c.complete(0);
        Ok(c)
    }

    fn size(&self) -> std::result::Result<u64, LimboError> {
        self.store()?.len().map_err(|e| io_error(e, "size"))
    }

    fn truncate(
        &self,
        len: u64,
        c: ::turso::core::Completion,
    ) -> std::result::Result<::turso::core::Completion, LimboError> {
        self.store()?
            .set_len(len)
            .map_err(|e| io_error(e, "truncate"))?;
        c.complete(0);
        Ok(c)
    }
}

async fn open_directory() -> Result<FileSystemDirectoryHandle> {
    let navigator = js_sys::Reflect::get(
        &js_sys::global(),
        &wasm_bindgen::JsValue::from_str("navigator"),
    )
    .map_err(js_error)?;
    let storage = js_sys::Reflect::get(&navigator, &wasm_bindgen::JsValue::from_str("storage"))
        .map_err(js_error)?;
    if storage.is_undefined() {
        return Err(unsupported(
            "this browser has no Storage Manager API, so OPFS is unavailable",
        ));
    }
    let get_directory =
        js_sys::Reflect::get(&storage, &wasm_bindgen::JsValue::from_str("getDirectory"))
            .map_err(js_error)?
            .dyn_into::<js_sys::Function>()
            .map_err(js_error)?;
    let root: FileSystemDirectoryHandle = JsFuture::from(
        get_directory
            .call0(&storage)
            .map_err(js_error)?
            .dyn_into::<js_sys::Promise>()
            .map_err(js_error)?,
    )
    .await
    .map_err(js_error)?
    .dyn_into()
    .map_err(js_error)?;

    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(true);
    let directory = JsFuture::from(root.get_directory_handle_with_options(DIRECTORY, &options))
        .await
        .map_err(js_error)?
        .dyn_into()
        .map_err(js_error)?;
    Ok(directory)
}

fn js_error(value: wasm_bindgen::JsValue) -> KeyRingError {
    KeyRingError::from(value)
}

fn js_message(value: wasm_bindgen::JsValue) -> String {
    KeyRingError::from(value).as_str()
}

fn unsupported(msg: &str) -> KeyRingError {
    KeyRingError::GeneralError {
        msg: msg.to_string(),
    }
}
