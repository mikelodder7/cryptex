/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Durable keyring images in IndexedDB, for browsers.
//!
//! A browser tab has no filesystem, so a keyring is persisted as one image:
//! the bytes [`TursoKeyring::export`](crate::turso::TursoKeyring::export)
//! produces. This module stores that image and takes an exclusive Web Lock
//! named after the keyring, so two tabs cannot open the same keyring at the
//! same time and overwrite each other.
//!
//! ```no_run
//! # use cryptex::indexeddb::SnapshotStore;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let store = SnapshotStore::open("settings").await?;
//! if let Some(image) = store.load().await? {
//!     // pass the image to TursoKeyring::from_bytes
//!     # let _ = image;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! IndexedDB is per origin and readable by every script that runs on it, so
//! the image must stay encrypted: the key never leaves the password or raw
//! key the caller passes to the keyring.

use js_sys::Reflect;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbDatabase, IdbFactory, IdbRequest, IdbTransaction, IdbTransactionMode};

use crate::Result;
use crate::error::KeyRingError;

/// Database holding every keyring image for this origin.
const DB_NAME: &str = "cryptex";
/// Object store within [`DB_NAME`].
const STORE_NAME: &str = "keyrings";

/// An IndexedDB-backed snapshot of one keyring.
///
/// Opening takes the Web Lock `cryptex:<name>`; it is held until the store is
/// dropped. If another tab holds it, [`open`](Self::open) fails with
/// `AccessDenied` instead of waiting.
pub struct SnapshotStore {
    name: String,
    db: IdbDatabase,
    hold: LockHold,
}

impl SnapshotStore {
    /// Open the store for `name`, taking the single-opener lock.
    pub async fn open(name: &str) -> Result<Self> {
        let hold = LockHold::acquire(&format!("cryptex:{name}")).await?;
        let db = open_db().await?;
        Ok(Self {
            name: name.to_string(),
            db,
            hold,
        })
    }

    /// The name this store was opened under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Release the lock and wait until the browser has done so.
    ///
    /// Releasing is asynchronous: without this wait, opening the same name
    /// again in the same page can still see the old lock and be refused.
    pub async fn release(&mut self) {
        self.hold.release_async().await;
    }

    /// Read the stored image, if there is one.
    pub async fn load(&self) -> Result<Option<Vec<u8>>> {
        let tx = self.transaction(IdbTransactionMode::Readonly)?;
        let value = await_request(
            &tx.object_store(STORE_NAME)?
                .get(&JsValue::from_str(&self.name))?,
        )
        .await?;
        drop(tx);
        if value.is_undefined() || value.is_null() {
            Ok(None)
        } else {
            Ok(Some(js_sys::Uint8Array::new(&value).to_vec()))
        }
    }

    /// Write an image, replacing any previous one. Returns once the
    /// transaction has committed.
    pub async fn save(&self, image: &[u8]) -> Result<()> {
        let tx = self.transaction(IdbTransactionMode::Readwrite)?;
        let bytes = js_sys::Uint8Array::from(image);
        tx.object_store(STORE_NAME)?
            .put_with_key(&bytes, &JsValue::from_str(&self.name))?;
        await_transaction(&tx).await
    }

    /// Remove the stored image.
    pub async fn delete(&self) -> Result<()> {
        let tx = self.transaction(IdbTransactionMode::Readwrite)?;
        tx.object_store(STORE_NAME)?
            .delete(&JsValue::from_str(&self.name))?;
        await_transaction(&tx).await
    }

    fn transaction(&self, mode: IdbTransactionMode) -> Result<IdbTransaction> {
        self.db
            .transaction_with_str_and_mode(STORE_NAME, mode)
            .map_err(js_error)
    }
}

/// The exclusive lock held by a [`SnapshotStore`], released on drop.
///
/// The lock lives as long as the promise the callback returns, so dropping
/// this resolves that promise and lets the next tab in.
struct LockHold {
    /// Resolves the promise the lock callback returned.
    release: std::rc::Rc<std::cell::RefCell<Option<js_sys::Function>>>,
    /// The promise itself: the lock is held until it settles.
    _held: js_sys::Promise,
    /// Resolves once the lock has been released.
    released: js_sys::Promise,
    /// The callback, kept alive because the browser may still call it.
    _callback: JsValue,
}

impl LockHold {
    async fn acquire(name: &str) -> Result<Self> {
        let locks = Reflect::get(&navigator()?, &JsValue::from_str("locks")).map_err(js_error)?;
        if locks.is_undefined() || locks.is_null() {
            return Err(unsupported(
                "this browser has no Web Locks API, so a keyring cannot be opened safely",
            ));
        }
        let request: js_sys::Function = Reflect::get(&locks, &JsValue::from_str("request"))
            .map_err(js_error)?
            .dyn_into()
            .map_err(|_| unsupported("the Web Locks API is not callable"))?;

        let options = js_sys::Object::new();
        Reflect::set(&options, &JsValue::from_str("ifAvailable"), &JsValue::TRUE)
            .map_err(js_error)?;

        // `release` settles the promise the callback returns, ending the lock.
        let release: std::rc::Rc<std::cell::RefCell<Option<js_sys::Function>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let held = js_sys::Promise::new(&mut {
            let release = std::rc::Rc::clone(&release);
            move |resolve, _reject| *release.borrow_mut() = Some(resolve)
        });

        // Resolved once the callback runs, whether or not it got the lock.
        let signalled: std::rc::Rc<std::cell::RefCell<Option<js_sys::Function>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let signal = js_sys::Promise::new(&mut {
            let signalled = std::rc::Rc::clone(&signalled);
            move |resolve, _reject| *signalled.borrow_mut() = Some(resolve)
        });

        let denied = std::rc::Rc::new(std::cell::Cell::new(false));
        let callback = {
            let denied = std::rc::Rc::clone(&denied);
            let held = held.clone();
            let signalled = std::rc::Rc::clone(&signalled);
            Closure::<dyn FnMut(JsValue) -> JsValue>::once_into_js(move |lock: JsValue| {
                if let Some(resolve) = signalled.borrow_mut().take() {
                    let _ = resolve.call0(&JsValue::NULL);
                }
                if lock.is_null() || lock.is_undefined() {
                    denied.set(true);
                    JsValue::UNDEFINED
                } else {
                    JsValue::from(held.clone())
                }
            })
        };

        let request_promise: js_sys::Promise = request
            .call3(
                &locks,
                &JsValue::from_str(name),
                &options,
                callback.unchecked_ref(),
            )
            .map_err(js_error)?
            .dyn_into()
            .map_err(js_error)?;

        // Wait for whichever happens first: the callback runs, or the request
        // itself fails. A granted lock keeps its request pending, so racing is
        // what makes this usable at all.
        let signals = js_sys::Array::of2(&signal, &request_promise);
        JsFuture::from(js_sys::Promise::race(signals.as_ref()))
            .await
            .map_err(js_error)?;

        if denied.get() {
            return Err(KeyRingError::AccessDenied {
                msg: format!("the keyring '{name}' is open in another tab"),
            });
        }
        Ok(Self {
            release,
            _held: held,
            released: request_promise,
            _callback: callback,
        })
    }
}

impl LockHold {
    /// Release the lock and wait for the browser to finish doing so.
    async fn release_async(&mut self) {
        if let Some(release) = self.release.borrow_mut().take() {
            let _ = release.call0(&JsValue::NULL);
        }
        // The request settles only after the lock is gone, so awaiting it is
        // what makes an immediate reopen of the same name work.
        let _ = JsFuture::from(self.released.clone()).await;
    }
}

impl Drop for LockHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.borrow_mut().take() {
            let _ = release.call0(&JsValue::NULL);
        }
    }
}

async fn open_db() -> Result<IdbDatabase> {
    // `indexedDB` hangs off the global object, not off `navigator`.
    let factory: IdbFactory = Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
        .map_err(js_error)?
        .dyn_into()
        .map_err(|_| unsupported("this browser has no IndexedDB"))?;
    let request = factory.open_with_u32(DB_NAME, 1).map_err(js_error)?;

    // Create the object store the first time the database is opened.
    let upgrade_request = request.clone();
    let upgrade = Closure::<dyn FnMut(JsValue)>::once_into_js(move |_event: JsValue| {
        if let Some(db) = upgrade_request
            .result()
            .ok()
            .and_then(|db| db.dyn_into::<IdbDatabase>().ok())
        {
            let _ = db.create_object_store(STORE_NAME);
        }
    });
    request.set_onupgradeneeded(Some(upgrade.unchecked_ref()));

    let db = await_request(&request).await?;
    db.dyn_into::<IdbDatabase>().map_err(js_error)
}

/// The global object: `window` in a page, the worker scope in a worker.
fn navigator() -> Result<JsValue> {
    let global = js_sys::global();
    // Workers expose `navigator` too, so this works in both contexts.
    Reflect::get(&global, &JsValue::from_str("navigator"))
        .map_err(js_error)
        .and_then(|navigator| {
            if navigator.is_undefined() {
                Err(unsupported("no navigator: not a browser context"))
            } else {
                Ok(navigator)
            }
        })
}

/// Resolve a request's promise with `request.result`, rejecting on error.
async fn await_request(request: &IdbRequest) -> Result<JsValue> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let on_success = {
            let request = request.clone();
            let resolve = resolve.clone();
            Closure::<dyn FnMut(JsValue)>::once_into_js(move |_event: JsValue| {
                let value = request.result().unwrap_or(JsValue::NULL);
                let _ = resolve.call1(&JsValue::NULL, &value);
            })
        };
        let on_error = {
            let request = request.clone();
            let reject = reject.clone();
            Closure::<dyn FnMut(JsValue)>::once_into_js(move |_event: JsValue| {
                let err = request
                    .error()
                    .ok()
                    .flatten()
                    .map(JsValue::from)
                    .unwrap_or(JsValue::NULL);
                let _ = reject.call1(&JsValue::NULL, &err);
            })
        };
        request.set_onsuccess(Some(on_success.unchecked_ref()));
        request.set_onerror(Some(on_error.unchecked_ref()));
    });
    JsFuture::from(promise).await.map_err(js_error)
}

/// Wait for a transaction to commit.
async fn await_transaction(tx: &IdbTransaction) -> Result<()> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let on_complete = {
            let resolve = resolve.clone();
            Closure::<dyn FnMut(JsValue)>::once_into_js(move |_event: JsValue| {
                let _ = resolve.call0(&JsValue::NULL);
            })
        };
        let on_error = {
            let tx = tx.clone();
            let reject = reject.clone();
            Closure::<dyn FnMut(JsValue)>::once_into_js(move |_event: JsValue| {
                let err = tx.error().map(JsValue::from).unwrap_or(JsValue::NULL);
                let _ = reject.call1(&JsValue::NULL, &err);
            })
        };
        tx.set_oncomplete(Some(on_complete.unchecked_ref()));
        tx.set_onerror(Some(on_error.unchecked_ref()));
    });
    JsFuture::from(promise).await.map(|_| ()).map_err(js_error)
}

fn js_error(value: JsValue) -> KeyRingError {
    KeyRingError::from(value)
}

fn unsupported(msg: &str) -> KeyRingError {
    KeyRingError::GeneralError {
        msg: msg.to_string(),
    }
}
