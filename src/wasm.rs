/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! JavaScript bindings, for use from a browser with `wasm-bindgen`.
//!
//! ```js
//! import init, { Keyring } from "./pkg/cryptex.js";
//! await init();
//!
//! const keyring = await Keyring.open(
//!   "password=mysecret salt=0okm9ijn8uhb7ygv",
//!   "settings",
//!   { backend: "turso", store: "indexeddb" },
//! );
//! await keyring.set("api-token", new TextEncoder().encode("secret"));
//! const token = keyring.get("api-token");
//! await keyring.close();
//! ```
//!
//! Backends:
//!
//! | `backend` | what it is |
//! | --- | --- |
//! | `turso` (default) | a Turso database, encrypted with the key from the connection string |
//! | `memory` | an encrypted image in memory, no database |
//!
//! Stores, in order of preference:
//!
//! | `store` | where the image lives | works in |
//! | --- | --- | --- |
//! | `indexeddb` (default) | IndexedDB, one image per keyring, guarded by a Web Lock | page and worker |
//! | `localstorage` | `localStorage`, one string per keyring | page only |
//! | `opfs` | origin private file system, one file per keyring | worker only, `backend: "turso"` only |
//! | `memory` | nowhere: the keyring is gone when the page unloads | page and worker |
//!
//! Every store keeps the image encrypted; the key comes from the password (or
//! raw key) in the connection string. What a store protects against is other
//! origins and other users, not scripts running on the same origin: any script
//! there can read IndexedDB, OPFS and `localStorage`.
//!
//! Deriving the key runs Argon2, which blocks the thread it runs on. Open the
//! keyring in a worker (or with default parameters) to keep the page
//! responsive.

use js_sys::Reflect;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::DynKeyRing;
use crate::error::KeyRingError;
use crate::indexeddb::SnapshotStore;
use crate::memory::MemoryKeyring;
use crate::turso::TursoKeyring;
use crate::web_storage::{self, LocalStorageImage};

/// A keyring, opened from JavaScript.
#[wasm_bindgen]
pub struct Keyring {
    inner: Inner,
}

enum Inner {
    /// A Turso keyring plus the store its image is written to.
    Turso {
        /// `None` once the keyring is closed: dropping it releases the
        /// database, and with it an OPFS handle or an IndexedDB lock.
        keyring: Option<TursoKeyring>,
        store: Store,
        dirty: bool,
    },
    Memory {
        keyring: MemoryKeyring,
        store: Store,
        dirty: bool,
    },
}

enum Store {
    /// The keyring persists itself, or is not persisted at all.
    None,
    /// The database is an OPFS file; it holds its own data.
    Opfs,
    IndexedDb(SnapshotStore),
    LocalStorage(LocalStorageImage),
}

#[wasm_bindgen]
impl Keyring {
    /// Open the keyring called `name`, creating it on first use.
    ///
    /// `connection` is a connection string such as
    /// `password=mysecret salt=0okm9ijn8uhb7ygv`. `options` may name a
    /// `backend` and a `store`; both default as shown above. A stored keyring
    /// is refused with an `AccessDenied` error when the key is wrong.
    #[wasm_bindgen(js_name = "open")]
    pub async fn open(connection: &str, name: &str, options: JsValue) -> Result<Keyring, JsError> {
        let options = Options::parse(options)?;
        let name = if name.is_empty() { "default" } else { name };
        match options.backend {
            Backend::Turso => open_turso(connection, name, options.store).await,
            Backend::Memory => open_memory(connection, name, options.store).await,
        }
    }

    /// Reopen a keyring from an image returned by [`export`](Self::export).
    ///
    /// Only `backend` is consulted: the image is used as given, so nothing is
    /// read from storage and nothing is written until the first change.
    #[wasm_bindgen(js_name = "import")]
    pub async fn import(
        connection: &str,
        image: &[u8],
        options: JsValue,
    ) -> Result<Keyring, JsError> {
        let options = Options::parse(options)?;
        match options.backend {
            Backend::Turso => {
                let keyring =
                    TursoKeyring::from_bytes(image, &turso_params(connection)?).map_err(js)?;
                Ok(Keyring {
                    inner: Inner::Turso {
                        keyring: Some(keyring),
                        store: Store::None,
                        dirty: false,
                    },
                })
            }
            Backend::Memory => {
                let keyring =
                    MemoryKeyring::import(image, &memory_secret(connection)?).map_err(js)?;
                Ok(Keyring {
                    inner: Inner::Memory {
                        keyring,
                        store: Store::None,
                        dirty: false,
                    },
                })
            }
        }
    }

    /// Read a secret. Throws `ItemNotFound` when there is none.
    pub fn get(&mut self, id: &str) -> Result<Vec<u8>, JsError> {
        let secret = match &mut self.inner {
            Inner::Turso { keyring, .. } => keyring.as_mut().ok_or_else(closed)?.get_secret(id),
            Inner::Memory { keyring, .. } => keyring.get_secret(id),
        }
        .map_err(js)?;
        let value: Zeroizing<Vec<u8>> = Zeroizing::new(secret.0.clone());
        Ok(value.to_vec())
    }

    /// Store a secret, replacing any previous value.
    ///
    /// Resolves once the change has reached storage, so a resolved promise
    /// means the secret survives a reload.
    pub async fn set(&mut self, id: &str, secret: &[u8]) -> Result<(), JsError> {
        match &mut self.inner {
            Inner::Turso {
                keyring,
                store,
                dirty,
            } => {
                let keyring = keyring.as_mut().ok_or_else(closed)?;
                keyring.set_secret(id, secret).map_err(js)?;
                *dirty = true;
                flush(store, dirty, || keyring.export()).await
            }
            Inner::Memory {
                keyring,
                store,
                dirty,
            } => {
                keyring.set_secret(id, secret).map_err(js)?;
                *dirty = true;
                let keyring = &*keyring;
                flush(store, dirty, || keyring.export()).await
            }
        }
    }

    /// Remove a secret. Resolves once storage has been updated.
    pub async fn delete(&mut self, id: &str) -> Result<(), JsError> {
        match &mut self.inner {
            Inner::Turso {
                keyring,
                store,
                dirty,
            } => {
                let keyring = keyring.as_mut().ok_or_else(closed)?;
                keyring.delete_secret(id).map_err(js)?;
                *dirty = true;
                flush(store, dirty, || keyring.export()).await
            }
            Inner::Memory {
                keyring,
                store,
                dirty,
            } => {
                keyring.delete_secret(id).map_err(js)?;
                *dirty = true;
                let keyring = &*keyring;
                flush(store, dirty, || keyring.export()).await
            }
        }
    }

    /// Re-encrypt under a new connection string and store the result.
    ///
    /// Nothing changes if the new key cannot be applied. An OPFS keyring
    /// cannot be rekeyed in place: create a keyring with a new name and copy
    /// the secrets into it.
    pub async fn rekey(&mut self, connection: &str) -> Result<(), JsError> {
        match &mut self.inner {
            Inner::Turso {
                keyring,
                store,
                dirty,
            } => {
                if matches!(store, Store::Opfs) {
                    return Err(JsError::new(
                        "GeneralError: an OPFS keyring cannot be rekeyed in place; \
                         open a keyring with a new name and copy the secrets into it",
                    ));
                }
                let params = turso_params(connection)?;
                let keyring = keyring.as_mut().ok_or_else(closed)?;
                // Build the replacement first: if it fails, the keyring the
                // caller holds is untouched.
                let rekeyed = keyring.copy_under(&params).map_err(js)?;
                *keyring = rekeyed;
                *dirty = true;
                flush(store, dirty, || keyring.export()).await
            }
            Inner::Memory {
                keyring,
                store,
                dirty,
            } => {
                keyring.rekey(&memory_params(connection)?).map_err(js)?;
                *dirty = true;
                let keyring = &*keyring;
                flush(store, dirty, || keyring.export()).await
            }
        }
    }

    /// Every id in this keyring, in order.
    pub fn keys(&self) -> Result<Vec<String>, JsError> {
        match &self.inner {
            Inner::Turso { keyring, .. } => keyring.as_ref().ok_or_else(closed)?.keys().map_err(js),
            Inner::Memory { keyring, .. } => Ok(keyring.keys()),
        }
    }

    /// Copy the encrypted image out, e.g. to move it to another store.
    pub fn export(&self) -> Result<Vec<u8>, JsError> {
        match &self.inner {
            Inner::Turso { keyring, .. } => {
                keyring.as_ref().ok_or_else(closed)?.export().map_err(js)
            }
            Inner::Memory { keyring, .. } => keyring.export().map_err(js),
        }
    }

    /// Flush any pending change and release the store.
    ///
    /// A keyring holding a Web Lock releases it here, letting another tab
    /// open the same name. The keyring still answers reads and writes, but it
    /// no longer has anywhere to persist them.
    pub async fn close(&mut self) -> Result<(), JsError> {
        match &mut self.inner {
            Inner::Turso {
                keyring,
                store,
                dirty,
            } => {
                if let Some(keyring) = keyring.as_ref() {
                    flush(store, dirty, || keyring.export()).await?;
                }
                *keyring = None;
                release(store).await;
            }
            Inner::Memory {
                keyring,
                store,
                dirty,
            } => {
                // The secrets stay readable; they just have nowhere to go.
                flush(store, dirty, || keyring.export()).await?;
                release(store).await;
            }
        }
        Ok(())
    }
}

/// Ask the browser not to evict this origin's storage.
///
/// Browsers may grant it silently, prompt, or refuse. Call it while the user
/// is interacting with the page; without it a browser under storage pressure
/// can delete the keyring.
#[wasm_bindgen(js_name = "requestPersistentStorage")]
pub async fn request_persistent_storage() -> Result<bool, JsError> {
    web_storage::request_persistent_storage().await.map_err(js)
}

/// Every keyring IndexedDB holds for this origin, in name order.
///
/// Works without opening anything, so a page can list what is stored before
/// the user picks one.
#[wasm_bindgen(js_name = "storedKeyrings")]
pub async fn stored_keyrings() -> Result<Vec<String>, JsError> {
    SnapshotStore::list_names().await.map_err(js)
}

async fn open_turso(connection: &str, name: &str, store: StoreKind) -> Result<Keyring, JsError> {
    let params = turso_params(connection)?;
    let (keyring, store) = match store {
        StoreKind::IndexedDb => {
            let snapshot = SnapshotStore::open(name).await.map_err(js)?;
            let keyring = match snapshot.load().await.map_err(js)? {
                Some(image) => TursoKeyring::from_bytes(&image, &params).map_err(js)?,
                None => TursoKeyring::in_memory(&params).map_err(js)?,
            };
            (keyring, Store::IndexedDb(snapshot))
        }
        StoreKind::LocalStorage => {
            let image = LocalStorageImage::new(Some(name))?;
            let keyring = match image.load()? {
                Some(bytes) => TursoKeyring::from_bytes(&bytes, &params).map_err(js)?,
                None => TursoKeyring::in_memory(&params).map_err(js)?,
            };
            (keyring, Store::LocalStorage(image))
        }
        StoreKind::Opfs => {
            let keyring = TursoKeyring::open_opfs(&params, name).await.map_err(js)?;
            (keyring, Store::Opfs)
        }
        StoreKind::Memory => (TursoKeyring::in_memory(&params).map_err(js)?, Store::None),
    };
    Ok(Keyring {
        inner: Inner::Turso {
            keyring: Some(keyring),
            store,
            dirty: false,
        },
    })
}

async fn open_memory(connection: &str, name: &str, store: StoreKind) -> Result<Keyring, JsError> {
    let params = memory_params(connection)?;
    let secret = memory_secret(connection)?;
    let (keyring, store) = match store {
        StoreKind::IndexedDb => {
            let snapshot = SnapshotStore::open(name).await.map_err(js)?;
            let keyring = match snapshot.load().await.map_err(js)? {
                Some(image) => MemoryKeyring::import(&image, &secret).map_err(js)?,
                None => MemoryKeyring::with_params(&params).map_err(js)?,
            };
            (keyring, Store::IndexedDb(snapshot))
        }
        StoreKind::LocalStorage => {
            let image = LocalStorageImage::new(Some(name))?;
            let keyring = match image.load()? {
                Some(bytes) => MemoryKeyring::import(&bytes, &secret).map_err(js)?,
                None => MemoryKeyring::with_params(&params).map_err(js)?,
            };
            (keyring, Store::LocalStorage(image))
        }
        StoreKind::Memory => (
            MemoryKeyring::with_params(&params).map_err(js)?,
            Store::None,
        ),
        // Refused when the options are parsed; OPFS stores database files.
        StoreKind::Opfs => {
            return Err(JsError::new(
                "TypeError: the opfs store needs backend: \"turso\"",
            ));
        }
    };
    Ok(Keyring {
        inner: Inner::Memory {
            keyring,
            store,
            dirty: false,
        },
    })
}

/// Drop the store, releasing a Web Lock only once the browser has done so.
async fn release(store: &mut Store) {
    if let Store::IndexedDb(snapshot) = store {
        snapshot.release().await;
    }
    *store = Store::None;
}

/// Write the keyring's current image to its store.
///
/// Nothing to do for a keyring that keeps its own data (OPFS) or has no store:
/// `image` is only called when a store actually needs a copy.
async fn flush(
    store: &Store,
    dirty: &mut bool,
    image: impl FnOnce() -> Result<Vec<u8>, KeyRingError>,
) -> Result<(), JsError> {
    if !*dirty {
        return Ok(());
    }
    match store {
        Store::None | Store::Opfs => {}
        Store::IndexedDb(snapshot) => snapshot.save(&image().map_err(js)?).await.map_err(js)?,
        Store::LocalStorage(local) => local.save(&image().map_err(js)?)?,
    }
    *dirty = false;
    Ok(())
}

#[derive(Clone, Copy)]
enum Backend {
    Turso,
    Memory,
}

#[derive(Clone, Copy)]
enum StoreKind {
    IndexedDb,
    LocalStorage,
    Opfs,
    Memory,
}

struct Options {
    backend: Backend,
    store: StoreKind,
}

impl Options {
    fn parse(options: JsValue) -> Result<Self, JsError> {
        let mut parsed = Self {
            backend: Backend::Turso,
            store: StoreKind::IndexedDb,
        };
        if options.is_undefined() || options.is_null() {
            return Ok(parsed);
        }
        if let Some(backend) = string_property(&options, "backend")? {
            parsed.backend = match backend.as_str() {
                "turso" => Backend::Turso,
                "memory" => Backend::Memory,
                other => return Err(unknown("backend", other)),
            };
        }
        if let Some(store) = string_property(&options, "store")? {
            parsed.store = match store.as_str() {
                "indexeddb" => StoreKind::IndexedDb,
                "localstorage" => StoreKind::LocalStorage,
                "opfs" => StoreKind::Opfs,
                "memory" => StoreKind::Memory,
                other => return Err(unknown("store", other)),
            };
        }
        // OPFS holds database files, so it needs a database backend.
        if matches!(parsed.store, StoreKind::Opfs) && matches!(parsed.backend, Backend::Memory) {
            return Err(JsError::new(
                "TypeError: the opfs store needs backend: \"turso\"",
            ));
        }
        Ok(parsed)
    }
}

fn string_property(value: &JsValue, name: &str) -> Result<Option<String>, JsError> {
    let property =
        Reflect::get(value, &JsValue::from_str(name)).map_err(|e| js(KeyRingError::from(e)))?;
    if property.is_undefined() || property.is_null() {
        return Ok(None);
    }
    property
        .as_string()
        .map(Some)
        .ok_or_else(|| JsError::new(&format!("TypeError: options.{name} must be a string")))
}

fn unknown(field: &str, value: &str) -> JsError {
    JsError::new(&format!(
        "TypeError: unknown {field} '{value}'; expected one of the documented values"
    ))
}

fn turso_params(connection: &str) -> Result<crate::turso::ConnectionParams, JsError> {
    connection.parse().map_err(js)
}

fn memory_params(connection: &str) -> Result<crate::memory::ConnectionParams, JsError> {
    connection.parse().map_err(js)
}

/// The password or raw key from a connection string, for a memory keyring.
fn memory_secret(connection: &str) -> Result<Vec<u8>, JsError> {
    let params = memory_params(connection)?;
    Ok(if params.key.is_empty() {
        params.password.clone()
    } else {
        params.key.clone()
    })
}

fn closed() -> JsError {
    JsError::new("GeneralError: the keyring is closed")
}

fn js(error: KeyRingError) -> JsError {
    // Keep the kind as the first word so JavaScript can switch on it.
    let kind = match &error {
        KeyRingError::ItemNotFound => "ItemNotFound",
        KeyRingError::AccessDenied { .. } => "AccessDenied",
        KeyRingError::GeneralError { .. } => "GeneralError",
    };
    JsError::new(&format!("{kind}: {error}"))
}
