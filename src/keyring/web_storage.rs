/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! A keyring kept in browser `localStorage`.
//!
//! The whole keyring is an encrypted image ([`MemoryKeyring::export`]) that is
//! rewritten whenever a secret changes. It is the simplest browser backend:
//! no worker and no asynchronous API, so it fits code that must stay
//! synchronous, such as an `onclick` handler.
//!
//! ```no_run
//! # use cryptex::web_storage::WebStorageKeyring;
//! # use cryptex::KeyRing;
//! let mut keyring = WebStorageKeyring::with_params(
//!     &"password=mysecret salt=0okm9ijn8uhb7ygv".parse()?,
//!     Some("settings"),
//! )?;
//! keyring.set_secret("api-token", b"secret")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! `localStorage` belongs to the page, not to the worker: a web worker has no
//! `localStorage` at all. Use the [`indexeddb`](crate::indexeddb) store from a
//! worker instead.
//!
//! Every script on the origin can read `localStorage`, and browsers evict it
//! under storage pressure unless the site has been granted persistent storage
//! ([`request_persistent_storage`]). The image is encrypted, so what a script
//! gets is ciphertext.
//!
//! There is no cross-tab lock here: the whole image is rewritten on every
//! change, so two tabs on one name would lose each other's secrets. Take the
//! `cryptex:<name>` Web Lock first, as the JavaScript `Keyring` does, or give
//! each tab its own name.

use super::cipher::CipherAlgorithm;
use super::file_common;
use super::memory::MemoryKeyring;
use crate::KeyRingSecret;
use crate::error::KeyRingError;
use crate::{DynKeyRing, NewKeyRing, Result};
use wasm_bindgen::JsCast;

/// Connection parameters for [`WebStorageKeyring`].
pub type ConnectionParams = file_common::ConnectionParams<CipherAlgorithm>;

/// `localStorage` key used when no name is given.
pub const DEFAULT_NAME: &str = "cryptex";

/// The encrypted image of a keyring, kept in one `localStorage` entry.
///
/// The image is the same blob [`MemoryKeyring::export`] and
/// [`TursoKeyring::export`](crate::turso::TursoKeyring::export) produce, so a
/// Turso keyring can use this store too.
pub struct LocalStorageImage {
    entry: String,
}

impl LocalStorageImage {
    /// Name the entry for a keyring called `name` (default [`DEFAULT_NAME`]).
    pub fn new(name: Option<&str>) -> Result<Self> {
        Ok(Self {
            entry: entry_name(name),
        })
    }

    /// The `localStorage` key this image is stored under.
    pub fn entry(&self) -> &str {
        &self.entry
    }

    /// Read the stored image, if there is one.
    pub fn load(&self) -> Result<Option<Vec<u8>>> {
        let storage = storage()?;
        match storage.get_item(&self.entry).map_err(js_error)? {
            Some(encoded) => hex::decode(encoded).map(Some).map_err(|_| invalid_blob()),
            None => Ok(None),
        }
    }

    /// Write an image, replacing any previous one.
    pub fn save(&self, image: &[u8]) -> Result<()> {
        storage()?
            .set_item(&self.entry, &hex::encode(image))
            .map_err(|e| match js_error(e) {
                KeyRingError::GeneralError { msg } => KeyRingError::GeneralError {
                    msg: format!("unable to store the keyring in localStorage: {msg}"),
                },
                other => other,
            })
    }

    /// Remove the stored image.
    pub fn delete(&self) -> Result<()> {
        storage()?.remove_item(&self.entry).map_err(js_error)
    }
}

/// A keyring whose image lives in `localStorage`.
pub struct WebStorageKeyring {
    inner: MemoryKeyring,
    image: LocalStorageImage,
}

impl WebStorageKeyring {
    /// Open the keyring called `name` (default [`DEFAULT_NAME`]), creating it
    /// on first use.
    ///
    /// A stored image is decrypted with the password or key in `params`; a
    /// wrong one returns [`KeyRingError::AccessDenied`].
    pub fn with_params(params: &ConnectionParams, name: Option<&str>) -> Result<Self> {
        let image = LocalStorageImage::new(name)?;
        let inner = match image.load()? {
            Some(blob) => MemoryKeyring::import(&blob, password_or_key(params)),
            None => MemoryKeyring::with_params(params),
        }?;
        Ok(Self { inner, image })
    }

    /// The `localStorage` key this keyring is stored under.
    pub fn entry(&self) -> &str {
        self.image.entry()
    }

    /// Copy the encrypted image out, e.g. to move it to another backend.
    pub fn export(&self) -> Result<Vec<u8>> {
        self.inner.export()
    }

    /// Re-encrypt under new connection parameters and store the result.
    pub fn rekey(&mut self, params: &ConnectionParams) -> Result<()> {
        self.inner.rekey(params)?;
        self.persist()
    }

    /// The cipher the stored image is sealed with.
    pub fn cipher(&self) -> CipherAlgorithm {
        self.inner.cipher()
    }

    /// Remove the stored image, leaving this keyring's contents in memory.
    pub fn forget(&self) -> Result<()> {
        self.image.delete()
    }

    fn persist(&self) -> Result<()> {
        self.image.save(&self.inner.export()?)
    }
}

impl DynKeyRing for WebStorageKeyring {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        self.inner.get_secret(id)
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        self.inner.set_secret(id, secret)?;
        self.persist()
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        self.inner.delete_secret(id)?;
        self.persist()
    }
}

impl NewKeyRing for WebStorageKeyring {
    fn new<S: AsRef<str>>(lock_key: S) -> Result<Self> {
        let params = lock_key.as_ref().parse::<ConnectionParams>()?;
        Self::with_params(&params, None)
    }
}

fn entry_name(name: Option<&str>) -> String {
    format!("cryptex:{}", name.unwrap_or(DEFAULT_NAME))
}

fn password_or_key(params: &ConnectionParams) -> &[u8] {
    if params.key.is_empty() {
        &params.password
    } else {
        &params.key
    }
}

/// Ask the browser not to evict this origin's storage under pressure.
///
/// Browsers grant this silently, prompt, or refuse; the answer is returned as
/// given.
pub async fn request_persistent_storage() -> Result<bool> {
    let storage_manager = js_sys::Reflect::get(
        &js_sys::global(),
        &wasm_bindgen::JsValue::from_str("navigator"),
    )
    .ok()
    .and_then(|navigator| {
        js_sys::Reflect::get(&navigator, &wasm_bindgen::JsValue::from_str("storage")).ok()
    })
    .ok_or_else(|| KeyRingError::GeneralError {
        msg: "this browser has no Storage Manager API".to_string(),
    })?;
    let persist = js_sys::Reflect::get(
        &storage_manager,
        &wasm_bindgen::JsValue::from_str("persist"),
    )
    .map_err(js_error)?
    .dyn_into::<js_sys::Function>()
    .map_err(|_| KeyRingError::GeneralError {
        msg: "this browser cannot persist storage".to_string(),
    })?;
    let granted = persist
        .call0(&storage_manager)
        .map_err(js_error)?
        .dyn_into::<js_sys::Promise>()
        .map_err(js_error)?;
    let value = wasm_bindgen_futures::JsFuture::from(granted)
        .await
        .map_err(js_error)?;
    Ok(value.as_bool().unwrap_or(false))
}

/// Names of every keyring this origin keeps in `localStorage`.
///
/// Reads the entry names only, never the images. A keyring entry is
/// `cryptex:<name>`, the key [`LocalStorageImage`] writes for that name.
pub fn list_names() -> Result<Vec<String>> {
    const PREFIX: &str = "cryptex:";

    let storage = storage()?;
    let length = storage.length().map_err(js_error)?;
    let mut names = Vec::new();
    for index in 0..length {
        if let Some(name) = storage
            .key(index)
            .map_err(js_error)?
            .and_then(|key| key.strip_prefix(PREFIX).map(str::to_string))
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn storage() -> Result<web_sys::Storage> {
    let window = web_sys::window().ok_or_else(|| KeyRingError::GeneralError {
        msg: "localStorage is not available here: it exists only on a page, not in a worker"
            .to_string(),
    })?;
    window
        .local_storage()
        .map_err(js_error)?
        .ok_or_else(|| KeyRingError::GeneralError {
            msg: "this browser blocks localStorage for the origin; cookies or private mode may be disabled"
                .to_string(),
        })
}

fn js_error(value: wasm_bindgen::JsValue) -> KeyRingError {
    KeyRingError::from(value)
}

fn invalid_blob() -> KeyRingError {
    KeyRingError::AccessDenied {
        msg: "the stored keyring is corrupt: its image could not be decoded".to_string(),
    }
}
