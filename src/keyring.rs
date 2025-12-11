/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

mod keyringsecret;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(feature = "file")]
pub mod sqlcipher;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
#[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
pub use self::macos::MacOsKeyRing as OsKeyRing;

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
pub use self::linux::LinuxOsKeyRing as OsKeyRing;

#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(target_os = "windows")))]
pub use self::windows::WindowsOsKeyRing as OsKeyRing;

use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, crate::error::KeyRingError>;

pub use keyringsecret::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use users::{get_current_username, get_effective_username};

/// Return the OS keyring if available
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "windows"))))]
pub fn get_os_keyring(service: &str) -> Result<OsKeyRing> {
    OsKeyRing::new(service)
}

/// Return the OS keyring if available
#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
pub fn get_os_keyring(service: &str) -> Result<OsKeyRing<'_>> {
    OsKeyRing::new(service)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("no keyring implementation is available for this platform");

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_username() -> String {
    fn get_current_user() -> String {
        match get_current_username() {
            Some(s) => s.into_string().unwrap_or_else(|_| whoami::username()),
            None => whoami::username(),
        }
    }

    match get_effective_username() {
        Some(s) => s.into_string().unwrap_or_else(|_| get_current_user()),
        None => get_current_user(),
    }
}

#[cfg(feature = "file")]
pub const fn allows_file() -> bool {
    true
}

#[cfg(not(feature = "file"))]
pub const fn allows_file() -> bool {
    false
}

/// A trait for all key rings
pub trait KeyRing: Send + Sync {
    fn get_secret<S: AsRef<str>>(&mut self, id: S) -> Result<KeyRingSecret>;

    fn set_secret<S: AsRef<str>, B: AsRef<[u8]>>(&mut self, id: S, secret: B) -> Result<()>;

    fn delete_secret<S: AsRef<str>>(&mut self, id: S) -> Result<()>;
}

/// Modification of [`KeyRing`] trait suitable for trait Objects. Implementers
/// should use this trait and [`KeyRing`] will be implemented automatically
pub trait DynKeyRing: Send + Sync {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret>;

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()>;

    fn delete_secret(&mut self, id: &str) -> Result<()>;
}

impl<D: DynKeyRing> KeyRing for D {
    fn get_secret<S: AsRef<str>>(&mut self, id: S) -> Result<KeyRingSecret> {
        DynKeyRing::get_secret(self, id.as_ref())
    }

    fn set_secret<S: AsRef<str>, B: AsRef<[u8]>>(&mut self, id: S, secret: B) -> Result<()> {
        DynKeyRing::set_secret(self, id.as_ref(), secret.as_ref())
    }

    fn delete_secret<S: AsRef<str>>(&mut self, id: S) -> Result<()> {
        DynKeyRing::delete_secret(self, id.as_ref())
    }
}

/// A KeyRing that can be created from a service name
pub trait NewKeyRing: Sized {
    fn new<S: AsRef<str>>(service: S) -> Result<Self>;
}

/// A Keyring that allows inspecting the identifiers
pub trait PeekableKeyRing {
    fn peek_secret<S: AsRef<str>>(id: S) -> Result<Vec<(String, KeyRingSecret)>>;
}

/// A Keyring that allows listing the identifiers
pub trait ListKeyRing {
    fn list_secrets() -> Result<Vec<BTreeMap<String, String>>>;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn parse_peek_criteria(id: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    if !id.is_empty() {
        for pair in id.split(',') {
            let s = pair.split('=').collect::<Vec<&str>>();
            result.insert(s[0].to_string(), s[1].to_string());
        }
    }
    result
}
