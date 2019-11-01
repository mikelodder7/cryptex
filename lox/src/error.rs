/*
 * Copyright 2019 Michael Lodder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */
use failure::{Backtrace, Context, Fail};

#[cfg(target_os = "macos")]
use security_framework::base::Error as MacOsError;
#[cfg(target_os = "linux")]
use secret_service::SsError as LinuxOsError;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum KeyRingErrorKind {
    #[fail(display = "The specified item could not be found in the keychain")]
    ItemNotFound,
    #[fail(display = "Unable to access the keychain: {:?}", msg)]
    AccessDenied { msg: String },
    #[fail(display = "{:?}", msg)]
    GeneralError { msg: String }
}

#[derive(Debug)]
pub struct KeyRingError {
    inner: Context<KeyRingErrorKind>,
}

impl KeyRingError {
    pub fn kind(&self) -> KeyRingErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<Context<KeyRingErrorKind>> for KeyRingError {
    fn from(inner: Context<KeyRingErrorKind>) -> Self {
        Self { inner }
    }
}

impl From<KeyRingErrorKind> for KeyRingError {
    fn from(kind: KeyRingErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<&str> for KeyRingError {
    fn from(s: &str) -> Self {
        Self {
            inner: Context::new("").context(KeyRingErrorKind::GeneralError {msg: s.to_string()})
        }
    }
}

#[cfg(target_os = "macos")]
impl From<MacOsError> for KeyRingError {
    fn from(e: MacOsError) -> Self {
        match e.code() {
            -128 => KeyRingErrorKind::AccessDenied { msg: format!("{:?}", e.to_string()) }.into(),
            -25300 => KeyRingErrorKind::ItemNotFound.into(),
            _ => KeyRingErrorKind::GeneralError { msg: "Unknown error".to_string() }.into(),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<LinuxOsError> for KeyRingError {
    fn from(e: LinuxOsError) -> Self {
        match e {
            LinuxOsError::Crypto(_) | LinuxOsError::Dbus(_) |
            LinuxOsError::Parse | LinuxOsError::Prompt => KeyRingErrorKind::GeneralError { msg: format!("{:?}", e.to_string()) }.into(),
            LinuxOsError::Locked => KeyRingErrorKind::AccessDenied { msg: format!("{:?}", e.to_string()) }.into(),
            LinuxOsError::NoResult => KeyRingErrorKind::ItemNotFound.into(),
        }
    }
}

impl Fail for KeyRingError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl std::fmt::Display for KeyRingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}
