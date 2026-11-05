/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
};

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
use secret_service::Error as LinuxOsError;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
use security_framework::base::Error as MacOsError;

/// Errors returned by every keyring backend.
#[derive(Clone, Eq, PartialEq)]
pub enum KeyRingError {
    /// No secret is stored under the requested id.
    ItemNotFound,
    /// The keyring refused access, e.g. a wrong key or a locked keyring.
    AccessDenied {
        /// Details of the refusal.
        msg: String,
    },
    /// Any other failure.
    GeneralError {
        /// Description of the failure.
        msg: String,
    },
}

impl KeyRingError {
    /// A human-readable description of the error.
    pub fn as_str(&self) -> String {
        match *self {
            Self::ItemNotFound => {
                "The specified item could not be found in the keychain".to_string()
            }
            Self::AccessDenied { ref msg } => format!("Unable to access the keychain: {:?}", msg),
            Self::GeneralError { ref msg } => msg.to_string(),
        }
    }
}

impl Display for KeyRingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Debug for KeyRingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", stringify!(self), self.as_str())
    }
}

impl From<&str> for KeyRingError {
    fn from(s: &str) -> Self {
        KeyRingError::GeneralError { msg: s.to_string() }
    }
}

impl Error for KeyRingError {}

impl From<std::io::Error> for KeyRingError {
    fn from(value: std::io::Error) -> Self {
        KeyRingError::GeneralError {
            msg: value.to_string(),
        }
    }
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
#[cfg_attr(docsrs, doc(cfg(all(target_os = "macos", feature = "macos-keychain"))))]
impl From<MacOsError> for KeyRingError {
    fn from(e: MacOsError) -> Self {
        match e.code() {
            -128 => KeyRingError::AccessDenied {
                msg: format!("{:?}", e.to_string()),
            },
            -25300 => KeyRingError::ItemNotFound,
            _ => KeyRingError::GeneralError {
                msg: "Unknown error".to_string(),
            },
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(target_os = "linux", feature = "linux-secret-service")))
)]
impl From<LinuxOsError> for KeyRingError {
    fn from(e: LinuxOsError) -> Self {
        match e {
            LinuxOsError::Crypto(_)
            | LinuxOsError::Zbus(_)
            | LinuxOsError::ZbusFdo(_)
            | LinuxOsError::Zvariant(_)
            | LinuxOsError::Prompt => KeyRingError::GeneralError {
                msg: format!("{:?}", e.to_string()),
            },
            LinuxOsError::Locked => KeyRingError::AccessDenied {
                msg: format!("{:?}", e.to_string()),
            },
            LinuxOsError::NoResult => KeyRingError::ItemNotFound,
            _ => KeyRingError::GeneralError {
                msg: "Unknown error".to_string(),
            },
        }
    }
}

#[cfg(any(feature = "file", feature = "encrypted-vfs"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "file", feature = "encrypted-vfs"))))]
impl From<rusqlite::Error> for KeyRingError {
    fn from(value: rusqlite::Error) -> Self {
        KeyRingError::GeneralError {
            msg: value.to_string(),
        }
    }
}

#[cfg(any(feature = "turso", feature = "turso-encrypted-io"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "turso", feature = "turso-encrypted-io")))
)]
impl From<::turso::Error> for KeyRingError {
    fn from(value: ::turso::Error) -> Self {
        KeyRingError::GeneralError {
            msg: value.to_string(),
        }
    }
}
