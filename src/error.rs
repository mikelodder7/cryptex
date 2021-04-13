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

use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
};

#[cfg(target_os = "linux")]
use secret_service::SsError as LinuxOsError;
#[cfg(target_os = "macos")]
use security_framework::base::Error as MacOsError;

#[derive(Clone, Eq, PartialEq)]
pub enum KeyRingError {
    ItemNotFound,
    AccessDenied { msg: String },
    GeneralError { msg: String },
}

impl KeyRingError {
    pub fn as_str(&self) -> String {
        match self {
            &Self::ItemNotFound => {
                "The specified item could not be found in the keychain".to_string()
            }
            &Self::AccessDenied { ref msg } => format!("Unable to access the keychain: {:?}", msg),
            &Self::GeneralError { ref msg } => msg.to_string(),
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "linux")]
impl From<LinuxOsError> for KeyRingError {
    fn from(e: LinuxOsError) -> Self {
        match e {
            LinuxOsError::Crypto(_)
            | LinuxOsError::Dbus(_)
            | LinuxOsError::Parse
            | LinuxOsError::Prompt => KeyRingError::GeneralError {
                msg: format!("{:?}", e.to_string()),
            },
            LinuxOsError::Locked => KeyRingError::AccessDenied {
                msg: format!("{:?}", e.to_string()),
            },
            LinuxOsError::NoResult => KeyRingError::ItemNotFound,
        }
    }
}
