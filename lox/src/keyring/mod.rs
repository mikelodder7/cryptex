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
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub(crate) use self::macos::MacOsKeyRing as OsKeyRing;

#[cfg(target_os = "linux")]
pub(crate) use self::linux::LinuxOsKeyRing as OsKeyRing;

#[cfg(target_os = "windows")]
pub(crate) use self::windows::WindowsOsKeyRing as OsKeyRing;

use crate::base::Result;
use crate::KeyRing;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use users::{get_current_username, get_effective_username};

pub fn get_os_keyring(service: &str) -> Result<OsKeyRing> {
    OsKeyRing::new(service)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("no keyring implementation is available for this platform");

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_username() -> String {
    fn get_current_user() -> String {
        match get_current_username() {
            Some(s) => match s.into_string() {
                Ok(r) => r,
                Err(_) => whoami::username(),
            },
            None => whoami::username(),
        }
    }

    match get_effective_username() {
        Some(s) => match s.into_string() {
            Ok(r) => r,
            Err(_) => get_current_user(),
        },
        None => get_current_user(),
    }
}
