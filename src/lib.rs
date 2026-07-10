/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    warnings,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

pub mod error;
mod keyring;

#[cfg(feature = "encrypted-vfs")]
#[cfg_attr(docsrs, doc(cfg(feature = "encrypted-vfs")))]
pub use keyring::encrypted_vfs;
#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http")))
)]
pub use keyring::kms;
#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(target_os = "linux", feature = "linux-secret-service")))
)]
pub use keyring::linux;
#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
#[cfg_attr(docsrs, doc(cfg(all(target_os = "macos", feature = "macos-keychain"))))]
pub use keyring::macos;
#[cfg(feature = "file")]
#[cfg_attr(docsrs, doc(cfg(feature = "file")))]
pub use keyring::sqlcipher;
#[cfg(all(target_os = "windows", feature = "windows-credentials"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(target_os = "windows", feature = "windows-credentials")))
)]
pub use keyring::windows;
#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http")))
)]
pub use keyring::yubihsm;
pub use keyring::*;

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_peek_criteria_test() {
        for pair in &[
            ("", 0),
            ("kind=generic", 1),
            ("kind=internet,account=aws", 2),
            ("account=aws,service=lox", 2),
            // Malformed input must be skipped, not panic (no '=' delimiter).
            ("no_delimiter_here", 0),
            ("valid=1,broken", 1),
            ("kind=internet,,account=aws", 2),
        ] {
            let criteria = parse_peek_criteria(pair.0);
            assert_eq!(criteria.len(), pair.1, "input: {:?}", pair.0);
        }
    }
}
