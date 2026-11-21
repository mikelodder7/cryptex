/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! The AEAD algorithm choice shared by every encrypted keyring.

use super::file_common;
use crate::Result;
use crate::error::KeyRingError;
use zeroize::Zeroize;

/// Selects the AEAD algorithm used for page encryption.
///
/// `Aes256Gcm` uses AES-NI hardware acceleration on x86/x86_64/AArch64 when
/// available; on hardware without AES-NI it falls back to a constant-time
/// software implementation that is slower than ChaCha20-Poly1305.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// ChaCha20-Poly1305 (default)
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM
    Aes256Gcm,
}

impl Zeroize for CipherAlgorithm {
    fn zeroize(&mut self) {
        *self = CipherAlgorithm::default();
    }
}

impl file_common::CipherParam for CipherAlgorithm {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "chacha20poly1305" | "chacha20" => Ok(CipherAlgorithm::ChaCha20Poly1305),
            "aes256gcm" | "aes" => Ok(CipherAlgorithm::Aes256Gcm),
            other => Err(KeyRingError::GeneralError {
                msg: format!(
                    "unknown cipher '{}'; use chacha20poly1305 or aes256gcm",
                    other
                ),
            }),
        }
    }
}
