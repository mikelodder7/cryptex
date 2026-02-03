/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use std::{
    fmt::{self, Debug, Display, Formatter},
    ops::{Index, Range, RangeFrom, RangeFull, RangeTo},
    str::FromStr,
};
use subtle::ConstantTimeEq;

use crate::error::KeyRingError;
#[cfg(feature = "serde")]
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as DError, Visitor},
};
use zeroize::Zeroize;

/// Represents a value stored in the keyring
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyRingSecret(pub Vec<u8>);

unsafe impl Send for KeyRingSecret {}

unsafe impl Sync for KeyRingSecret {}

impl KeyRingSecret {
    pub fn new(d: Vec<u8>) -> Self {
        KeyRingSecret(d)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[inline]
    /// Converts the object to a raw pointer for FFI interfacing
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_slice().as_ptr()
    }

    #[inline]
    /// Converts the object to a mutable raw pointer for FFI interfacing
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_slice().as_mut_ptr()
    }

    #[inline]
    /// Returns the length of the object as an array
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(feature = "serde")]
    pub fn from_serde<S: Serialize>(input: S) -> Result<Self, KeyRingError> {
        Ok(Self(
            postcard::to_stdvec(&input).map_err(|e| KeyRingError::from(e.to_string().as_str()))?,
        ))
    }

    #[cfg(feature = "serde")]
    pub fn to_serde<D: DeserializeOwned>(&self) -> Result<D, KeyRingError> {
        postcard::from_bytes(&self.0)
            .map_err(|e| KeyRingError::from(e.to_string().as_str()))
    }
}

impl PartialEq for KeyRingSecret {
    #[inline]
    fn eq(&self, other: &KeyRingSecret) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl Eq for KeyRingSecret {}

impl Clone for KeyRingSecret {
    #[inline]
    fn clone(&self) -> KeyRingSecret {
        KeyRingSecret(self.0.clone())
    }
}

impl Index<usize> for KeyRingSecret {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl Index<Range<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl Index<RangeTo<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: RangeTo<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl Index<RangeFrom<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl Index<RangeFull> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, _: RangeFull) -> &[u8] {
        self.0.as_slice()
    }
}

impl Display for KeyRingSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "KeyRingSecret {{ {} }}",
            hex::encode(&self.0[..])
        )
    }
}

impl Debug for KeyRingSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "KeyRingSecret {{ {} }}",
            hex::encode(&self.0[..])
        )
    }
}

impl FromStr for KeyRingSecret {
    type Err = KeyRingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| KeyRingError::from(e.to_string().as_str()))?;
        Ok(Self(bytes))
    }
}

impl From<String> for KeyRingSecret {
    fn from(s: String) -> Self {
        Self::from_str(&s).unwrap()
    }
}

impl From<&str> for KeyRingSecret {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

impl From<&[u8]> for KeyRingSecret {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for KeyRingSecret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[cfg(feature = "serde")]
impl Serialize for KeyRingSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("KeyRingSecret", &hex::encode(&self.0[..]))
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for KeyRingSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct Thingvisitor;

        impl<'a> Visitor<'a> for Thingvisitor {
            type Value = KeyRingSecret;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "expected string")
            }

            fn visit_str<E>(self, value: &str) -> Result<KeyRingSecret, E>
            where
                E: DError,
            {
                Ok(KeyRingSecret(hex::decode(value).map_err(DError::custom)?))
            }
        }

        deserializer.deserialize_str(Thingvisitor)
    }
}
