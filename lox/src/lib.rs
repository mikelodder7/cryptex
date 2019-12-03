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
#![deny(
    warnings,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

#[cfg(target_os = "windows")]
extern crate byteorder;
#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate core_foundation_sys;
#[cfg(target_os = "linux")]
extern crate secret_service;
#[cfg(target_os = "macos")]
extern crate security_framework;
#[cfg(target_os = "macos")]
extern crate security_framework_sys;
#[cfg(any(target_os = "macos", target_os = "linux"))]
extern crate users;
#[cfg(target_os = "windows")]
extern crate winapi;

use subtle::ConstantTimeEq;
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub mod base {
    pub type Result<T> = std::result::Result<T, crate::error::KeyRingError>;
}

pub mod prelude {
    pub use super::{KeyRing, KeyRingSecret,
                    base::Result as KeyRingResult,
                    keyring::get_os_keyring,
                    error::{KeyRingError, KeyRingErrorKind}};
}

pub trait KeyRing: Sized {
    fn new<S: AsRef<str>>(service: S) -> base::Result<Self>;

    fn get_secret<S: AsRef<str>>(&mut self, id: S) -> base::Result<KeyRingSecret>;

    fn set_secret<S: AsRef<str>, B: AsRef<[u8]>>(&mut self, id: S, secret: B) -> base::Result<()>;

    fn delete_secret<S: AsRef<str>>(&mut self, id: S) -> base::Result<()>;

    fn peek_secret<S: AsRef<str>>(id: S) -> base::Result<Vec<(String, KeyRingSecret)>>;

    fn list_secrets() -> base::Result<Vec<BTreeMap<String, String>>>;
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyRingSecret(Vec<u8>);

impl KeyRingSecret {
    pub fn new(d: Vec<u8>) -> Self {
        KeyRingSecret(d)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] { self.0.as_mut_slice() }

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

impl ::std::ops::Index<usize> for KeyRingSecret {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl ::std::ops::Index<::std::ops::Range<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ::std::ops::Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for KeyRingSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ::std::ops::RangeFull) -> &[u8] {
        self.0.as_slice()
    }
}

impl ::std::fmt::Display for KeyRingSecret {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            formatter,
            "KeyRingSecret {{ {} }}",
            hex::encode(&self.0[..])
        )
    }
}

impl ::std::fmt::Debug for KeyRingSecret {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            formatter,
            "KeyRingSecret {{ {} }}",
            hex::encode(&self.0[..])
        )
    }
}

#[cfg(feature = "serialization")]
impl serde::ser::Serialize for KeyRingSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::ser::Serializer,
    {
        serializer.serialize_newtype_struct("KeyRingSecret", &hex::encode(&self.0[..]))
    }
}

#[cfg(feature = "serialization")]
impl<'a> serde::de::Deserialize<'a> for KeyRingSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::de::Deserializer<'a>,
    {
        struct Thingvisitor;

        impl<'a> ::serde::de::Visitor<'a> for Thingvisitor {
            type Value = KeyRingSecret;

            fn expecting(
                &self,
                formatter: &mut ::std::fmt::Formatter,
            ) -> ::std::fmt::Result {
                write!(formatter, "expected KeyRingSecret")
            }

            fn visit_str<E>(self, value: &str) -> Result<KeyRingSecret, E>
            where
                E: ::serde::de::Error,
            {
                Ok(KeyRingSecret(hex::decode(value).map_err(::serde::de::Error::custom)?))
            }
        }

        deserializer.deserialize_str(Thingvisitor)
    }
}

pub mod keyring;
pub mod error;

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_peek_criteria(id: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    if !id.is_empty() {
        for pair in id.split(',') {
            let s = pair.split('=').collect::<Vec<&str>>();
            result.insert(s[0].to_string(), s[1].to_string());
        }
    }
    result
}

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
        ] {
            let criteria = parse_peek_criteria(pair.0);
            assert_eq!(criteria.len(), pair.1);
        }
    }
}
