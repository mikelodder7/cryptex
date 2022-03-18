/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyRingSecret(pub Vec<u8>);

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

#[cfg(feature = "serde")]
impl serde::ser::Serialize for KeyRingSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::ser::Serializer,
    {
        serializer.serialize_newtype_struct("KeyRingSecret", &hex::encode(&self.0[..]))
    }
}

#[cfg(feature = "serde")]
impl<'a> serde::de::Deserialize<'a> for KeyRingSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::de::Deserializer<'a>,
    {
        struct Thingvisitor;

        impl<'a> ::serde::de::Visitor<'a> for Thingvisitor {
            type Value = KeyRingSecret;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "expected KeyRingSecret")
            }

            fn visit_str<E>(self, value: &str) -> Result<KeyRingSecret, E>
            where
                E: ::serde::de::Error,
            {
                Ok(KeyRingSecret(
                    hex::decode(value).map_err(::serde::de::Error::custom)?,
                ))
            }
        }

        deserializer.deserialize_str(Thingvisitor)
    }
}
