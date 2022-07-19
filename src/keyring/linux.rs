/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use secret_service::{EncryptionType, SecretService};

use super::{get_username, parse_peek_criteria, KeyRing, KeyRingSecret, Result};
use crate::error::KeyRingError;

use std::collections::BTreeMap;

pub struct LinuxOsKeyRing {
    keychain: SecretService,
    service: String,
    username: String,
}

unsafe impl Send for LinuxOsKeyRing {}

unsafe impl Sync for LinuxOsKeyRing {}

impl KeyRing for LinuxOsKeyRing {
    fn new<S: AsRef<str>>(service: S) -> Result<Self> {
        Ok(LinuxOsKeyRing {
            keychain: SecretService::new(EncryptionType::Dh).map_err(KeyRingError::from)?,
            service: service.as_ref().to_string(),
            username: get_username(),
        })
    }

    fn get_secret<S: AsRef<str>>(&mut self, id: S) -> Result<KeyRingSecret> {
        let id = id.as_ref();
        let collection = self
            .keychain
            .get_default_collection()
            .map_err(KeyRingError::from)?;
        if collection.is_locked().map_err(KeyRingError::from)? {
            collection.unlock().map_err(KeyRingError::from)?
        }
        let attributes = vec![
            ("application", "lox"),
            ("service", &self.service),
            ("username", &self.username),
            ("id", id),
        ];
        let search = collection
            .search_items(attributes)
            .map_err(KeyRingError::from)?;
        let item = search.get(0).ok_or(KeyRingError::ItemNotFound)?;
        let secret = item.get_secret().map_err(KeyRingError::from)?;
        Ok(KeyRingSecret(secret))
    }

    fn list_secrets() -> Result<Vec<BTreeMap<String, String>>> {
        let key_chain = SecretService::new(EncryptionType::Dh).map_err(KeyRingError::from)?;
        let collection = key_chain
            .get_default_collection()
            .map_err(KeyRingError::from)?;
        if collection.is_locked().map_err(KeyRingError::from)? {
            collection.unlock().map_err(KeyRingError::from)?
        }
        let items = collection.get_all_items().map_err(KeyRingError::from)?;
        let mut out = Vec::new();
        for item in &items {
            match item.get_attributes() {
                Ok(atts) => {
                    out.push(vec_to_btreemap(atts));
                }
                Err(e) => {
                    if !out.is_empty() {
                        return Ok(out);
                    } else {
                        return Err(KeyRingError::from(e));
                    }
                }
            }
        }

        Ok(out)
    }

    fn peek_secret<S: AsRef<str>>(id: S) -> Result<Vec<(String, KeyRingSecret)>> {
        let id = id.as_ref();
        let key_chain = SecretService::new(EncryptionType::Dh).map_err(KeyRingError::from)?;
        let collection = key_chain
            .get_default_collection()
            .map_err(KeyRingError::from)?;
        if collection.is_locked().map_err(KeyRingError::from)? {
            collection.unlock().map_err(KeyRingError::from)?
        }
        let attributes = parse_peek_criteria(id);

        let items = collection.get_all_items().map_err(KeyRingError::from)?;
        let mut out = Vec::new();

        for item in &items {
            match item.get_attributes() {
                Ok(atts) => {
                    let mut matches = true;
                    let filter = vec_to_btreemap(atts);
                    for (k, v) in &attributes {
                        if filter.contains_key(k) {
                            matches = filter[k] == v.as_str();
                        } else {
                            matches = false;
                        }
                        if !matches {
                            break;
                        }
                    }
                    if matches || id.is_empty() {
                        let secret = item.get_secret().map_err(KeyRingError::from)?;
                        out.push((format!("{:?}", filter), KeyRingSecret(secret)));
                    }
                }
                Err(e) => {
                    if !out.is_empty() {
                        return Ok(out);
                    } else {
                        return Err(KeyRingError::from(e));
                    }
                }
            }
        }

        Ok(out)
    }

    fn set_secret<S: AsRef<str>, B: AsRef<[u8]>>(&mut self, id: S, secret: B) -> Result<()> {
        let id = id.as_ref();
        let secret = secret.as_ref();
        let collection = self
            .keychain
            .get_default_collection()
            .map_err(KeyRingError::from)?;
        if collection.is_locked().map_err(KeyRingError::from)? {
            collection.unlock().map_err(KeyRingError::from)?
        }
        let attributes = vec![
            ("application", "lox"),
            ("service", &self.service),
            ("username", &self.username),
            ("id", id),
        ];
        collection
            .create_item(
                &format!("Secret for {}", id),
                attributes,
                secret,
                true,
                "text/plain",
            )
            .map_err(KeyRingError::from)?;
        Ok(())
    }

    fn delete_secret<S: AsRef<str>>(&mut self, id: S) -> Result<()> {
        let id = id.as_ref();
        let collection = self
            .keychain
            .get_default_collection()
            .map_err(KeyRingError::from)?;
        if collection.is_locked().map_err(KeyRingError::from)? {
            collection.unlock().map_err(KeyRingError::from)?
        }
        let attributes = vec![
            ("application", "lox"),
            ("service", &self.service),
            ("username", &self.username),
            ("id", id),
        ];
        let search = collection
            .search_items(attributes)
            .map_err(KeyRingError::from)?;
        let item = search
            .get(0)
            .ok_or_else(|| KeyRingError::from("No secret found"))?;
        item.delete().map_err(KeyRingError::from)
    }
}

fn vec_to_btreemap(values: Vec<(String, String)>) -> BTreeMap<String, String> {
    let mut value = BTreeMap::new();
    for (k, v) in values {
        value.insert(k.to_string(), v.to_string());
    }
    value
}
