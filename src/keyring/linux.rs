/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use secret_service::{EncryptionType, SecretService};

use super::*;
use crate::error::KeyRingError;

use std::collections::BTreeMap;
use std::sync::RwLock;
use tokio::runtime::Runtime;

pub struct LinuxOsKeyRing<'a> {
    keychain: SecretService<'a>,
    service: String,
    username: String,
}

unsafe impl<'a> Send for LinuxOsKeyRing<'a> {}

unsafe impl<'a> Sync for LinuxOsKeyRing<'a> {}

static RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);

impl<'a> DynKeyRing for LinuxOsKeyRing<'a> {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        let opt_runtime = RUNTIME.read().map_err(|_e| KeyRingError::GeneralError {
            msg: "unable to find runtime".to_string(),
        })?;
        if opt_runtime.is_none() {
            return Err(KeyRingError::GeneralError {
                msg: "unable to find runtime".to_string(),
            });
        }
        let runtime = opt_runtime.as_ref().unwrap();
        runtime.block_on(async move {
            let collection = self
                .keychain
                .get_default_collection()
                .await
                .map_err(KeyRingError::from)?;
            if collection.is_locked().await.map_err(KeyRingError::from)? {
                collection.unlock().await.map_err(KeyRingError::from)?
            }
            let attributes = maplit::hashmap![
                "application" => "lox",
                "service" => &self.service,
                "username" => &self.username,
                "id" => id,
            ];
            let search = collection
                .search_items(attributes)
                .await
                .map_err(KeyRingError::from)?;
            let item = search.get(0).ok_or(KeyRingError::ItemNotFound)?;
            let secret = item.get_secret().await.map_err(KeyRingError::from)?;
            Ok(KeyRingSecret(secret))
        })
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        let opt_runtime = RUNTIME.read().map_err(|_e| KeyRingError::GeneralError {
            msg: "unable to find runtime".to_string(),
        })?;
        if opt_runtime.is_none() {
            return Err(KeyRingError::GeneralError {
                msg: "unable to find runtime".to_string(),
            });
        }
        let runtime = opt_runtime.as_ref().unwrap();
        runtime.block_on(async move {
            let collection = self
                .keychain
                .get_default_collection()
                .await
                .map_err(KeyRingError::from)?;
            if collection.is_locked().await.map_err(KeyRingError::from)? {
                collection.unlock().await.map_err(KeyRingError::from)?
            }
            let attributes = maplit::hashmap![
                "application" => "lox",
                "service" => &self.service,
                "username" => &self.username,
                "id" => id,
            ];
            collection
                .create_item(
                    &format!("Secret for {}", id),
                    attributes,
                    secret,
                    true,
                    "text/plain",
                )
                .await
                .map_err(KeyRingError::from)?;
            Ok(())
        })
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        let opt_runtime = RUNTIME.read().map_err(|_e| KeyRingError::GeneralError {
            msg: "unable to find runtime".to_string(),
        })?;
        if opt_runtime.is_none() {
            return Err(KeyRingError::GeneralError {
                msg: "unable to find runtime".to_string(),
            });
        }
        let runtime = opt_runtime.as_ref().unwrap();
        runtime.block_on(async move {
            let collection = self
                .keychain
                .get_default_collection()
                .await
                .map_err(KeyRingError::from)?;
            if collection.is_locked().await.map_err(KeyRingError::from)? {
                collection.unlock().await.map_err(KeyRingError::from)?
            }
            let attributes = maplit::hashmap![
                "application" => "lox",
                "service" => &self.service,
                "username" => &self.username,
                "id" => id,
            ];
            let search = collection
                .search_items(attributes)
                .await
                .map_err(KeyRingError::from)?;
            let item = search
                .get(0)
                .ok_or_else(|| KeyRingError::from("No secret found"))?;
            item.delete().await.map_err(KeyRingError::from)
        })
    }
}

impl<'a> NewKeyRing for LinuxOsKeyRing<'a> {
    fn new<S: AsRef<str>>(service: S) -> Result<Self> {
        let runtime = Runtime::new().unwrap();
        let keychain_result =
            runtime.block_on(async move { SecretService::connect(EncryptionType::Dh).await });
        *RUNTIME.write().unwrap() = Some(runtime);
        Ok(LinuxOsKeyRing {
            keychain: keychain_result.map_err(KeyRingError::from)?,
            service: service.as_ref().to_string(),
            username: get_username(),
        })
    }
}

impl<'a> PeekableKeyRing for LinuxOsKeyRing<'a> {
    fn peek_secret<S: AsRef<str>>(id: S) -> Result<Vec<(String, KeyRingSecret)>> {
        let runtime = Runtime::new().unwrap();
        let id = id.as_ref();
        runtime.block_on(async move {
            let key_chain = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(KeyRingError::from)?;
            let collection = key_chain
                .get_default_collection()
                .await
                .map_err(KeyRingError::from)?;
            if collection.is_locked().await.map_err(KeyRingError::from)? {
                collection.unlock().await.map_err(KeyRingError::from)?
            }
            let attributes = parse_peek_criteria(id);

            let items = collection
                .get_all_items()
                .await
                .map_err(KeyRingError::from)?;
            let mut out = Vec::new();

            for item in &items {
                match item.get_attributes().await {
                    Ok(atts) => {
                        let mut matches = true;
                        for (k, v) in &attributes {
                            if atts.contains_key(k) {
                                matches = atts[k] == v.as_str();
                            } else {
                                matches = false;
                            }
                            if !matches {
                                break;
                            }
                        }
                        if matches || id.is_empty() {
                            let secret = item.get_secret().await.map_err(KeyRingError::from)?;
                            out.push((format!("{:?}", atts), KeyRingSecret(secret)));
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
        })
    }
}

impl<'a> ListKeyRing for LinuxOsKeyRing<'a> {
    fn list_secrets() -> Result<Vec<BTreeMap<String, String>>> {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async move {
            let key_chain = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(KeyRingError::from)?;
            let collection = key_chain
                .get_default_collection()
                .await
                .map_err(KeyRingError::from)?;
            if collection.is_locked().await.map_err(KeyRingError::from)? {
                collection.unlock().await.map_err(KeyRingError::from)?
            }
            let items = collection
                .get_all_items()
                .await
                .map_err(KeyRingError::from)?;
            let mut out = Vec::new();
            for item in &items {
                match item.get_attributes().await {
                    Ok(atts) => {
                        out.push(BTreeMap::from_iter(atts.into_iter()));
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
        })
    }
}
