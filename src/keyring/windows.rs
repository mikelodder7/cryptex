/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use std::ffi::{OsStr, OsString, c_void};
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use crate::error::KeyRingError;
use ::windows::Win32::Foundation::{FILETIME, HLOCAL, LocalFree};
use ::windows::Win32::Security::Credentials::{
    CRED_ENUMERATE_ALL_CREDENTIALS, CRED_ENUMERATE_FLAGS, CRED_FLAGS, CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC, CREDENTIAL_ATTRIBUTEW, CREDENTIALW, CredDeleteW, CredEnumerateW, CredFree,
    CredReadW, CredWriteW,
};
use ::windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
};
use ::windows::core::{PCWSTR, PWSTR};
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub struct WindowsOsKeyRing {
    service: String,
    username: String,
}

unsafe impl Send for WindowsOsKeyRing {}

unsafe impl Sync for WindowsOsKeyRing {}

impl WindowsOsKeyRing {
    fn get_target_name(&self, id: &str) -> Vec<u16> {
        let target_name = [&self.username, &self.service, id].join(":");
        to_utf16_bytes(&target_name)
    }
}

impl DynKeyRing for WindowsOsKeyRing {
    fn get_secret(&mut self, id: &str) -> Result<KeyRingSecret> {
        let target_name = self.get_target_name(id);
        let mut pcredential: *mut CREDENTIALW = std::ptr::null_mut();

        unsafe {
            CredReadW(
                PCWSTR(target_name.as_ptr()),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut pcredential,
            )
        }
        .map_err(|e: ::windows::core::Error| {
            KeyRingError::from(e.message().to_string().as_str())
        })?;

        let credential: CREDENTIALW = unsafe { *pcredential };

        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: credential.CredentialBlobSize,
            pbData: credential.CredentialBlob,
        };

        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        let res = match unsafe {
            CryptUnprotectData(&mut in_blob, None, None, None, None, 0, &mut out_blob)
        } {
            Err(_) => Err(KeyRingError::from("Windows Crypt Unprotect Data Error")),
            Ok(()) => {
                let secret = unsafe {
                    std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize)
                };
                let r = Ok(KeyRingSecret(secret.to_vec()));
                secret.zeroize();
                r
            }
        };
        unsafe { CredFree(pcredential as *const c_void) };
        unsafe { LocalFree(Some(HLOCAL(out_blob.pbData as _))) };
        res
    }

    fn set_secret(&mut self, id: &str, secret: &[u8]) -> Result<()> {
        let mut target_name = self.get_target_name(id);
        let mut empty = to_utf16_bytes("");
        let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut user_name = to_utf16_bytes(&self.username);
        let mut secret_cp = secret.to_vec();

        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: secret.len() as u32,
            pbData: secret_cp.as_mut_ptr(),
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptProtectData(
                &mut in_blob,
                PCWSTR(target_name.as_ptr()),
                None,
                None,
                None,
                0,
                &mut out_blob,
            )
        }
        .map_err(|_| KeyRingError::from("Windows Crypt Protect Data Error"))?;

        secret_cp.zeroize();

        let mut credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_name.as_mut_ptr()),
            Comment: PWSTR(empty.as_mut_ptr()),
            LastWritten: FILETIME {
                dwHighDateTime: 0,
                dwLowDateTime: 0,
            },
            CredentialBlobSize: out_blob.cbData,
            CredentialBlob: out_blob.pbData,
            Persist: CRED_PERSIST_ENTERPRISE,
            Attributes: attributes,
            AttributeCount: 0,
            TargetAlias: PWSTR(empty.as_mut_ptr()),
            UserName: PWSTR(user_name.as_mut_ptr()),
        };
        let res = match unsafe { CredWriteW(&mut credential, 0) } {
            Err(_) => Err(KeyRingError::from("Windows Vault Error")),
            Ok(()) => Ok(()),
        };
        unsafe { LocalFree(Some(HLOCAL(out_blob.pbData as _))) };
        res
    }

    fn delete_secret(&mut self, id: &str) -> Result<()> {
        let target_name = self.get_target_name(id);

        unsafe { CredDeleteW(PCWSTR(target_name.as_ptr()), CRED_TYPE_GENERIC, Some(0)) }.map_err(
            |e: ::windows::core::Error| KeyRingError::from(e.message().to_string().as_str()),
        )?;
        Ok(())
    }
}

impl NewKeyRing for WindowsOsKeyRing {
    fn new<S: AsRef<str>>(service: S) -> Result<Self> {
        Ok(WindowsOsKeyRing {
            service: service.as_ref().to_string(),
            username: whoami::username().unwrap_or_else(|_| String::from("unknown")),
        })
    }
}

impl PeekableKeyRing for WindowsOsKeyRing {
    fn peek_secret<S: AsRef<str>>(id: S) -> Result<Vec<(String, KeyRingSecret)>> {
        let id = id.as_ref();
        let flags = if id.is_empty() {
            Some(CRED_ENUMERATE_ALL_CREDENTIALS)
        } else {
            None
        };

        let found_credentials = unsafe { get_credentials(id, flags)? };

        Ok(found_credentials)
    }
}

impl ListKeyRing for WindowsOsKeyRing {
    fn list_secrets() -> Result<Vec<BTreeMap<String, String>>> {
        let mut pcredentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
        let mut count = 0u32;

        unsafe {
            CredEnumerateW(
                PCWSTR::null(),
                Some(CRED_ENUMERATE_ALL_CREDENTIALS),
                &mut count,
                &mut pcredentials,
            )
        }
        .map_err(|e: ::windows::core::Error| {
            KeyRingError::from(e.message().to_string().as_str())
        })?;

        let credentials: &[*mut CREDENTIALW] =
            unsafe { std::slice::from_raw_parts(pcredentials, count as usize) };

        let mut found_credentials = Vec::new();

        for c in credentials {
            let cred: CREDENTIALW = unsafe { **c };
            let mut i = 0isize;
            while unsafe { *cred.TargetName.0.offset(i) } != 0u16 {
                i += 1;
            }
            let target = unsafe { std::slice::from_raw_parts(cred.TargetName.0, i as usize) };
            let name = OsString::from_wide(target).into_string().unwrap();
            let mut value = BTreeMap::new();
            value.insert("targetname".to_string(), name);

            found_credentials.push(value);
        }
        unsafe { CredFree(pcredentials as *const c_void) };
        Ok(found_credentials)
    }
}

fn to_utf16_bytes(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

unsafe fn get_credentials(
    id: &str,
    flags: Option<CRED_ENUMERATE_FLAGS>,
) -> Result<Vec<(String, KeyRingSecret)>> {
    let id = if !id.is_empty() {
        to_utf16_bytes(id)
    } else {
        Vec::new()
    };
    let filter = if flags.is_some() {
        PCWSTR::null()
    } else {
        PCWSTR(id.as_ptr())
    };
    let mut pcredentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let mut count = 0u32;
    unsafe { CredEnumerateW(filter, flags, &mut count, &mut pcredentials) }.map_err(
        |e: ::windows::core::Error| KeyRingError::from(e.message().to_string().as_str()),
    )?;

    let credentials: &[*mut CREDENTIALW] =
        unsafe { std::slice::from_raw_parts(pcredentials, count as usize) };

    let mut found_credentials = Vec::new();

    for c in credentials {
        let cred: CREDENTIALW = unsafe { **c };
        let blob: *const u8 = cred.CredentialBlob;
        let blob_len: usize = cred.CredentialBlobSize as usize;
        let mut i = 0isize;
        while unsafe { *cred.TargetName.0.offset(i) } != 0u16 {
            i += 1;
        }
        let target = unsafe { std::slice::from_raw_parts(cred.TargetName.0, i as usize) };
        let name = OsString::from_wide(target).into_string().unwrap();

        let secret = unsafe { std::slice::from_raw_parts(blob, blob_len) };
        let mut secret_u16 = vec![0u16; blob_len / 2];
        for (i, chunk) in secret.chunks_exact(2).enumerate() {
            secret_u16[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        let t = match String::from_utf16(secret_u16.as_slice()).map(|pass| pass.to_string()) {
            Ok(s) => s,
            Err(_) => {
                match String::from_utf8(secret.to_vec()).map(|pass| pass.to_string()) {
                    Ok(s1) => s1,
                    Err(_) => {
                        //Binary blob
                        secret
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join("")
                    }
                }
            }
        };
        found_credentials.push((name, KeyRingSecret(t.as_bytes().to_vec())));
    }
    unsafe { CredFree(pcredentials as *const c_void) };
    Ok(found_credentials)
}
