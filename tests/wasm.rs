/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Browser tests for the JavaScript bindings.
//!
//! Run with `wasm-pack test --headless --chrome --no-default-features
//! --features js`. Native `cargo test` skips this file.

#![cfg(all(target_family = "wasm", target_os = "unknown", feature = "js"))]

use cryptex::Keyring;
use wasm_bindgen_test::wasm_bindgen_test;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const CONNECTION: &str = "password=browser-test salt=0okm9ijn8uhb7ygv";

/// A keyring name no other run uses, so a leftover store cannot fool a test.
fn unique_name(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

#[wasm_bindgen_test]
async fn memory_keyring_round_trips() {
    let mut keyring = Keyring::open(CONNECTION, &unique_name("memory"), Default::default())
        .await
        .expect("a memory keyring opens");

    keyring.set("token", b"secret").await.expect("set succeeds");
    assert_eq!(keyring.get("token").expect("get succeeds"), b"secret");
    keyring.delete("token").await.expect("delete succeeds");
    assert!(keyring.get("token").is_err());

    keyring.close().await.expect("close succeeds");
}

#[wasm_bindgen_test]
async fn indexeddb_keeps_the_secrets() {
    let name = unique_name("indexeddb");

    let mut keyring = Keyring::open(CONNECTION, &name, Default::default())
        .await
        .expect("a keyring opens");
    keyring.set("token", b"value").await.expect("set succeeds");
    // A resolved set has reached the store, so the image is encrypted at rest.
    let image = keyring.export().expect("export succeeds");
    assert!(!image.windows(5).any(|w| w == b"value"));
    keyring.close().await.expect("close succeeds");

    let mut reopened = Keyring::open(CONNECTION, &name, Default::default())
        .await
        .expect("the keyring reopens");
    assert_eq!(reopened.get("token").expect("get succeeds"), b"value");
    reopened.close().await.expect("close succeeds");
}

#[wasm_bindgen_test]
async fn keys_and_keyring_names_are_listed() {
    let name = unique_name("keys");
    let mut keyring = Keyring::open(CONNECTION, &name, Default::default())
        .await
        .expect("a keyring opens");

    keyring.set("b", b"two").await.expect("set succeeds");
    keyring.set("a", b"one").await.expect("set succeeds");
    assert_eq!(
        keyring.keys().expect("keys succeeds"),
        ["a".to_string(), "b".to_string()]
    );

    // A page can list what is stored without opening anything.
    let stored = cryptex::stored_keyrings().await.expect("the store lists");
    assert!(stored.contains(&name));

    keyring.close().await.expect("close succeeds");
}

#[wasm_bindgen_test]
async fn a_wrong_password_is_refused() {
    let name = unique_name("indexeddb");
    let mut keyring = Keyring::open(CONNECTION, &name, Default::default())
        .await
        .expect("a keyring opens");
    keyring.set("token", b"value").await.expect("set succeeds");
    keyring.close().await.expect("close succeeds");

    let result = Keyring::open(
        "password=wrong salt=0okm9ijn8uhb7ygv",
        &name,
        Default::default(),
    )
    .await;
    match result {
        Err(error) => assert!(format!("{error:?}").contains("AccessDenied")),
        Ok(_) => panic!("the wrong password is refused"),
    }
}
