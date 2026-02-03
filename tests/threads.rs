#![cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]

use cryptex::{KeyRing, get_os_keyring};

#[test]
#[ignore = "requires a running OS keyring service"]
fn thread_test() {
    let handle = std::thread::spawn(|| {
        let res = get_os_keyring("cryptex_text");
        assert!(res.is_ok());
        let mut keyring = res.unwrap();
        // result doesn't matter
        assert!(keyring.get_secret("").is_err());
        assert!(keyring.set_secret("thread_test", b"dummy").is_ok());
        let res = keyring.get_secret("thread_test");
        assert!(res.is_ok());
        assert_eq!(b"dummy".to_vec(), res.unwrap().0);
        assert!(keyring.delete_secret("thread_test").is_ok());
    });
    handle.join().unwrap();
}
