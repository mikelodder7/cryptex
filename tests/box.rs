use cryptex::{get_os_keyring, DynKeyRing};

#[test]
fn put_in_box() {
    let mut keyring: Box<dyn DynKeyRing> = Box::new(get_os_keyring("cryptex_put_in_box_test").unwrap());
    let res = keyring.set_secret("put_in_box_id", b"put_in_box_value");
    assert!(res.is_ok());
    let res = keyring.get_secret("put_in_box_id");
    assert!(res.is_ok());
    let put_in_box_value = res.unwrap();
    assert_eq!(put_in_box_value.0.as_slice(), b"put_in_box_value");
    let res = keyring.delete_secret("put_in_box_id");
    assert!(res.is_ok());
}
