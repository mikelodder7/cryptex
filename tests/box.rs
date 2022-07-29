use cryptex::{get_os_keyring, DynKeyRing};

#[test]
fn put_in_box() {
    let _: Box<dyn DynKeyRing> = Box::new(get_os_keyring("cryptex_put_in_box_test").unwrap());
}
