#![cfg(all(feature = "file", feature = "encrypted-vfs"))]

use std::process::Command;

#[test]
fn default_argon2_params_are_checked_without_test_cfg() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    // A separate target dir: the cdylib crate type leaves the rlib unhashed, so a
    // nested build with fewer features would replace the one doctests link.
    let target_dir = concat!(env!("CARGO_TARGET_TMPDIR"), "/default_argon2_params");
    let output = Command::new(cargo)
        .args([
            "run",
            "--target-dir",
            target_dir,
            "--quiet",
            "--example",
            "default_argon2_params",
            "--no-default-features",
            "--features",
            "file,encrypted-vfs",
        ])
        .output()
        .expect("run default_argon2_params example");

    assert!(
        output.status.success(),
        "default_argon2_params example failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
