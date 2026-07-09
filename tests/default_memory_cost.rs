use std::process::Command;

#[test]
fn default_memory_cost_is_checked_without_test_cfg() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args([
            "run",
            "--quiet",
            "--example",
            "default_memory_cost",
            "--no-default-features",
            "--features",
            "file,encrypted-vfs",
        ])
        .output()
        .expect("run default_memory_cost example");

    assert!(
        output.status.success(),
        "default_memory_cost example failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
