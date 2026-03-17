/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#![deny(
    warnings,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

use clap::{Arg, ArgMatches, Command};
use colored::Colorize;

// ── Imports used only when at least one active backend is compiled in ─────────

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use std::fs::File;

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use std::io::{self, IsTerminal, Read, Write};

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use std::path::PathBuf;

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use zeroize::Zeroize;

// ── Shared backend imports ────────────────────────────────────────────────────

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use cryptex::{KeyRing, KeyRingSecret};

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
use std::collections::BTreeMap;

// ── OS keyring ────────────────────────────────────────────────────────────────

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
use cryptex::{ListKeyRing, PeekableKeyRing, get_os_keyring};

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
use cryptex::macos::MacOsKeyRing as OsKeyRing;

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
use cryptex::linux::LinuxOsKeyRing as OsKeyRing;

#[cfg(all(target_os = "windows", feature = "windows-credentials"))]
use cryptex::windows::WindowsOsKeyRing as OsKeyRing;

// ── YubiHSM ───────────────────────────────────────────────────────────────────

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
use cryptex::NewKeyRing;

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
use cryptex::yubihsm::YubiHsmKeyRing;

// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let matches = Command::new("cryptex")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Michael Lodder")
        .about("Platform-independent CLI for storing and retrieving secrets from secure keyrings")
        .arg(
            Arg::new("keyring")
                .long("keyring")
                .short('k')
                .value_name("TYPE")
                .global(true)
                .help("Keyring backend to use: 'os' (default) or 'yubihsm'"),
        )
        .subcommand(
            Command::new("get")
                .about("Retrieve a secret by ID")
                .arg(
                    Arg::new("SERVICE")
                        .help("Service name (OS) or connection string (yubihsm)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("ID")
                        .help("The secret ID. If omitted, read from STDIN")
                        .required(false)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("set")
                .about("Save a secret by ID")
                .arg(
                    Arg::new("SERVICE")
                        .help("Service name (OS) or connection string (yubihsm)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("ID")
                        .help("The secret ID")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("SECRET")
                        .help("The secret value. If omitted, read from STDIN")
                        .required(false)
                        .index(3),
                ),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a secret by ID")
                .arg(
                    Arg::new("SERVICE")
                        .help("Service name (OS) or connection string (yubihsm)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("ID")
                        .help("The secret ID. If omitted, read from STDIN")
                        .required(false)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("peek")
                .about("Inspect OS keyring entries without full retrieval (OS backends only)")
                .arg(
                    Arg::new("ID")
                        .help("Filter as comma-separated name=value pairs (e.g. service=aws,account=key)")
                        .required(false)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List secret IDs. For 'os': lists all. For 'yubihsm': requires a connection string.")
                .arg(
                    Arg::new("SERVICE")
                        .help("Connection string (required for 'yubihsm')")
                        .required(false)
                        .index(1),
                ),
        )
        .get_matches();

    dispatch(&matches);
}

fn dispatch(matches: &ArgMatches) {
    let keyring_type = matches
        .get_one::<String>("keyring")
        .map(|s| s.as_str())
        .unwrap_or("os");

    match keyring_type {
        "yubihsm" => {
            #[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
            dispatch_yubihsm(matches);
            #[cfg(not(any(feature = "yubihsm-usb", feature = "yubihsm-http")))]
            die::<()>(
                "YubiHSM support is not compiled in. \
                 Enable the 'yubihsm-usb' or 'yubihsm-http' feature.",
            );
        }
        "os" => dispatch_os(matches),
        other => die::<()>(&format!(
            "Unknown keyring type '{}'. Valid options: os, yubihsm",
            other
        )),
    }
}

// ── OS keyring dispatch ───────────────────────────────────────────────────────

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn dispatch_os(matches: &ArgMatches) {
    if let Some(m) = matches.subcommand_matches("get") {
        os_get(m);
    } else if let Some(m) = matches.subcommand_matches("set") {
        os_set(m);
    } else if let Some(m) = matches.subcommand_matches("delete") {
        os_delete(m);
    } else if let Some(m) = matches.subcommand_matches("peek") {
        os_peek(m);
    } else if matches.subcommand_matches("list").is_some() {
        os_list();
    } else {
        die::<()>("Please specify a command: get | set | delete | peek | list");
    }
}

#[cfg(not(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
)))]
fn dispatch_os(_matches: &ArgMatches) {
    die::<()>(
        "No OS keyring available for this platform/feature combination. \
         Use '--keyring yubihsm' or enable a platform keyring feature.",
    );
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn os_get(matches: &ArgMatches) {
    let mut keyring = os_open(matches);
    let id = get_id(matches, true);
    let secret = keyring
        .get_secret(&id)
        .unwrap_or_else(|e| die::<KeyRingSecret>(&e.to_string()));
    io::stdout().write_all(secret.as_slice()).unwrap();
    io::stdout().flush().unwrap();
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn os_set(matches: &ArgMatches) {
    let mut keyring = os_open(matches);
    let id = matches.get_one::<String>("ID").map(|s| s.as_str()).unwrap();
    let mut secret = read_input(matches, "SECRET", true);
    keyring
        .set_secret(id, &secret)
        .unwrap_or_else(|e| die::<()>(&format!("Failed: {}", e)));
    secret.zeroize();
    println!("{}", "Success".green());
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn os_delete(matches: &ArgMatches) {
    let mut keyring = os_open(matches);
    let id = get_id(matches, true);
    keyring
        .delete_secret(&id)
        .unwrap_or_else(|e| die::<()>(&e.to_string()));
    println!("{}", "Success".green());
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn os_peek(matches: &ArgMatches) {
    let id = get_id(matches, false);
    let secrets = OsKeyRing::peek_secret(&id)
        .unwrap_or_else(|e| die::<Vec<(String, KeyRingSecret)>>(&e.to_string()));
    if secrets.len() == 1 && !id.is_empty() {
        io::stdout().write_all(secrets[0].1.as_slice()).unwrap();
        io::stdout().flush().unwrap();
        println!();
    } else {
        for s in secrets {
            print!("{} -> ", s.0);
            io::stdout().write_all(s.1.as_slice()).unwrap();
            println!();
            io::stdout().flush().unwrap();
        }
    }
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
))]
fn os_list() {
    let secret_names = OsKeyRing::list_secrets()
        .unwrap_or_else(|e| die::<Vec<BTreeMap<String, String>>>(&e.to_string()));
    for s in secret_names {
        println!("{:?}", s);
    }
}

#[cfg(all(target_os = "linux", feature = "linux-secret-service"))]
fn os_open(matches: &ArgMatches) -> OsKeyRing<'_> {
    let service = matches
        .get_one::<String>("SERVICE")
        .map(|s| s.as_str())
        .unwrap();
    get_os_keyring(service).unwrap_or_else(|e| die(&format!("Unable to open OS keyring: {}", e)))
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
))]
fn os_open(matches: &ArgMatches) -> OsKeyRing {
    let service = matches
        .get_one::<String>("SERVICE")
        .map(|s| s.as_str())
        .unwrap();
    get_os_keyring(service).unwrap_or_else(|e| die(&format!("Unable to open OS keyring: {}", e)))
}

// ── YubiHSM dispatch ─────────────────────────────────────────────────────────

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn dispatch_yubihsm(matches: &ArgMatches) {
    if let Some(m) = matches.subcommand_matches("get") {
        yubihsm_get(m);
    } else if let Some(m) = matches.subcommand_matches("set") {
        yubihsm_set(m);
    } else if let Some(m) = matches.subcommand_matches("delete") {
        yubihsm_delete(m);
    } else if let Some(m) = matches.subcommand_matches("list") {
        yubihsm_list(m);
    } else if matches.subcommand_matches("peek").is_some() {
        die::<()>("The 'peek' command is not supported for the YubiHSM backend.");
    } else {
        die::<()>("Please specify a command: get | set | delete | list");
    }
}

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn yubihsm_open(matches: &ArgMatches) -> YubiHsmKeyRing {
    let connstr = matches
        .get_one::<String>("SERVICE")
        .map(|s| s.as_str())
        .unwrap_or_else(|| die("A YubiHSM connection string is required as the SERVICE argument"));
    YubiHsmKeyRing::new(connstr)
        .unwrap_or_else(|e| die(&format!("Failed to connect to YubiHSM: {}", e)))
}

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn yubihsm_get(matches: &ArgMatches) {
    let mut ring = yubihsm_open(matches);
    let id = get_id(matches, true);
    let secret = ring
        .get_secret(&id)
        .unwrap_or_else(|e| die::<KeyRingSecret>(&e.to_string()));
    io::stdout().write_all(secret.as_slice()).unwrap();
    io::stdout().flush().unwrap();
}

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn yubihsm_set(matches: &ArgMatches) {
    let mut ring = yubihsm_open(matches);
    let id = matches.get_one::<String>("ID").map(|s| s.as_str()).unwrap();
    let mut secret = read_input(matches, "SECRET", true);
    ring.set_secret(id, &secret)
        .unwrap_or_else(|e| die::<()>(&format!("Failed: {}", e)));
    secret.zeroize();
    println!("{}", "Success".green());
}

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn yubihsm_delete(matches: &ArgMatches) {
    let mut ring = yubihsm_open(matches);
    let id = get_id(matches, true);
    ring.delete_secret(&id)
        .unwrap_or_else(|e| die::<()>(&e.to_string()));
    println!("{}", "Success".green());
}

#[cfg(any(feature = "yubihsm-usb", feature = "yubihsm-http"))]
fn yubihsm_list(matches: &ArgMatches) {
    let ring = yubihsm_open(matches);
    let entries = ring
        .list_hsm_secrets()
        .unwrap_or_else(|e| die::<Vec<BTreeMap<String, String>>>(&e.to_string()));
    for entry in entries {
        println!("{:?}", entry);
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
fn get_id(matches: &ArgMatches, read_stdin: bool) -> String {
    let bytes = read_input(matches, "ID", read_stdin);
    String::from_utf8(bytes).unwrap_or_else(|_| die("ID is not valid UTF-8"))
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
fn read_input(matches: &ArgMatches, name: &str, read_stdin: bool) -> Vec<u8> {
    match matches.get_one::<String>(name).map(|s| s.as_str()) {
        Some(text) => match get_file(text) {
            Some(file) => match File::open(file.as_path()) {
                Ok(mut f) => read_stream(&mut f),
                Err(_) => die(&format!("Unable to read file {}", file.to_str().unwrap())),
            },
            None => text.as_bytes().to_vec(),
        },
        None => {
            if io::stdin().is_terminal() {
                if read_stdin {
                    rpassword::prompt_password("Enter Secret: ")
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                } else {
                    Vec::new()
                }
            } else {
                let mut f = io::stdin();
                read_stream(&mut f)
            }
        }
    }
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
fn read_stream<R: Read>(f: &mut R) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match f.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    bytes
}

#[cfg(any(
    all(target_os = "macos", feature = "macos-keychain"),
    all(target_os = "windows", feature = "windows-credentials"),
    all(target_os = "linux", feature = "linux-secret-service"),
    feature = "yubihsm-usb",
    feature = "yubihsm-http",
))]
fn get_file(name: &str) -> Option<PathBuf> {
    let mut file = PathBuf::from(name);
    if file.as_path().is_file() {
        let metadata = file
            .as_path()
            .symlink_metadata()
            .expect("symlink_metadata call failed");
        if metadata.file_type().is_symlink() {
            match file.as_path().read_link() {
                Ok(f) => file = f,
                Err(_) => die::<()>(&format!("Can't read the symbolic link: {}", name)),
            }
        }
        Some(file)
    } else {
        None
    }
}

fn die<R>(final_message: &str) -> R {
    eprintln!("{}", final_message.red());
    std::process::exit(1);
}
