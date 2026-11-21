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

//! The `cryptex` command-line tool.
//!
//! The CLI talks to OS keyrings, files and YubiHSM devices, none of which
//! exist in a browser or WASI sandbox, so a wasm build reports that instead of
//! exposing commands that cannot work. Use the library, or the JS bindings on
//! wasm.

#[cfg(not(target_family = "wasm"))]
mod native;

#[cfg(not(target_family = "wasm"))]
fn main() {
    native::main();
}

#[cfg(target_family = "wasm")]
fn main() {
    eprintln!(
        "cryptex CLI is not supported on wasm; use the cryptex library or its JS bindings instead"
    );
    std::process::exit(1);
}
