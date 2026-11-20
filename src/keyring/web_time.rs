/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Clocks for Turso I/O backends that run in a browser.
//!
//! Turso's own clock calls `Instant::now`, which panics on
//! `wasm32-unknown-unknown`: the platform has no monotonic clock behind it.
//! `performance.now()` is the closest equivalent and, unlike `Date.now()`,
//! only moves forward.

use ::turso::core::{Clock, MonotonicInstant, WallClockInstant};

/// A [`Clock`] backed by the JavaScript runtime.
pub(crate) struct WebClock;

impl Clock for WebClock {
    fn current_time_monotonic(&self) -> MonotonicInstant {
        MonotonicInstant::from_nanos(monotonic_nanos())
    }

    fn current_time_wall_clock(&self) -> WallClockInstant {
        wall_clock_now()
    }
}

/// Milliseconds since the time origin, from `performance.now()`.
///
/// A worker has no `window`, so the value is read off the global object.
#[cfg(target_family = "wasm")]
fn performance_millis() -> Option<f64> {
    use wasm_bindgen::{JsCast, JsValue};

    let global = js_sys::global();
    let performance = js_sys::Reflect::get(&global, &JsValue::from_str("performance")).ok()?;
    let now = js_sys::Reflect::get(&performance, &JsValue::from_str("now")).ok()?;
    let now: js_sys::Function = now.dyn_into().ok()?;
    now.call0(&performance).ok()?.as_f64()
}

#[cfg(target_family = "wasm")]
fn monotonic_nanos() -> u128 {
    // Fall back to the wall clock where `performance` is missing.
    let millis = performance_millis().unwrap_or_else(js_sys::Date::now);
    (millis * 1_000_000.0) as u128
}

#[cfg(not(target_family = "wasm"))]
fn monotonic_nanos() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos()
}

#[cfg(target_family = "wasm")]
fn wall_clock_now() -> WallClockInstant {
    let millis = js_sys::Date::now();
    let secs = (millis / 1000.0).floor();
    let micros = ((millis - secs * 1000.0) * 1000.0).round() as u32;
    WallClockInstant {
        secs: secs as i64,
        micros: micros.min(999_999),
    }
}

#[cfg(not(target_family = "wasm"))]
fn wall_clock_now() -> WallClockInstant {
    use std::time::{SystemTime, UNIX_EPOCH};

    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    WallClockInstant {
        secs: since_epoch.as_secs() as i64,
        micros: since_epoch.subsec_micros(),
    }
}
