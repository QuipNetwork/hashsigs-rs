// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal println helpers that compile under `no_std`.

/// `println!` when `std` is enabled; no-op otherwise.
#[cfg(feature = "std")]
macro_rules! hashsigs_println {
    ($($arg:tt)*) => {
        ::std::println!($($arg)*)
    };
}

#[cfg(not(feature = "std"))]
macro_rules! hashsigs_println {
    ($($arg:tt)*) => {{
        if false {
            let _ = format_args!($($arg)*);
        }
    }};
}

/// Whether stateless-signing debug tracing is enabled via `SHRINCS_TRACE_STATELESS`.
pub(crate) fn stateless_trace_enabled() -> bool {
    #[cfg(feature = "std")]
    {
        matches!(
            std::env::var("SHRINCS_TRACE_STATELESS").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        )
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

/// How often the FORS-C sequential counter grind logs progress, from
/// `SHRINCS_TRACE_COUNTER_EVERY` (defaults to `1 << 20`).
#[cfg(not(feature = "parallel"))]
pub(crate) fn stateless_trace_counter_every() -> u32 {
    #[cfg(feature = "std")]
    {
        std::env::var("SHRINCS_TRACE_COUNTER_EVERY")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1 << 20)
    }
    #[cfg(not(feature = "std"))]
    {
        1 << 20
    }
}

/// Emit a stateless-trace message when `stateless_trace_enabled()`; no-op otherwise.
pub(crate) fn stateless_trace(message: &str) {
    #[cfg(feature = "std")]
    if stateless_trace_enabled() {
        hashsigs_println!("{message}");
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = message;
    }
}
