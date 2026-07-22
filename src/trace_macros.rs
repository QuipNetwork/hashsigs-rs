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
