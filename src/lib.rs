// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core hash-based signature library.
//!
//! This crate exports:
//!
//! - WOTS+ primitives
//! - SHRINCS signer / verifier primitives
//! - shared SHRINCS types used by higher-level wrappers

// Panic-prevention lints (review bead qg4): library code must not panic on
// untrusted input. Scoped to non-test builds so `#[cfg(test)]` modules may use
// unwrap/expect freely. The broader `indexing-slicing` and full `pedantic`
// sets are intentionally deferred — under CI's `-D warnings` they would force
// a large, churn-heavy rewrite of the crypto slice code with no safety gain
// (the verifier already bounds every attacker-controlled index).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic_in_result_fn
    )
)]

pub mod account;
pub mod shrincs;
pub mod wasm;
pub mod wotsplus;

pub use wotsplus::{constants, HashFn, PublicKey, WOTSPlus};
