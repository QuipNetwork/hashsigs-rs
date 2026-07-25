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
//! - independent SPHINCS+C layer
//! - SHRINCS hybrid signer / verifier
//! - shared types used by higher-level wrappers
//!
//! # Features
//!
//! - **`std`** (default): host surface, thiserror, env traces, serde std.
//! - **`alloc`**: `Vec`-based signature wire types (required for crypto APIs).
//! - **`solana`**: optional `solana-program` + syscall hash routing.
//! - Profile selectors and `wasm-bindings` as before.
//!
//! Pure-core no-alloc (fixed arrays only) is out of scope for this release;
//! `no_std + alloc` is the embedded baseline.

#![cfg_attr(not(feature = "std"), no_std)]

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

// Always available: the crate has no pure-core no-alloc build path.
// `no_std + alloc` is the embedded baseline (see module docs above). The
// `alloc` cargo feature remains as a no-op marker so existing
// `--features alloc,...` invocations and `std = ["alloc", ...]` keep working.
extern crate alloc;

#[macro_use]
mod trace_macros;

// Layering: `primitives` is scheme-neutral; `sphincs_plus_c` is the
// stateless scheme and is oblivious to `shrincs`; `shrincs` builds its
// hybrid (stateful UXMSS + stateless recovery) on top of `sphincs_plus_c`.
// `wasm` sits above both.
pub mod signer;
pub mod verifier;
pub(crate) mod hash;
pub(crate) mod primitives;
pub mod shrincs;
pub mod sphincs_plus_c;
#[cfg(feature = "std")]
pub mod wasm;
pub mod wotsplus;
pub mod wots_c;

#[cfg(all(test, feature = "std"))]
pub(crate) mod test_support;

pub use signer::SignerInterface;
pub use verifier::{VerifierInterface, VerifyOutcome};
pub use primitives::HASH_LEN;
pub use sphincs_plus_c::{
    keygen as sphincs_plus_c_keygen, sign as sphincs_plus_c_sign, to_message as sphincs_plus_c_to_message,
    verify as sphincs_plus_c_verify, verify_hash as sphincs_plus_c_verify_hash,
};
pub use sphincs_plus_c::SphincsPlusCVerifier;
pub use wotsplus::{constants, HashFn, PublicKey, WOTSPlus};
