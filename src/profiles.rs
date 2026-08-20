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

//! Compile-time SHRINCS profile constants.

// The per-profile parameter tuple (STATELESS_SIGNATURE_LIMIT, HYPERTREE_HEIGHT,
// NUM_HYPERTREE_LAYERS, FORS_TREE_HEIGHT, NUM_FORS_TREES, WOTS_CHAIN_LEN,
// NUM_WOTS_CHAINS, FORS_C_MAX_GRIND_COUNTER, WOTS_TARGET_SUM, ...) comes
// exclusively from the `profile` module below via
// `pub use profile::*`. These must NOT also be declared unconditionally here:
// an explicit item silently shadows a glob re-export, so a top-level copy would
// pin every profile to the 256s values and quietly break `profile-128s-*` builds.

// Per-profile SHRINCS/SPHINCS parameter tuple, selected at compile time by the
// build-script-emitted profile cfg. This mirrors the Solidity
// contracts/profiles/<profile>/SHRINCSParams.sol libraries (one per build
// profile, selected by the `shrincs-profile/` Foundry remapping). Counts size
// arrays and bound loops, so they must be compile-time constants. Every value
// below matches the corresponding Solidity `SHRINCSParams` values for the
// Rust-implemented profiles. Solidity's SHRINCSParams keeps separate
// WOTS_*_STATEFUL/_STATELESS target-sum constants per tree; the Rust
// deliberately unifies them into the single `WOTS_TARGET_SUM` here since every
// profile uses identical values for both trees (owned alongside `NUM_CHAINS`/
// `BASE` in `crate::wots_c`, parity preserved, values unchanged).
#[cfg(shrincs_profile_256s)]
mod profile {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identity.rs"));
    pub const HASH_TRUNC_LEN: usize = 32;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    pub const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
    pub const WOTS_TARGET_SUM: u32 = 480;
}

#[cfg(shrincs_profile_128s_q18)]
mod profile {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identity.rs"));
    pub const HASH_TRUNC_LEN: usize = 16;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 262_144;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    pub const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 28;
    pub const WOTS_TARGET_SUM: u32 = 240;
}

#[cfg(shrincs_profile_128s_q20)]
mod profile {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identity.rs"));
    pub const HASH_TRUNC_LEN: usize = 16;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    pub const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 28;
    pub const WOTS_TARGET_SUM: u32 = 240;
}

#[cfg(shrincs_profile_256s_sha2)]
mod profile {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identity.rs"));
    pub const HASH_TRUNC_LEN: usize = 32;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    pub const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
    pub const WOTS_TARGET_SUM: u32 = 480;
}

pub use profile::*;

/// Maximum grind counter for WOTS-C target-sum searches (stateless + stateful).
pub(crate) const WOTS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
