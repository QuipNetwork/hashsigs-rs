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

// The per-profile parameter tuple (STATELESS_SIGNATURE_LIMIT, HYPERTREE_HEIGHT,
// NUM_HYPERTREE_LAYERS, FORS_TREE_HEIGHT, NUM_FORS_TREES, WOTS_CHAIN_LEN,
// NUM_WOTS_CHAINS, ...) comes exclusively from the `profile` module below via
// `pub use profile::*`. These must NOT also be declared unconditionally here:
// an explicit item silently shadows a glob re-export, so a top-level copy would
// pin every profile to the 256s values and quietly break `profile-128s-*` builds.

// Per-profile SHRINCS/SPHINCS parameter tuple, selected at compile time by
// cargo feature. This mirrors the Solidity
// contracts/profiles/<profile>/SHRINCSParams.sol libraries (one per build
// profile, selected by the `shrincs-profile/` Foundry remapping). Counts size
// arrays and bound loops, so they must be compile-time constants. Every value
// below matches its Solidity `SHRINCSParams` counterpart exactly.
#[cfg(all(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
compile_error!(
    "select at most one SHRINCS 128s profile feature \
     (profile-128s-q18 or profile-128s-q20)"
);

// shrincs-256s (default): contracts/profiles/256s/SHRINCSParams.sol.
#[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
mod profile {
    /// Suite-qualified profile identifier, matching the Solidity PROFILE_ID
    /// preimage. Reserved for tooling/vector labelling; T6 binds it into the
    /// public-key commitment tag.
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-256s-keccak";
    /// SPHINCS `n` (HASH_LEN = 32): no truncation, `mask_hash` is a no-op.
    pub const HASH_TRUNC_LEN: usize = 32;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    /// Stateful WOTS-C uses 64 chains.
    pub const WOTS_CHAINS_STATEFUL: usize = 64;
    /// Stateful WOTS-C uses base-16 digits for message expansion.
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    /// The 64 base-16 stateful digits must sum to 64 * (16 - 1) / 2 = 480.
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 480;
}

// shrincs-128s-q18: contracts/profiles/128s-q18/SHRINCSParams.sol.
#[cfg(feature = "profile-128s-q18")]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q18-keccak";
    /// SPHINCS `n` = 16: hash outputs are truncated to the high 16 bytes.
    pub const HASH_TRUNC_LEN: usize = 16;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 262_144;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    /// Stateful WOTS-C follows n: 2n = 32 chains.
    pub const WOTS_CHAINS_STATEFUL: usize = 32;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    /// The 32 base-16 stateful digits must sum to 32 * (16 - 1) / 2 = 240.
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 240;
}

// shrincs-128s-q20: contracts/profiles/128s-q20/SHRINCSParams.sol. Shares
// every constant with q18 except the stateless signature budget (2^20).
#[cfg(all(feature = "profile-128s-q20", not(feature = "profile-128s-q18")))]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q20-keccak";
    pub const HASH_TRUNC_LEN: usize = 16;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    pub const WOTS_CHAINS_STATEFUL: usize = 32;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 240;
}

pub use profile::*;
