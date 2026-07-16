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
// NUM_WOTS_CHAINS, ...) comes exclusively from the `profile` module below via
// `pub use profile::*`. These must NOT also be declared unconditionally here:
// an explicit item silently shadows a glob re-export, so a top-level copy would
// pin every profile to the 256s values and quietly break `profile-128s-*` builds.

// Per-profile SHRINCS/SPHINCS parameter tuple, selected at compile time by
// cargo feature. This mirrors the Solidity
// contracts/profiles/<profile>/SHRINCSParams.sol libraries (one per build
// profile, selected by the `shrincs-profile/` Foundry remapping). Counts size
// arrays and bound loops, so they must be compile-time constants. Every value
// below matches the corresponding Solidity `SHRINCSParams` values for the
// Rust-implemented profiles.
#[cfg(any(
    all(feature = "profile-128s-q18", feature = "profile-128s-q20"),
    all(feature = "profile-128s-q18", feature = "profile-256s-sha2"),
    all(feature = "profile-128s-q20", feature = "profile-256s-sha2")
))]
compile_error!(
    "select at most one SHRINCS profile feature \
     (profile-128s-q18, profile-128s-q20, or profile-256s-sha2)"
);

#[cfg(not(any(
    feature = "profile-128s-q18",
    feature = "profile-128s-q20",
    feature = "profile-256s-sha2"
)))]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-256s-keccak";
    pub const PROFILE_ID: [u8; 32] = [
        0x32, 0xf5, 0x73, 0xb4, 0x53, 0xff, 0xc4, 0xb3, 0xed, 0xb5, 0xdb, 0x5c,
        0x8c, 0x6f, 0x10, 0xd9, 0x2a, 0xae, 0x60, 0xd6, 0xb7, 0x74, 0x91, 0x16,
        0xa8, 0x66, 0x51, 0xf5, 0x6e, 0x2a, 0x48, 0x78,
    ];
    pub const HASH_TRUNC_LEN: usize = 32;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    pub const WOTS_CHAINS_STATEFUL: usize = 64;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 480;
    pub const WOTS_TARGET_SUM_STATELESS: u32 = 480;
}

#[cfg(feature = "profile-128s-q18")]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q18-keccak";
    pub const PROFILE_ID: [u8; 32] = [
        0x27, 0x4b, 0xab, 0x86, 0x7d, 0xc0, 0x6d, 0x56, 0x2b, 0x1e, 0x14, 0x04,
        0x5b, 0xe5, 0x9a, 0xd5, 0x21, 0xf6, 0x5e, 0x70, 0x1f, 0x05, 0x42, 0x18,
        0x56, 0x73, 0x87, 0x99, 0x26, 0x3c, 0x6c, 0x1e,
    ];
    pub const HASH_TRUNC_LEN: usize = 16;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 262_144;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    pub const WOTS_CHAINS_STATEFUL: usize = 32;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 240;
    pub const WOTS_TARGET_SUM_STATELESS: u32 = 240;
}

#[cfg(all(feature = "profile-128s-q20", not(feature = "profile-128s-q18")))]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q20-keccak";
    pub const PROFILE_ID: [u8; 32] = [
        0x3b, 0xce, 0x70, 0x58, 0xcc, 0xa6, 0xaa, 0x5f, 0x5d, 0x6e, 0x80, 0xd6,
        0x5d, 0x93, 0x99, 0x98, 0xbb, 0xe2, 0x5a, 0xca, 0x79, 0xad, 0xe0, 0x09,
        0xa0, 0xe3, 0x40, 0x69, 0x8b, 0x58, 0xde, 0xe9,
    ];
    pub const HASH_TRUNC_LEN: usize = 16;
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
    pub const WOTS_TARGET_SUM_STATELESS: u32 = 240;
}

#[cfg(feature = "profile-256s-sha2")]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-256s-sha2";
    pub const PROFILE_ID: [u8; 32] = [
        0x80, 0x7d, 0xe9, 0x8a, 0xc6, 0x5a, 0xb9, 0xf0, 0x32, 0x89, 0x95, 0x0d,
        0x18, 0x78, 0xe5, 0xec, 0x52, 0x61, 0xf1, 0x62, 0xaf, 0x55, 0x93, 0xcc,
        0xba, 0x2f, 0x17, 0x09, 0xc7, 0x93, 0xc2, 0xbb,
    ];
    pub const HASH_TRUNC_LEN: usize = 32;
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    pub const WOTS_CHAINS_STATEFUL: usize = 64;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 480;
    pub const WOTS_TARGET_SUM_STATELESS: u32 = 480;
}

pub use profile::*;
