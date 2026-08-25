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

//! The `shrincs-256s` profile. Mirrors
//! `contracts/profiles/256s/SHRINCSParams.sol`.

use crate::hash::suite::Keccak256Suite;
use crate::profile::Profile;
use crate::profiles::identity;

/// Parameter tuple for `shrincs-256s`.
pub struct Profile256s;

impl Profile for Profile256s {
    type Suite = Keccak256Suite;
    const PROFILE_NAME: &'static str = "shrincs-256s-keccak";
    const PROFILE_ID: [u8; 32] = identity::p256s::PROFILE_ID;
    const HASH_TRUNC_LEN: usize = 32;
    const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    const HYPERTREE_HEIGHT: u8 = 64;
    const NUM_HYPERTREE_LAYERS: u8 = 8;
    const FORS_TREE_HEIGHT: u8 = 14;
    const NUM_FORS_TREES: u8 = 22;
    const WOTS_CHAIN_LEN: u16 = 16;
    const NUM_WOTS_CHAINS: u16 = 64;
    const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
    const WOTS_TARGET_SUM: u32 = 480;
}

/// Compile-time proof that the hand-transcribed `PROFILE_NAME` above is
/// byte-identical to the one `build.rs` hashed into this profile's
/// `PROFILE_ID`. `PROFILE_ID` is ABI-bearing: the Solidity contracts compare
/// against it, so a typo in either copy is a wire break that no golden vector
/// would catch. A `const` item forces const evaluation, making that a build
/// failure rather than an unreached runtime assertion.
const _: () = assert!(
    crate::profile::str_eq(
        <Profile256s as Profile>::PROFILE_NAME,
        identity::p256s::PROFILE_NAME
    ),
    "profile type PROFILE_NAME disagrees with the build script's profile identity"
);

/// `shrincs-256s` instantiated. The const generic arguments repeat
/// `NUM_WOTS_CHAINS` and `NUM_HYPERTREE_LAYERS` as `usize` array widths;
/// `assert_widths` rejects a mismatch at compile time.
pub type Shrincs = crate::shrincs::ShrincsCore<Profile256s, 64, 8>;

/// Drift guard for the literals above: forces `assert_widths` to run against
/// this alias's own `64, 8`, independently of `Profile256s::NUM_WOTS_CHAINS`
/// and `NUM_HYPERTREE_LAYERS`, so a hand-edit to either side that goes out of
/// sync is a compile error rather than a latent bug caught only when
/// `Shrincs::new()` happens to be called.
const _: () = crate::profile::assert_widths::<Profile256s, 64, 8>();
