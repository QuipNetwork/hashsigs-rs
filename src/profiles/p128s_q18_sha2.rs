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

//! The `shrincs-128s-q18-sha2` profile. Mirrors
//! `contracts/profiles/128s-q18/SHRINCSParams.sol`. Every numeric parameter is
//! identical to [`crate::profiles::p128s_q18`]; only the scheme hash suite and
//! the profile identity string differ.

use crate::hash::suite::Sha2256Suite;
use crate::profile::Profile;
use crate::profiles::identity;

/// Parameter tuple for `shrincs-128s-q18-sha2`.
pub struct Profile128sQ18Sha2;

impl Profile for Profile128sQ18Sha2 {
    type Suite = Sha2256Suite;
    const PROFILE_NAME: &'static str = "shrincs-128s-q18-sha2";
    const PROFILE_ID: [u8; 32] = identity::p128s_q18_sha2::PROFILE_ID;
    const HASH_TRUNC_LEN: usize = 16;
    const STATELESS_SIGNATURE_LIMIT: u64 = 262_144;
    const HYPERTREE_HEIGHT: u8 = 18;
    const NUM_HYPERTREE_LAYERS: u8 = 1;
    const FORS_TREE_HEIGHT: u8 = 24;
    const NUM_FORS_TREES: u8 = 6;
    const WOTS_CHAIN_LEN: u16 = 16;
    const NUM_WOTS_CHAINS: u16 = 32;
    const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 28;
    const WOTS_TARGET_SUM: u32 = 240;
}

/// Compile-time proof that the hand-transcribed `PROFILE_NAME` above is
/// byte-identical to the one `build.rs` hashed into this profile's
/// `PROFILE_ID`. `PROFILE_ID` is ABI-bearing: the Solidity contracts compare
/// against it, so a typo in either copy is a wire break that no golden vector
/// would catch. A `const` item forces const evaluation, making that a build
/// failure rather than an unreached runtime assertion.
const _: () = assert!(
    crate::profile::str_eq(
        <Profile128sQ18Sha2 as Profile>::PROFILE_NAME,
        identity::p128s_q18_sha2::PROFILE_NAME
    ),
    "profile type PROFILE_NAME disagrees with the build script's profile identity"
);

/// `shrincs-128s-q18-sha2` instantiated.
pub type Shrincs = crate::shrincs::ShrincsCore<Profile128sQ18Sha2, 32, 1>;

/// Drift guard: forces the width check against THIS alias, by consuming the
/// associated const `ShrincsCore` already carries. The alias is the operand,
/// so editing either the alias widths or the profile's own `NUM_WOTS_CHAINS` /
/// `NUM_HYPERTREE_LAYERS` out of sync is a compile error, rather than a latent
/// bug caught only when `Shrincs::new()` happens to be called. Spelling the
/// widths out again here instead would check a third copy and leave the alias
/// unguarded.
const _: () = Shrincs::WIDTHS_AGREE;
