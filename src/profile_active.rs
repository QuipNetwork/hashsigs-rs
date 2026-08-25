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

//! Bridge from the old cfg-selected profile to the new [`Profile`] trait.
//!
//! TEMPORARY. Task 4 genericised every algorithm over `P: Profile`, but the
//! per-profile types and the default alias belong to Task 5. Until those
//! exist, callers that used to rely on the cfg-selected `crate::profiles`
//! constants — the public free functions, the `wasm` bindings, and the
//! in-crate test modules — instantiate the algorithms at [`ActiveProfile`].
//!
//! Every value here is *read from* `crate::profiles`; nothing is redeclared,
//! so a profile parameter cannot drift. Task 5 deletes this module together
//! with `crate::profiles` and repoints these three names at the real profile
//! types.

use crate::hash::suite::HashSuite;
use crate::profile::Profile;

/// The profile selected by the build-script cfg, as a [`Profile`] type.
pub(crate) struct ActiveProfile;

/// Scheme hash suite for the active profile, selected by the same cfg
/// `build.rs` already emits.
#[cfg(not(shrincs_hash_suite_sha2))]
type ActiveSuite = crate::hash::suite::Keccak256Suite;
#[cfg(shrincs_hash_suite_sha2)]
type ActiveSuite = crate::hash::suite::Sha2256Suite;

impl Profile for ActiveProfile {
    type Suite = ActiveSuite;

    const PROFILE_NAME: &'static str = crate::profiles::PROFILE_NAME;
    const HASH_TRUNC_LEN: usize = crate::profiles::HASH_TRUNC_LEN;
    const STATELESS_SIGNATURE_LIMIT: u64 = crate::profiles::STATELESS_SIGNATURE_LIMIT;
    const HYPERTREE_HEIGHT: u8 = crate::profiles::HYPERTREE_HEIGHT;
    const NUM_HYPERTREE_LAYERS: u8 = crate::profiles::NUM_HYPERTREE_LAYERS;
    const FORS_TREE_HEIGHT: u8 = crate::profiles::FORS_TREE_HEIGHT;
    const NUM_FORS_TREES: u8 = crate::profiles::NUM_FORS_TREES;
    const WOTS_CHAIN_LEN: u16 = crate::profiles::WOTS_CHAIN_LEN;
    const NUM_WOTS_CHAINS: u16 = crate::profiles::NUM_WOTS_CHAINS;
    const FORS_C_MAX_GRIND_COUNTER: u32 = crate::profiles::FORS_C_MAX_GRIND_COUNTER;
    const WOTS_TARGET_SUM: u32 = crate::profiles::WOTS_TARGET_SUM;
}

/// `ActiveProfile::NUM_WOTS_CHAINS` as an array width. A plain `const`, not a
/// generic expression, so it is legal in array-length position.
pub(crate) const NUM_CHAINS: usize = crate::profiles::NUM_WOTS_CHAINS as usize;

/// `ActiveProfile::NUM_HYPERTREE_LAYERS` as an array width.
pub(crate) const NUM_LAYERS: usize = crate::profiles::NUM_HYPERTREE_LAYERS as usize;

/// Compile-time proof that the two width constants above agree with the
/// trait constants, in the same associated-const form the core types use.
const _: () = crate::profile::assert_widths::<ActiveProfile, NUM_CHAINS, NUM_LAYERS>();

/// The suite id of the active profile, for the sites that still fold it into
/// a preimage or a wire field.
#[allow(dead_code)]
pub(crate) const ACTIVE_HASH_SUITE_ID: u32 = <ActiveSuite as HashSuite>::HASH_SUITE_ID;
