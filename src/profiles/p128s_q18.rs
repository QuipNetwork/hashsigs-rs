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

//! The `shrincs-128s-q18` profile. Mirrors
//! `contracts/profiles/128s-q18/SHRINCSParams.sol`.

use crate::hash::suite::Keccak256Suite;
use crate::profile::Profile;

/// Parameter tuple for `shrincs-128s-q18`.
pub struct Profile128sQ18;

impl Profile for Profile128sQ18 {
    type Suite = Keccak256Suite;
    const PROFILE_NAME: &'static str = "shrincs-128s-q18-keccak";
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

/// `shrincs-128s-q18` instantiated.
pub type Shrincs = crate::shrincs::ShrincsCore<Profile128sQ18, 32, 1>;
