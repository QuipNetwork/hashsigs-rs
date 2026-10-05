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

//! A reduced profile for the replays of key generation and stateless
//! signing. It keeps every algorithm and shrinks every tree: a hypertree of
//! two layers of height 2, three FORS trees of height 2, and eight WOTS-C
//! chains. Its FORS digest fits one hash block, so the full profile and this
//! one together cover both branches of `fors_digest_bytes`.

use crate::hash::suite::Keccak256Suite;
use crate::profile::Profile;

/// The reduced profile.
pub struct Toy;

/// WOTS-C chains of [`Toy`].
pub const TOY_CHAINS: usize = 8;
/// Hypertree layers of [`Toy`].
pub const TOY_LAYERS: usize = 2;

impl Profile for Toy {
    type Suite = Keccak256Suite;
    const PROFILE_NAME: &'static str = "shrincs-kat-toy-keccak";
    // keccak256(PROFILE_NAME), checked by the test below.
    const PROFILE_ID: [u8; 32] = [
        0xb9, 0xa0, 0xfa, 0x3f, 0xe4, 0xbb, 0x2c, 0x8e, 0x74, 0x11, 0xfc, 0xd1, 0xbc, 0x54, 0x45,
        0x63, 0xca, 0xca, 0x75, 0x74, 0xd2, 0x47, 0x4f, 0x9b, 0x59, 0x38, 0xf8, 0xa8, 0xb7, 0x95,
        0x75, 0xe2,
    ];
    const HASH_TRUNC_LEN: usize = 32;
    const STATELESS_SIGNATURE_LIMIT: u64 = 16;
    const HYPERTREE_HEIGHT: u8 = 4;
    const NUM_HYPERTREE_LAYERS: u8 = TOY_LAYERS as u8;
    const FORS_TREE_HEIGHT: u8 = 2;
    const NUM_FORS_TREES: u8 = 3;
    const WOTS_CHAIN_LEN: u16 = 16;
    const NUM_WOTS_CHAINS: u16 = TOY_CHAINS as u16;
    const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
    const WOTS_TARGET_SUM: u32 = 60;
}

#[cfg(test)]
mod tests {
    use super::Toy;
    use crate::hash::backend::keccak256v;
    use crate::profile::Profile;

    #[test]
    fn toy_profile_id_is_the_keccak_hash_of_its_name() {
        assert_eq!(Toy::PROFILE_ID, keccak256v(&[Toy::PROFILE_NAME.as_bytes()]));
    }
}
