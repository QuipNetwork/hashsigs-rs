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

//! Stateless SHRINCS composition over FORS-C and the hypertree.

use crate::shrincs::components::{fors_c, hypertree};
use crate::shrincs::shrincs_verifier_utils::{
    matches_expected_public_key_commitment, valid_public_key,
};
use crate::shrincs::types::{PublicKey, StatelessSignature, HASH_LEN};

pub(crate) fn verify_stateless_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    if signature.hypertree.is_empty() {
        return false;
    }

    let Some((fors_root, seed_tree_index, seed_leaf_index)) =
        fors_c::verify_fors_c_and_return_root(public_key, message, &signature.fors)
    else {
        return false;
    };
    hypertree::verify_hypertree(
        public_key,
        fors_root,
        seed_tree_index,
        seed_leaf_index,
        &signature.hypertree,
    )
}
