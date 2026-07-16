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
use crate::shrincs::components::hash::word32;
use crate::shrincs::types::{PublicKey, StatelessSignature};

pub(crate) fn verify_stateless_raw(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    if signature.hypertree.is_empty() {
        return false;
    }
    let Some(pk_seed) = word32(&public_key.pk_seed) else {
        return false;
    };
    let Some(hypertree_root) = word32(&public_key.hypertree_root) else {
        return false;
    };

    let Some((fors_root, seed_tree_index, seed_leaf_index)) =
        fors_c::verify_fors_c_and_return_root(&pk_seed, &hypertree_root, message, &signature.fors)
    else {
        return false;
    };
    hypertree::verify_hypertree(
        &pk_seed,
        &hypertree_root,
        fors_root,
        seed_tree_index,
        seed_leaf_index,
        &signature.hypertree,
    )
}
