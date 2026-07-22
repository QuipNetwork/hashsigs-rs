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


//! Consolidated `#[cfg(test)]` helpers shared across modules.

use crate::shrincs::{
    derive32, encode_stateful_public_key, public_key_from_components, ShrincsSigningKey,
};
use crate::types::PublicKey;
use crate::uxmss;

const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;

/// Build a signing key that exercises only the stateful subsystem, with a
/// placeholder hypertree root. Avoids compute-infeasible stateless hypertree
/// keygen so it runs on every profile.
pub(crate) fn stateful_only_key(seed: &[u8], max: u32) -> (ShrincsSigningKey, PublicKey) {
    let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed, &[]);
    let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed, &[]);
    let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed, &[]);
    let stateful_root = uxmss::stateful_subtree_root(
        &stateful_sk_seed,
        &stateful_pk_seed,
        INITIAL_STATEFUL_LEAF_INDEX,
        max,
    );
    let pk_seed = derive32(b"shrincs-pk-seed", seed, &[]);
    let hypertree_root = derive32(b"placeholder-hypertree-root", seed, &[]);
    let signing_key = ShrincsSigningKey {
        stateful_sk_seed,
        stateful_prf_seed,
        stateful_pk_seed,
        stateful_root,
        max_stateful_signatures: max,
        next_stateful_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
        stateless_sk_seed: derive32(b"shrincs-stateless-sk-seed", seed, &[]),
        stateless_prf_seed: derive32(b"shrincs-stateless-prf-seed", seed, &[]),
        pk_seed,
        hypertree_root,
    };
    let public_key = public_key_from_components(
        encode_stateful_public_key(stateful_pk_seed, stateful_root, max),
        pk_seed,
        hypertree_root,
    );
    (signing_key, public_key)
}
