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

//! FORS-C signing.
//!
//! A key owns one FORS forest. The message digest chooses one leaf in each FORS
//! tree and also chooses the starting hypertree coordinates above the FORS layer.
//! Those coordinates are address/domain context for the opened leaves and nodes,
//! not a selector for a separate FORS public key.

use super::super::components::fors_c;
use super::types::{ShrincsSignerResult, ShrincsSigningKey};
use super::utils::{hash_node, hash_packed, FORS_C_MAX_GRIND_COUNTER};
use super::super::types::{ForsEntry, ForsSignature, HASH_LEN};
use super::super::profiles::NUM_FORS_TREES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedForsC {
    /// Aggregate FORS public root reconstructed from the opened tree roots.
    pub root: [u8; HASH_LEN],
    /// Signature payload that the verifier consumes: one secret leaf and auth path
    /// for every signed FORS tree.
    pub signature: ForsSignature,
    /// Layer-0 hypertree tree selected by the FORS message digest.
    pub tree_index: u64,
    /// Layer-0 hypertree leaf selected by the FORS message digest.
    pub leaf_index: u32,
}

pub(crate) fn sign_fors_c(
    signing_key: &ShrincsSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<SignedForsC> {
    // FORS-C signs k - 1 trees. The final tree is omitted only when the digest
    // selects leaf zero for that final tree, so the signer grinds the counter
    // until that condition holds.
    let signed_trees = NUM_FORS_TREES as usize - 1;

    // This is the FORS-C local message randomizer. It is deterministic for the
    // same stateless PRF seed and message, matching the SPHINCS-style separation
    // between SK.seed-derived signing secrets and SK.prf-derived randomness.
    let randomizer = hash_packed(&[b"fors-randomizer", &signing_key.stateless_prf_seed, message]);

    for counter in 0..FORS_C_MAX_GRIND_COUNTER {
        // The counter is public and stored in the signature. Its only job is to
        // find a digest whose omitted final FORS tree opens leaf zero.
        let Some(digest) = fors_c::signer_fors_digest(
            &signing_key.pk_seed,
            &signing_key.hypertree_root,
            message,
            &randomizer,
            counter,
        ) else {
            continue;
        };
        if !digest.omitted_final_tree_is_zero {
            continue;
        }

        let mut roots = Vec::with_capacity(signed_trees * HASH_LEN);
        let mut entries = Vec::with_capacity(signed_trees);
        for fors_tree in 0..signed_trees {
            // For each selected tree, reveal exactly the chosen secret leaf and
            // provide the siblings needed to recompute that tree's root.
            let leaf = digest.signed_tree_indices[fors_tree];
            let (root, secret_leaf, auth_path) = fors_c::fors_tree_root_and_auth_path(
                &signing_key.pk_seed,
                &signing_key.stateless_sk_seed,
                digest.tree_index,
                digest.leaf_index,
                fors_tree as u32,
                leaf,
            );
            roots.extend_from_slice(&root);
            entries.push(ForsEntry {
                secret_leaf: secret_leaf.to_vec(),
                auth_path,
            });
        }

        // The verifier aggregates the reconstructed per-tree roots the same way.
        // The public seed is included so roots from a different FORS key cannot
        // be transplanted into this key.
        return Some(SignedForsC {
            root: hash_node(&[b"fors-pk", &signing_key.pk_seed, &roots]),
            signature: ForsSignature {
                randomizer: randomizer.to_vec(),
                counter,
                entries,
            },
            tree_index: digest.tree_index,
            leaf_index: digest.leaf_index,
        });
    }

    None
}
