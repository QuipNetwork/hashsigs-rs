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

//! Stateful SHRINCS verification.
//!
//! Validate the stateful public key binding, reconstruct a compact WOTS-C public key
// from the signature, then climb the unbalanced stateful Merkle path back to the pinned root.

use super::shrincs_verifier_types::{
    PublicKey, StatefulSignature, ADDRESS_TYPE_WOTS_HASH, HASH_LEN, WOTS_BASE_STATEFUL,
    WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};
use super::shrincs_verifier_utils::{
    address_word32, base_w16_digit, decode_stateful_public_key, hash_node, hash_packed,
    matches_expected_public_key_commitment, valid_public_key,
};

pub(crate) fn verify_stateful_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    // Low-level verifier path. The caller supplies the signed message directly,
    // so replay protection and domain separation are entirely caller-managed.
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    let Some(stateful_key) = decode_stateful_public_key(&public_key.stateful_public_key) else {
        return false;
    };

    // The Solidity verifier encodes the leaf index as the authentication-path
    // length. Leaf zero is intentionally not accepted by this stateful layout.
    let leaf_index = signature.auth_path.len() as u32;
    if leaf_index == 0 {
        return false;
    }
    if leaf_index > stateful_key.max_signatures {
        return false;
    }
    if signature.chains.len() != WOTS_CHAINS_STATEFUL {
        return false;
    }

    // Reconstruct the compact WOTS-C public key hash from the signature chains.
    // This gives us the leaf value that should appear in the stateful tree.
    let Some(pk_hash) = compact_stateful_wots_public_key_from_signature(
        stateful_key.pk_seed,
        leaf_index,
        message,
        signature,
    ) else {
        return false;
    };
    // Climb the unbalanced path encoded by `auth_path` and compare it to the
    // stateful root inside the stateful public key.
    let Some(root) = root_from_unbalanced_path(
        stateful_key.pk_seed,
        leaf_index,
        pk_hash,
        &signature.auth_path,
    ) else {
        return false;
    };
    stateful_key.root == root
}

fn compact_stateful_wots_public_key_from_signature(
    pk_seed: [u8; HASH_LEN],
    leaf_index: u32,
    message: &[u8],
    signature: &StatefulSignature,
) -> Option<[u8; HASH_LEN]> {
    // The digest chooses one base-16 digit per chain. It is domain-separated by
    // pk_seed, leaf index, randomizer, counter, and the signed message.
    let digest = hash_packed(&[
        b"uxmss-wots-digits",
        &pk_seed,
        &leaf_index.to_be_bytes(),
        &signature.randomizer,
        &signature.counter.to_be_bytes(),
        message,
    ]);

    let mut digit_sum = 0u32;
    let mut segments = Vec::with_capacity(WOTS_CHAINS_STATEFUL * HASH_LEN);
    for chain_index in 0..WOTS_CHAINS_STATEFUL {
        let digit = base_w16_digit(&digest, chain_index);
        digit_sum = digit_sum.checked_add(digit)?;
        // A signature chain value is already at position `digit`. Verification
        // runs it forward to the chain end (`base - 1`) to recover the public
        // chain segment.
        let segment = stateful_chain_no_mask(
            pk_seed,
            leaf_index,
            chain_index as u32,
            signature.chains[chain_index],
            digit,
            WOTS_BASE_STATEFUL - 1 - digit,
        );
        segments.extend_from_slice(&segment);
    }

    // WOTS-C omits checksum chains. Instead, valid messages are restricted to
    // the fixed target sum expected by the Solidity verifier and vector set.
    if digit_sum != WOTS_TARGET_SUM_STATEFUL {
        return None;
    }
    Some(hash_node(&[
        b"uxmss-wots-pk",
        &pk_seed,
        &leaf_index.to_be_bytes(),
        &segments,
    ]))
}

fn root_from_unbalanced_path(
    pk_seed: [u8; HASH_LEN],
    leaf_index: u32,
    leaf: [u8; HASH_LEN],
    auth_path: &[[u8; HASH_LEN]],
) -> Option<[u8; HASH_LEN]> {
    if auth_path.len() != leaf_index as usize {
        return None;
    }
    if auth_path.is_empty() {
        return None;
    }
    // The first parent combines the WOTS leaf with the first sibling. Each
    // following step combines the next left sibling with the root accumulated so
    // far. This matches Solidity's unbalanced tree convention.
    let mut root = stateful_parent_hash(pk_seed, leaf_index, leaf, auth_path[0]);
    for offset in 0..auth_path.len() - 1 {
        root = stateful_parent_hash(
            pk_seed,
            leaf_index - offset as u32 - 1,
            auth_path[offset + 1],
            root,
        );
    }
    Some(root)
}

fn stateful_parent_hash(
    pk_seed: [u8; HASH_LEN],
    left_leaf_index: u32,
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // Parent nodes are domain-separated from WOTS chain hashes and bind the
    // left leaf index, preventing the same pair of children from moving around
    // the unbalanced tree.
    hash_node(&[
        b"uxmss-node",
        &pk_seed,
        &left_leaf_index.to_be_bytes(),
        &left,
        &right,
    ])
}

fn stateful_chain_no_mask(
    pk_seed: [u8; HASH_LEN],
    leaf_index: u32,
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    for step_offset in 0..steps {
        // The address word binds this chain hash to a single leaf, chain, and
        // step. Without it, chain segments could be replayed across positions.
        let address_word = address_word32(
            0,
            0,
            ADDRESS_TYPE_WOTS_HASH,
            leaf_index,
            chain_index,
            start + step_offset,
        );
        out = hash_stateful_wots_c_chain_no_mask32(pk_seed, address_word, out);
    }
    out
}

fn hash_stateful_wots_c_chain_no_mask32(
    pk_seed: [u8; HASH_LEN],
    address_word: [u8; HASH_LEN],
    segment: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_node(&[b"wots-c-chain", &pk_seed, &address_word, &segment])
}
