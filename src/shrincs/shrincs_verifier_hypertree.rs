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

//! Hypertree and stateless WOTS-C verification.
//!
//! The FORS root becomes the message for layer 0. Each layer verifies a WOTS-C
// signature for the current root, then climbs that layer's authentication path
// to produce the message for the next layer. The final layer must close at the
// hypertree root in the public key.

use super::shrincs_verifier_types::{
    HypertreeLayerSignature, PublicKey, WotsCSignature, HASH_LEN, HYPERTREE_HEIGHT,
    NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN, WOTS_TARGET_SUM_STATEFUL,
};
use super::shrincs_verifier_utils::{
    base_w_digit, hash_node, hash_packed, hypertree_address_word, word32, wots_address_base,
    wots_chain_address_word, wots_digest_bytes,
};

pub(crate) fn verify_hypertree(
    public_key: &PublicKey,
    fors_root: [u8; HASH_LEN],
    seed_tree_index: u64,
    seed_leaf_index: u32,
    layers: &[HypertreeLayerSignature],
) -> bool {
    if layers.len() != NUM_HYPERTREE_LAYERS as usize {
        return false;
    }
    // The hypertree is split evenly into the fixed layer count: 64 / 8 = 8
    // levels per layer.
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    if subtree_height == 0 {
        return false;
    }
    // `leaf_count` below shifts a u32, so the guard must be u32::BITS (not
    // u64::BITS): a profile with subtree_height in 32..64 would otherwise pass
    // this check and panic on the `1u32 << subtree_height` shift.
    if subtree_height >= u32::BITS {
        return false;
    }
    let leaf_count = 1u32 << subtree_height;
    let leaf_mask = (1u64 << subtree_height) - 1;
    let mut current_root = fors_root;
    // Layer-0 coordinates are seeded from the FORS digest (passed in by the
    // caller); every higher layer's coordinates are derived by the canonical
    // recurrence below. The signature no longer carries them, so there is no
    // carried-vs-derived equality check.
    let mut expected_tree_index = seed_tree_index;
    let mut expected_leaf_index = seed_leaf_index;

    for (layer_index, layer_signature) in layers.iter().enumerate() {
        if expected_leaf_index >= leaf_count
            || layer_signature.wots_c_pk_hash.len() != HASH_LEN
            || layer_signature.auth_path.len() != subtree_height as usize
        {
            return false;
        }
        // The current root is the message for this layer's WOTS-C signature.
        // Layer 0 starts with the FORS root; later layers use the root produced
        // by the previous layer's Merkle path.
        if !verify_wots_c32(
            &public_key.pk_seed,
            layer_index as u32,
            expected_tree_index,
            expected_leaf_index,
            &layer_signature.wots_c_pk_hash,
            current_root,
            &layer_signature.wots_c_signature,
        ) {
            return false;
        }
        let Some(layer_leaf) = word32(&layer_signature.wots_c_pk_hash) else {
            return false;
        };
        // Treat the verified WOTS-C public-key hash as the leaf of this layer
        // and climb the layer-local authentication path.
        let Some(next_root) = hypertree_root_from_path32(
            subtree_height,
            &public_key.pk_seed,
            layer_index as u32,
            expected_tree_index,
            expected_leaf_index,
            layer_leaf,
            &layer_signature.auth_path,
        ) else {
            return false;
        };
        current_root = next_root;
        expected_leaf_index = (expected_tree_index & leaf_mask) as u32;
        expected_tree_index >>= subtree_height;
    }

    // After all layers, the original FORS-selected tree coordinate must be fully
    // consumed. A nonzero remainder would mean the signature described a path
    // outside the declared hypertree height.
    expected_tree_index == 0 && word32(&public_key.hypertree_root) == Some(current_root)
}

fn verify_wots_c32(
    pk_seed_bytes: &[u8],
    layer: u32,
    tree: u64,
    keypair: u32,
    expected_pk_hash_bytes: &[u8],
    message: [u8; HASH_LEN],
    signature: &WotsCSignature,
) -> bool {
    let chain_count = NUM_WOTS_CHAINS as usize;
    // Each WOTS-C signature must have one randomizer, one counter, one expected
    // 32-byte public-key hash, and exactly `num_wots_chains` chain values.
    // Wire fields stay 32-byte slots in every profile; the WOTS message digest,
    // however, is `wots_digest_bytes()` bytes read out of a full 32-byte keccak
    // (16 for the 128s profiles, 32 for 256s). Guard only against a digest that
    // would over-read the slot, matching the Solidity `wotsDigestBytes() <= 32`
    // relaxation ([DESIGN §3.3]); for 256s this is still exactly 32.
    if signature.randomizer.len() != HASH_LEN
        || signature.chains.len() != chain_count
        || expected_pk_hash_bytes.len() != HASH_LEN
        || wots_digest_bytes() > HASH_LEN
    {
        return false;
    }
    let Some(pk_seed) = word32(pk_seed_bytes) else {
        return false;
    };
    let Some(expected_pk_hash) = word32(expected_pk_hash_bytes) else {
        return false;
    };
    let Some(randomizer) = word32(&signature.randomizer) else {
        return false;
    };
    let digest = wots_digest32(
        pk_seed,
        expected_pk_hash,
        randomizer,
        signature.counter,
        message,
    );

    let address_base = wots_address_base(layer, tree, keypair);
    let mut digit_sum = 0u32;
    let mut pk_input_segments = Vec::with_capacity(chain_count * HASH_LEN);
    for chain_index in 0..chain_count {
        let Some(chain_value) = signature
            .chains
            .get(chain_index)
            .and_then(|value| word32(value))
        else {
            return false;
        };
        // The digest digit tells us how far along this chain the signature value
        // starts. Verification runs from that digit to the end of the chain.
        let digit = base_w_digit(WOTS_CHAIN_LEN, &digest, chain_index);
        // Unify digit-sum accumulation with the stateful verifier's
        // `checked_add(...)?`: fail closed on overflow rather than saturating.
        let Some(next_sum) = digit_sum.checked_add(digit) else {
            return false;
        };
        digit_sum = next_sum;
        let segment = wots_chain32_no_mask_base(
            WOTS_CHAIN_LEN,
            pk_seed,
            address_base,
            chain_index as u32,
            chain_value,
            digit,
        );
        pk_input_segments.extend_from_slice(&segment);
    }
    // WOTS-C does not carry an explicit checksum chain suffix. Instead the message expansion
    // is accepted only when reconstructed base-w digits add up to the fixed target sum.
    if digit_sum != WOTS_TARGET_SUM_STATEFUL {
        return false;
    }

    let computed_pk_hash = hash_node(&[b"wots-c-pk", &pk_seed, &pk_input_segments]);
    computed_pk_hash == expected_pk_hash
}

fn wots_digest32(
    pk_seed: [u8; HASH_LEN],
    expected_pk_hash: [u8; HASH_LEN],
    randomizer: [u8; HASH_LEN],
    counter: u32,
    message: [u8; HASH_LEN],
) -> Vec<u8> {
    // WOTS-C message expansion is domain-separated by the public seed, expected
    // WOTS public-key hash, randomizer, counter, and current layer message/root.
    hash_packed(&[
        b"wots-c-msg",
        &pk_seed,
        &expected_pk_hash,
        &randomizer,
        &counter.to_be_bytes(),
        &message,
    ])
    .to_vec()
}

fn wots_chain32_no_mask_base(
    w: u16,
    pk_seed: [u8; HASH_LEN],
    address_base: [u8; HASH_LEN],
    chain_index: u32,
    value: [u8; HASH_LEN],
    digit: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    let steps = u32::from(w - 1) - digit;
    for step_offset in 0..steps {
        // Every chain step is addressed, binding it to this layer/tree/leaf and chain index.
        let address_word = wots_chain_address_word(address_base, chain_index, digit + step_offset);
        out = hash_stateless_wots_c_chain_no_mask32(pk_seed, address_word, out);
    }
    out
}

fn hash_stateless_wots_c_chain_no_mask32(
    pk_seed: [u8; HASH_LEN],
    address_word: [u8; HASH_LEN],
    segment: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_node(&[b"wots-c-chain", &pk_seed, &address_word, &segment])
}

fn hypertree_root_from_path32(
    height: u32,
    pk_seed: &[u8],
    layer: u32,
    tree_index: u64,
    leaf_index: u32,
    leaf: [u8; HASH_LEN],
    auth_path: &[Vec<u8>],
) -> Option<[u8; HASH_LEN]> {
    if auth_path.len() != height as usize {
        return None;
    }
    let pk_seed = word32(pk_seed)?;
    let mut node = leaf;
    let mut index = leaf_index;
    for level in 0..height {
        let sibling = word32(auth_path.get(level as usize)?)?;
        // Merkle path ordering is determined by the current index bit. After
        // hashing one parent, shift right to move to the next tree level.
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let address_word =
            hypertree_address_word(layer, tree_index, level + 1, u64::from(index >> 1));
        node = hash_hypertree_node32(pk_seed, address_word, left, right);
        index >>= 1;
    }
    Some(node)
}

fn hash_hypertree_node32(
    pk_seed: [u8; HASH_LEN],
    address_word: [u8; HASH_LEN],
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // Domain-separated parent hash for hypertree nodes. The address word binds
    // this hash to its exact layer/tree/height/parent-index position.
    hash_node(&[b"hypertree-node", &pk_seed, &address_word, &left, &right])
}
