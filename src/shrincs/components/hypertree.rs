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

//! Hypertree primitive verification logic.

use super::super::profiles::{
    HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN,
    WOTS_TARGET_SUM_STATELESS,
};
use super::hash::{
    address_word32, base_w_digit, hash_node, hash_packed, hypertree_address_word, word32,
    wots_address_base, wots_chain_address_word, wots_digest_bytes,
};
use super::super::types::{HypertreeLayerSignature, WotsCSignature, HASH_LEN};

pub(crate) fn verify_hypertree(
    pk_seed: &[u8; HASH_LEN],
    expected_hypertree_root: &[u8; HASH_LEN],
    fors_root: [u8; HASH_LEN],
    seed_tree_index: u64,
    seed_leaf_index: u32,
    layers: &[HypertreeLayerSignature],
) -> bool {
    if layers.len() != NUM_HYPERTREE_LAYERS as usize {
        return false;
    }
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    if subtree_height == 0 || subtree_height >= u32::BITS {
        return false;
    }
    let leaf_count = 1u32 << subtree_height;
    let leaf_mask = (1u64 << subtree_height) - 1;
    let mut current_root = fors_root;
    let mut expected_tree_index = seed_tree_index;
    let mut expected_leaf_index = seed_leaf_index;

    for (layer_index, layer_signature) in layers.iter().enumerate() {
        if expected_leaf_index >= leaf_count
            || layer_signature.wots_c_pk_hash.len() != HASH_LEN
            || layer_signature.auth_path.len() != subtree_height as usize
        {
            return false;
        }
        if !verify_wots_c32(
            pk_seed,
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
        let Some(next_root) = hypertree_root_from_path32(
            subtree_height,
            pk_seed,
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

    expected_tree_index == 0 && *expected_hypertree_root == current_root
}

pub(crate) fn stateless_wots_message_digest(
    pk_seed: &[u8; HASH_LEN],
    expected_pk_hash: &[u8; HASH_LEN],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
    message: &[u8; HASH_LEN],
) -> Vec<u8> {
    hash_packed(&[
        b"wots-c-msg".as_ref(),
        pk_seed.as_ref(),
        expected_pk_hash.as_ref(),
        randomizer.as_ref(),
        counter.to_be_bytes().as_ref(),
        message.as_ref(),
    ])
    .to_vec()
}

pub(crate) struct StatelessWotsChainCtx<'a> {
    pub(crate) pk_seed: &'a [u8; HASH_LEN],
    pub(crate) layer: u32,
    pub(crate) tree: u64,
    pub(crate) keypair: u32,
    pub(crate) chain_index: u32,
}

pub(crate) fn stateless_wots_chain(
    ctx: &StatelessWotsChainCtx<'_>,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    for step in start..start + steps {
        let address_word = address_word32(
            ctx.layer,
            ctx.tree,
            0,
            ctx.keypair,
            ctx.chain_index,
            step,
        );
        out = hash_node(&[
            b"wots-c-chain".as_ref(),
            ctx.pk_seed.as_ref(),
            address_word.as_ref(),
            out.as_ref(),
        ]);
    }
    out
}

pub(crate) fn stateless_wots_chain_from_address_base(
    pk_seed: &[u8; HASH_LEN],
    address_base: [u8; HASH_LEN],
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    for step_offset in 0..steps {
        let address_word = wots_chain_address_word(address_base, chain_index, start + step_offset);
        out = hash_node(&[
            b"wots-c-chain".as_ref(),
            pk_seed.as_ref(),
            address_word.as_ref(),
            out.as_ref(),
        ]);
    }
    out
}

pub(crate) fn stateless_wots_public_key_hash(
    pk_seed: &[u8; HASH_LEN],
    endpoints: &[[u8; HASH_LEN]],
) -> [u8; HASH_LEN] {
    let mut packed = Vec::with_capacity(endpoints.len() * HASH_LEN);
    for endpoint in endpoints {
        packed.extend_from_slice(endpoint);
    }
    hash_node(&[b"wots-c-pk".as_ref(), pk_seed.as_ref(), packed.as_slice()])
}

pub(crate) fn hypertree_virtual_node_from<F>(
    pk_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    height: u32,
    index: u32,
    leaf_fn: &F,
) -> [u8; HASH_LEN]
where
    F: Fn(u32) -> [u8; HASH_LEN],
{
    if height == 0 {
        return leaf_fn(index);
    }
    let left = hypertree_virtual_node_from(pk_seed, layer, tree, height - 1, index << 1, leaf_fn);
    let right = hypertree_virtual_node_from(
        pk_seed,
        layer,
        tree,
        height - 1,
        (index << 1) | 1,
        leaf_fn,
    );
    let address_word = hypertree_address_word(layer, tree, height, u64::from(index));
    hash_node(&[
        b"hypertree-node".as_ref(),
        pk_seed.as_ref(),
        address_word.as_ref(),
        left.as_ref(),
        right.as_ref(),
    ])
}

pub(crate) fn hypertree_auth_path_from<F>(
    subtree_height: u32,
    leaf: u32,
    leaf_fn: &F,
) -> Vec<Vec<u8>>
where
    F: Fn(u32, u32) -> [u8; HASH_LEN],
{
    (0..subtree_height)
        .map(|level| {
            let sibling = (leaf >> level) ^ 1;
            leaf_fn(level, sibling).to_vec()
        })
        .collect()
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
    let digest = stateless_wots_message_digest(
        &pk_seed,
        &expected_pk_hash,
        &randomizer,
        signature.counter,
        &message,
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
        let digit = base_w_digit(WOTS_CHAIN_LEN, &digest, chain_index);
        let Some(next_sum) = digit_sum.checked_add(digit) else {
            return false;
        };
        digit_sum = next_sum;
        let segment =
            wots_chain32_no_mask_base(WOTS_CHAIN_LEN, pk_seed, address_base, chain_index as u32, chain_value, digit);
        pk_input_segments.extend_from_slice(&segment);
    }
    if digit_sum != WOTS_TARGET_SUM_STATELESS {
        return false;
    }

    let computed_pk_hash = hash_node(&[
        b"wots-c-pk".as_ref(),
        pk_seed.as_ref(),
        pk_input_segments.as_slice(),
    ]);
    computed_pk_hash == expected_pk_hash
}

fn wots_chain32_no_mask_base(
    w: u16,
    pk_seed: [u8; HASH_LEN],
    address_base: [u8; HASH_LEN],
    chain_index: u32,
    value: [u8; HASH_LEN],
    digit: u32,
) -> [u8; HASH_LEN] {
    let steps = u32::from(w - 1) - digit;
    stateless_wots_chain_from_address_base(
        &pk_seed,
        address_base,
        chain_index,
        value,
        digit,
        steps,
    )
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
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let address_word =
            hypertree_address_word(layer, tree_index, level + 1, u64::from(index >> 1));
        node = hash_node(&[
            b"hypertree-node".as_ref(),
            pk_seed.as_ref(),
            address_word.as_ref(),
            left.as_ref(),
            right.as_ref(),
        ]);
        index >>= 1;
    }
    Some(node)
}
