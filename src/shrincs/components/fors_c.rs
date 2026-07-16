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

//! FORS-C primitive verification logic.

use super::super::profiles::{
    FORS_TREE_HEIGHT, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
};
use super::super::shrincs_verifier_utils::{
    fors_address_word, hash_node, hash_packed, pack, read_bits32, read_bits64, word32,
};
use super::super::types::{ForsEntry, ForsSignature, PublicKey, HASH_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForsDigest {
    tree_index: u64,
    leaf_index: u32,
    digest: Vec<u8>,
}

pub(crate) fn verify_fors_c_and_return_root(
    public_key: &PublicKey,
    message: &[u8],
    signature: &ForsSignature,
) -> Option<([u8; HASH_LEN], u64, u32)> {
    let signed_trees = NUM_FORS_TREES as usize - 1;
    if signature.randomizer.len() != HASH_LEN || signature.entries.len() != signed_trees {
        return None;
    }

    let digest = fors_digest(
        public_key,
        message,
        &signature.randomizer,
        signature.counter,
    )?;
    let fors_tree_height = FORS_TREE_HEIGHT as usize;
    if read_bits32(
        &digest.digest,
        signed_trees * fors_tree_height,
        FORS_TREE_HEIGHT as u32,
    )? != 0
    {
        return None;
    }

    let mut roots = Vec::with_capacity(signed_trees * HASH_LEN);
    for fors_tree_index in 0..signed_trees {
        let entry = signature.entries.get(fors_tree_index)?;
        if entry.secret_leaf.len() != HASH_LEN || entry.auth_path.len() != fors_tree_height {
            return None;
        }
        let entry_leaf_index = read_bits32(
            &digest.digest,
            fors_tree_index * fors_tree_height,
            FORS_TREE_HEIGHT as u32,
        )?;
        let root = fors_entry_root32(
            fors_tree_height as u32,
            &public_key.pk_seed,
            digest.tree_index,
            digest.leaf_index,
            fors_tree_index as u32,
            entry_leaf_index,
            entry,
        )?;
        roots.extend_from_slice(&root);
    }

    Some((
        hash_node(&[
            b"fors-pk".as_ref(),
            public_key.pk_seed.as_slice(),
            roots.as_slice(),
        ]),
        digest.tree_index,
        digest.leaf_index,
    ))
}

fn fors_entry_root32(
    height: u32,
    pk_seed: &[u8],
    tree_index: u64,
    leaf_index: u32,
    fors_tree_index: u32,
    entry_leaf_index: u32,
    entry: &ForsEntry,
) -> Option<[u8; HASH_LEN]> {
    let shifted_fors_tree = u64::from(fors_tree_index) << height;
    let leaf_low_index = shifted_fors_tree + u64::from(entry_leaf_index);
    let mut node = hash_fors_leaf32(
        pk_seed,
        fors_address_word(tree_index, leaf_index, 0, leaf_low_index),
        &entry.secret_leaf,
    )?;
    let mut index = entry_leaf_index;
    for level in 0..height {
        let sibling = word32(entry.auth_path.get(level as usize)?)?;
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let node_height = level + 1;
        let shifted_tree = u64::from(fors_tree_index) << (height - node_height);
        let parent_index = u64::from(index >> 1);
        let parent_low_index = shifted_tree + parent_index;
        let address_word = fors_address_word(tree_index, leaf_index, node_height, parent_low_index);
        node = hash_fors_node32(pk_seed, address_word, left, right)?;
        index >>= 1;
    }
    Some(node)
}

fn hash_fors_leaf32(
    pk_seed: &[u8],
    address_word: [u8; HASH_LEN],
    sk: &[u8],
) -> Option<[u8; HASH_LEN]> {
    if pk_seed.len() != HASH_LEN || sk.len() != HASH_LEN {
        return None;
    }
    Some(hash_node(&[b"fors-leaf", pk_seed, &address_word, sk]))
}

fn hash_fors_node32(
    pk_seed: &[u8],
    address_word: [u8; HASH_LEN],
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> Option<[u8; HASH_LEN]> {
    if pk_seed.len() != HASH_LEN {
        return None;
    }
    Some(hash_node(&[b"fors-node", pk_seed, &address_word, &left, &right]))
}

fn fors_digest(
    public_key: &PublicKey,
    message: &[u8],
    randomizer: &[u8],
    counter: u32,
) -> Option<ForsDigest> {
    let index_bits = u32::from(NUM_FORS_TREES) * u32::from(FORS_TREE_HEIGHT);
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    let tree_bits = u32::from(HYPERTREE_HEIGHT) - subtree_height;
    let digest_bytes = (index_bits + u32::from(HYPERTREE_HEIGHT)).div_ceil(8) as usize;
    let digest = fors_digest_bytes(
        &public_key.pk_seed,
        &public_key.hypertree_root,
        randomizer,
        counter,
        message,
        digest_bytes,
    );

    let cursor = index_bits as usize;
    Some(ForsDigest {
        tree_index: read_bits64(&digest, cursor, tree_bits)?,
        leaf_index: read_bits32(&digest, cursor + tree_bits as usize, subtree_height)?,
        digest,
    })
}

fn fors_digest_bytes(
    pk_seed: &[u8],
    hypertree_root: &[u8],
    randomizer: &[u8],
    counter: u32,
    message: &[u8],
    digest_bytes: usize,
) -> Vec<u8> {
    let base = pack(&[
        b"fors-digest",
        pk_seed,
        hypertree_root,
        randomizer,
        &counter.to_be_bytes(),
        message,
    ]);
    if digest_bytes <= HASH_LEN {
        return hash_packed(&[&base])[..digest_bytes].to_vec();
    }

    let mut out = Vec::with_capacity(digest_bytes);
    let mut block_counter = 0u32;
    while out.len() < digest_bytes {
        let digest_word = hash_packed(&[&base, &block_counter.to_be_bytes()]);
        let remaining = digest_bytes - out.len();
        out.extend_from_slice(&digest_word[..remaining.min(HASH_LEN)]);
        block_counter = block_counter.wrapping_add(1);
    }
    out
}
