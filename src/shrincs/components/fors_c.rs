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

use zeroize::Zeroizing;

use super::hash::{fors_address_word, hash_node, hash_packed, pack, read_bits32, read_bits64, word32};
use super::super::profiles::{
    FORS_TREE_HEIGHT, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
};
use super::super::types::{ForsEntry, ForsSignature, HASH_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForsDigest {
    tree_index: u64,
    leaf_index: u32,
    digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningForsDigest {
    pub tree_index: u64,
    pub leaf_index: u32,
    pub signed_tree_indices: Vec<u32>,
    pub omitted_final_tree_is_zero: bool,
}

pub(crate) fn verify_fors_c_and_return_root(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    signature: &ForsSignature,
) -> Option<([u8; HASH_LEN], u64, u32)> {
    let signed_trees = NUM_FORS_TREES as usize - 1;
    if signature.randomizer.len() != HASH_LEN || signature.entries.len() != signed_trees {
        return None;
    }

    let digest = fors_digest(
        pk_seed,
        hypertree_root,
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
            pk_seed,
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
            pk_seed.as_ref(),
            roots.as_slice(),
        ]),
        digest.tree_index,
        digest.leaf_index,
    ))
}

pub(crate) fn signer_fors_digest(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
) -> Option<SigningForsDigest> {
    let signed_trees = NUM_FORS_TREES as usize - 1;
    let index_bits = u32::from(NUM_FORS_TREES) * u32::from(FORS_TREE_HEIGHT);
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    let tree_bits = u32::from(HYPERTREE_HEIGHT) - subtree_height;
    let digest_bytes = (index_bits + u32::from(HYPERTREE_HEIGHT)).div_ceil(8) as usize;
    let digest = fors_digest_bytes(
        pk_seed,
        hypertree_root,
        randomizer,
        counter,
        message,
        digest_bytes,
    );
    let signed_tree_indices = (0..signed_trees)
        .map(|tree| {
            read_bits32(
                &digest,
                tree as usize * FORS_TREE_HEIGHT as usize,
                FORS_TREE_HEIGHT as u32,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    let omitted_final_tree_is_zero = read_bits32(
        &digest,
        signed_trees * FORS_TREE_HEIGHT as usize,
        FORS_TREE_HEIGHT as u32,
    )? == 0;
    let cursor = index_bits as usize;
    Some(SigningForsDigest {
        tree_index: read_bits64(&digest, cursor, tree_bits)?,
        leaf_index: read_bits32(&digest, cursor + tree_bits as usize, subtree_height)?,
        signed_tree_indices,
        omitted_final_tree_is_zero,
    })
}

pub(crate) fn fors_leaf_secret(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> [u8; HASH_LEN] {
    let tree_leaf = (u64::from(fors_tree) << FORS_TREE_HEIGHT) + u64::from(leaf);
    let address_word = fors_address_word(tree_index, leaf_index, 0, tree_leaf);
    hash_packed(&[
        b"fors-sk".as_ref(),
        sk_seed.as_ref(),
        pk_seed.as_ref(),
        address_word.as_ref(),
    ])
}

pub(crate) fn fors_leaf_hash(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> [u8; HASH_LEN] {
    let secret = Zeroizing::new(fors_leaf_secret(
        pk_seed, sk_seed, tree_index, leaf_index, fors_tree, leaf,
    ));
    fors_leaf_hash_from_secret(pk_seed, tree_index, leaf_index, fors_tree, leaf, &secret)
}

fn fors_leaf_hash_from_secret(
    pk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
    secret: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let tree_leaf = (u64::from(fors_tree) << FORS_TREE_HEIGHT) + u64::from(leaf);
    let address_word = fors_address_word(tree_index, leaf_index, 0, tree_leaf);
    hash_node(&[
        b"fors-leaf".as_ref(),
        pk_seed.as_ref(),
        address_word.as_ref(),
        secret.as_ref(),
    ])
}

pub(crate) fn fors_tree_root_and_auth_path(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> ([u8; HASH_LEN], [u8; HASH_LEN], Vec<Vec<u8>>) {
    let height = u32::from(FORS_TREE_HEIGHT);
    let leaf_count = 1usize << height;
    let selected_secret_leaf =
        fors_leaf_secret(pk_seed, sk_seed, tree_index, leaf_index, fors_tree, leaf);
    let mut level_nodes = Vec::with_capacity(leaf_count);
    for index in 0..leaf_count {
        let index = index as u32;
        let leaf_hash = if index == leaf {
            fors_leaf_hash_from_secret(
                pk_seed,
                tree_index,
                leaf_index,
                fors_tree,
                leaf,
                &selected_secret_leaf,
            )
        } else {
            fors_leaf_hash(pk_seed, sk_seed, tree_index, leaf_index, fors_tree, index)
        };
        level_nodes.push(leaf_hash);
    }
    let mut index = leaf as usize;
    let mut auth_path = Vec::with_capacity(height as usize);

    for node_height in 1..=height {
        auth_path.push(level_nodes[index ^ 1].to_vec());
        let mut parents = Vec::with_capacity(level_nodes.len() / 2);
        for (parent_index, pair) in level_nodes.chunks_exact(2).enumerate() {
            let shifted_tree = u64::from(fors_tree) << (height - node_height);
            let parent_low_index = shifted_tree + parent_index as u64;
            let address_word =
                fors_address_word(tree_index, leaf_index, node_height, parent_low_index);
            parents.push(hash_node(&[
                b"fors-node".as_ref(),
                pk_seed.as_ref(),
                address_word.as_ref(),
                pair[0].as_ref(),
                pair[1].as_ref(),
            ]));
        }
        level_nodes = parents;
        index >>= 1;
    }

    (level_nodes[0], selected_secret_leaf, auth_path)
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
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    randomizer: &[u8],
    counter: u32,
) -> Option<ForsDigest> {
    let index_bits = u32::from(NUM_FORS_TREES) * u32::from(FORS_TREE_HEIGHT);
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    let tree_bits = u32::from(HYPERTREE_HEIGHT) - subtree_height;
    let digest_bytes = (index_bits + u32::from(HYPERTREE_HEIGHT)).div_ceil(8) as usize;
    let digest = fors_digest_bytes(
        pk_seed,
        hypertree_root,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_leaf_hash_reuse_matches_direct_leaf_hash() {
        let pk_seed = [0x11u8; HASH_LEN];
        let sk_seed = [0x22u8; HASH_LEN];
        let tree_index = 7u64;
        let leaf_index = 3u32;
        let fors_tree = 5u32;
        let leaf = 9u32;

        let secret =
            fors_leaf_secret(&pk_seed, &sk_seed, tree_index, leaf_index, fors_tree, leaf);
        let reused = fors_leaf_hash_from_secret(
            &pk_seed,
            tree_index,
            leaf_index,
            fors_tree,
            leaf,
            &secret,
        );
        let direct = fors_leaf_hash(&pk_seed, &sk_seed, tree_index, leaf_index, fors_tree, leaf);

        assert_eq!(reused, direct);
    }
}
