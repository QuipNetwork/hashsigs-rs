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

use zeroize::Zeroizing;

use super::shrincs_signer_types::{ShrincsSignerResult, ShrincsSigningKey};
use super::shrincs_signer_utils::{
    fors_address_word, hash_node, hash_packed, pack, read_bits32, read_bits64,
    FORS_C_MAX_GRIND_COUNTER,
};
use super::verifier::{
    ForsEntry, ForsSignature, FORS_TREE_HEIGHT, HASH_LEN, HYPERTREE_HEIGHT, NUM_FORS_TREES,
    NUM_HYPERTREE_LAYERS,
};

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
        let Some(digest) = fors_digest(
            &signing_key.pk_seed,
            &signing_key.hypertree_root,
            message,
            &randomizer,
            counter,
        ) else {
            continue;
        };
        if digest.indices.last() != Some(&0) {
            continue;
        }

        let mut roots = Vec::with_capacity(signed_trees * HASH_LEN);
        let mut entries = Vec::with_capacity(signed_trees);
        for fors_tree in 0..signed_trees {
            // For each selected tree, reveal exactly the chosen secret leaf and
            // provide the siblings needed to recompute that tree's root.
            let leaf = digest.indices[fors_tree];
            let (root, auth_path) = fors_tree_root_and_auth_path(
                &signing_key.pk_seed,
                &signing_key.stateless_sk_seed,
                digest.tree_index,
                digest.leaf_index,
                fors_tree as u32,
                leaf,
            );
            roots.extend_from_slice(&root);
            entries.push(ForsEntry {
                secret_leaf: fors_leaf_secret(
                    &signing_key.pk_seed,
                    &signing_key.stateless_sk_seed,
                    digest.tree_index,
                    digest.leaf_index,
                    fors_tree as u32,
                    leaf,
                )
                .to_vec(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForsDigest {
    /// Hypertree tree at layer 0. Upper-layer coordinates are derived from this.
    tree_index: u64,
    /// Hypertree leaf inside the selected layer-0 subtree.
    leaf_index: u32,
    /// One selected FORS leaf per FORS tree, including the omitted final tree.
    indices: Vec<u32>,
}

fn fors_digest(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
) -> Option<ForsDigest> {
    // The digest has three jobs:
    // 1. choose one FORS leaf in each tree,
    // 2. choose the layer-0 hypertree tree index,
    // 3. choose the layer-0 hypertree leaf index.
    //
    // These fields are read from one bit string. Changing the order or bit order
    // here would make signatures verify against a different set of openings.
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
    let indices = (0..NUM_FORS_TREES)
        .map(|tree| {
            read_bits32(
                &digest,
                tree as usize * FORS_TREE_HEIGHT as usize,
                FORS_TREE_HEIGHT as u32,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    let cursor = index_bits as usize;
    Some(ForsDigest {
        tree_index: read_bits64(&digest, cursor, tree_bits)?,
        leaf_index: read_bits32(&digest, cursor + tree_bits as usize, subtree_height)?,
        indices,
    })
}

fn fors_digest_bytes(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
    message: &[u8],
    digest_bytes: usize,
) -> Vec<u8> {
    // Bind the digest to the FORS public seed, the current hypertree root, the
    // randomizer, the grind counter, and the message. The hypertree root prevents
    // the same FORS opening from authorizing a different stateless root above it.
    let base = pack(&[
        b"fors-digest",
        pk_seed,
        hypertree_root,
        randomizer,
        &counter.to_be_bytes(),
        message,
    ]);
    if digest_bytes <= HASH_LEN {
        // The current digest fits in one word, but the expansion below keeps the
        // helper honest if the fixed constants are widened later.
        return hash_packed(&[&base])[..digest_bytes].to_vec();
    }

    let mut out = Vec::with_capacity(digest_bytes);
    let mut block_counter = 0u32;
    while out.len() < digest_bytes {
        // XOF-like expansion from Keccak-256: each block hashes the same base
        // plus a block counter, then the final block is truncated as needed.
        let digest_word = hash_packed(&[&base, &block_counter.to_be_bytes()]);
        let remaining = digest_bytes - out.len();
        out.extend_from_slice(&digest_word[..remaining.min(HASH_LEN)]);
        block_counter = block_counter.wrapping_add(1);
    }
    out
}

fn fors_tree_root_and_auth_path(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> ([u8; HASH_LEN], Vec<Vec<u8>>) {
    // Build one FORS tree bottom-up once, collecting the selected leaf's sibling
    // at each level. The root contributes to the aggregate FORS public root, and
    // the auth path is carried in the signature.
    let height = u32::from(FORS_TREE_HEIGHT);
    let leaf_count = 1usize << height;
    let mut level_nodes = (0..leaf_count)
        .map(|index| {
            fors_leaf_hash(
                pk_seed,
                sk_seed,
                tree_index,
                leaf_index,
                fors_tree,
                index as u32,
            )
        })
        .collect::<Vec<_>>();
    let mut index = leaf as usize;
    let mut auth_path = Vec::with_capacity(height as usize);

    for node_height in 1..=height {
        // `index ^ 1` is the sibling at this level. After saving it, shift the
        // selected index right so the next loop follows its parent.
        auth_path.push(level_nodes[index ^ 1].to_vec());
        let mut parents = Vec::with_capacity(level_nodes.len() / 2);
        for (parent_index, pair) in level_nodes.chunks_exact(2).enumerate() {
            // Parent addresses include the FORS tree number and the parent index
            // within that level, so identical child pairs in different trees hash
            // to different parents.
            let shifted_tree = u64::from(fors_tree) << (height - node_height);
            let parent_low_index = shifted_tree + parent_index as u64;
            let address_word =
                fors_address_word(tree_index, leaf_index, node_height, parent_low_index);
            parents.push(hash_node(&[
                b"fors-node",
                pk_seed,
                &address_word,
                &pair[0],
                &pair[1],
            ]));
        }
        level_nodes = parents;
        index >>= 1;
    }

    (level_nodes[0], auth_path)
}

fn fors_leaf_secret(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> [u8; HASH_LEN] {
    // A FORS secret leaf is derived, not stored. The address includes both the
    // FORS tree number and the selected leaf inside that tree.
    let tree_leaf = (u64::from(fors_tree) << FORS_TREE_HEIGHT) + u64::from(leaf);
    let address_word = fors_address_word(tree_index, leaf_index, 0, tree_leaf);
    hash_packed(&[b"fors-sk", sk_seed, pk_seed, &address_word])
}

fn fors_leaf_hash(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    tree_index: u64,
    leaf_index: u32,
    fors_tree: u32,
    leaf: u32,
) -> [u8; HASH_LEN] {
    // The leaf hash commits to the secret leaf under the public seed and address.
    // The verifier recomputes this from the revealed secret leaf before walking
    // the authentication path to the tree root. This internal secret (for the
    // non-revealed leaves that build the tree) is zeroized on drop.
    let secret = Zeroizing::new(fors_leaf_secret(
        pk_seed, sk_seed, tree_index, leaf_index, fors_tree, leaf,
    ));
    let tree_leaf = (u64::from(fors_tree) << FORS_TREE_HEIGHT) + u64::from(leaf);
    let address_word = fors_address_word(tree_index, leaf_index, 0, tree_leaf);
    hash_node(&[b"fors-leaf", pk_seed, &address_word, &*secret])
}
