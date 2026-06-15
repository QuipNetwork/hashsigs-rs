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

//! FORS-C verification.
//!
//! Derive the FORS digest, verify every revealed FORS tree entry, and compress
//! those roots into the per-signature FORS output carried into hypertree
//! verification.

use super::shrincs_types::{ForsEntry, ForsSignature, ParamsView, PublicKey, HASH_LEN};
use super::shrincs_utils::{
    fors_address_word, hash_packed, pack, read_bits32, read_bits64, word32,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForsDigest {
    tree_index: u64,
    leaf_index: u32,
    digest: Vec<u8>,
}

pub(crate) fn verify_fors_c_and_return_root(
    params: &ParamsView,
    public_key: &PublicKey,
    message: &[u8],
    signature: &ForsSignature,
    tree_index: u64,
    leaf_index: u32,
) -> Option<[u8; HASH_LEN]> {
    // FORS-C omits the final FORS tree by forcing its digest-selected leaf index to zero.
    // Verification therefore expects only k - 1 revealed entries and rejects any digest
    // whose omitted final tree would require a nonzero leaf.
    let signed_trees = params.num_fors_trees as usize - 1;
    if signature.randomizer.len() != HASH_LEN || signature.entries.len() != signed_trees {
        return None;
    }

    // The digest simultaneously selects:
    // - one leaf in each FORS tree,
    // - the layer-0 hypertree tree index,
    // - the layer-0 hypertree leaf index.
    // The first hypertree layer must echo those two coordinates.
    let digest = fors_digest(
        params,
        public_key,
        message,
        &signature.randomizer,
        signature.counter,
    );
    let fors_tree_height = params.fors_tree_height as usize;
    if read_bits32(
        &digest.digest,
        signed_trees * fors_tree_height,
        params.fors_tree_height as u32,
    )? != 0
    {
        return None;
    }
    if digest.tree_index != tree_index || digest.leaf_index != leaf_index {
        return None;
    }

    let mut roots = Vec::with_capacity(signed_trees * HASH_LEN);
    for fors_tree_index in 0..signed_trees {
        let entry = &signature.entries[fors_tree_index];
        if entry.secret_leaf.len() != HASH_LEN || entry.auth_path.len() != fors_tree_height {
            return None;
        }
        // Each FORS tree consumes `fors_tree_height` bits from the digest. Those
        // bits choose the secret leaf that should be revealed for this tree.
        let entry_leaf_index = read_bits32(
            &digest.digest,
            fors_tree_index * fors_tree_height,
            params.fors_tree_height as u32,
        )?;
        let root = fors_entry_root32(
            fors_tree_height as u32,
            &public_key.pk_seed,
            tree_index,
            leaf_index,
            fors_tree_index as u32,
            entry_leaf_index,
            entry,
        )?;
        roots.extend_from_slice(&root);
    }

    // The FORS output is the hash of all verified FORS roots under the domain
    // tag `fors-pk`. In the SPHINCS-style composition, this is a per-signature
    // value consumed by the hypertree rather than a field of the long-lived
    // public key.
    Some(hash_packed(&[b"fors-pk", &public_key.pk_seed, &roots]))
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
    // Start from the revealed secret leaf, domain-separate it as a FORS leaf,
    // then climb the authentication path to this FORS tree's root.
    let mut node = hash_fors_leaf32(
        pk_seed,
        fors_address_word(
            tree_index,
            leaf_index,
            0,
            (u64::from(fors_tree_index) << height) + u64::from(entry_leaf_index),
        ),
        &entry.secret_leaf,
    )?;
    let mut index = entry_leaf_index;
    for level in 0..height {
        let sibling = word32(entry.auth_path.get(level as usize)?)?;
        // Standard Merkle sibling ordering: even index means current node is
        // left, odd index means current node is right.
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let node_height = level + 1;
        // Base offset at the current height
        let shifted_tree = u64::from(fors_tree_index) << (height - node_height);
        let parent_index = u64::from(index >> 1);
        // The address binds this parent to the FORS tree number, node height,
        // and parent index inside the tree.
        let address_word = fors_address_word(
            tree_index,
            leaf_index,
            node_height,
            shifted_tree + parent_index,
        );
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
    Some(hash_packed(&[b"fors-leaf", pk_seed, &address_word, sk]))
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
    Some(hash_packed(&[
        b"fors-node",
        pk_seed,
        &address_word,
        &left,
        &right,
    ]))
}

fn fors_digest(
    params: &ParamsView,
    public_key: &PublicKey,
    message: &[u8],
    randomizer: &[u8],
    counter: u32,
) -> ForsDigest {
    // Digest bit layout:
    // [FORS indices: k * a bits][hypertree tree index][hypertree leaf index].
    // `digest_bytes` rounds that bit count up to a whole byte count.
    let index_bits = u32::from(params.num_fors_trees) * u32::from(params.fors_tree_height);
    let subtree_height = u32::from(params.hypertree_height / params.num_hypertree_layers);
    let tree_bits = u32::from(params.hypertree_height) - subtree_height;
    let digest_bytes = ((index_bits + u32::from(params.hypertree_height) + 7) / 8) as usize;
    let digest = fors_digest_bytes(
        &public_key.pk_seed,
        &public_key.hypertree_root,
        randomizer,
        counter,
        message,
        digest_bytes,
    );

    let cursor = index_bits as usize;
    let tree_index = read_bits64(&digest, cursor, tree_bits).unwrap_or(0);
    let leaf_index = read_bits32(&digest, cursor + tree_bits as usize, subtree_height).unwrap_or(0);
    ForsDigest {
        tree_index,
        leaf_index,
        digest,
    }
}

fn fors_digest_bytes(
    pk_seed: &[u8],
    hypertree_root: &[u8],
    randomizer: &[u8],
    counter: u32,
    message: &[u8],
    digest_bytes: usize,
) -> Vec<u8> {
    // Solidity has two modes here:
    // - one Keccak block if the requested digest fits in 32 bytes,
    // - counter-suffixed blocks when more bytes are needed.
    // The current supported profile uses the multi-block path.
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
