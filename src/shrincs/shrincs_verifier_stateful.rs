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

//! JARDIN compact-path FORS+C verification for the stateful fast path.

use super::shrincs_verifier_types::{
    ForsEntry, PublicKey, StatefulSignature, ADDRESS_TYPE_FORS_ROOTS, ADDRESS_TYPE_FORS_TREE,
    ADDRESS_TYPE_JARDIN_MERKLE, HASH_LEN, STATEFUL_FORS_K_OPEN, STATEFUL_FORS_K_TOTAL,
    STATEFUL_FORS_TREE_HEIGHT, STATEFUL_MERKLE_HEIGHT, STATEFUL_Q_MAX,
};
use super::shrincs_verifier_utils::{
    decode_stateful_public_key, hash_packed, matches_expected_public_key_commitment, pack,
    read_bits32, valid_public_key, word32,
};

// verify_stateful_unsafe_raw: Verify one JARDIN compact-path stateful signature.
// 1. Confirm the supplied public key matches the installed composite commitment.
// 2. Decode and bounds-check the compact stateful subkey.
// 3. Reconstruct the slot FORS+C public key from k_open entries.
// 4. Verify the balanced h=7 Merkle path reaches `subPkRoot`.
pub(crate) fn verify_stateful_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    let Some(stateful_key) = decode_stateful_public_key(&public_key.stateful_public_key) else {
        return false;
    };

    // `q` is the explicit compact-path slot, not derived from auth-path length.
    let q = u32::from(signature.q);
    if stateful_key.max_signatures == 0 || stateful_key.max_signatures > STATEFUL_Q_MAX {
        return false;
    }
    if q >= stateful_key.max_signatures {
        return false;
    }
    if signature.fors_entries.len() != usize::from(STATEFUL_FORS_K_OPEN) {
        return false;
    }
    if signature.auth_path.len() != usize::from(STATEFUL_MERKLE_HEIGHT) {
        return false;
    }

    let Some(fors_pk) = verify_compact_fors_c_and_return_pk(
        stateful_key.pk_seed,
        stateful_key.root,
        signature.q,
        message,
        signature,
    ) else {
        return false;
    };
    let Some(root) = root_from_jardin_merkle_path(
        stateful_key.pk_seed,
        signature.q,
        fors_pk,
        &signature.auth_path,
    ) else {
        return false;
    };
    stateful_key.root == root
}

// verify_compact_fors_c_and_return_pk: Recompute the slot FORS+C public key.
// 1. Derive the compact digest from `M*`, randomizer, and counter.
// 2. Require the omitted FORS tree's digest leaf to be 0.
// 3. Recompute each opened FORS tree root from the revealed entry.
// 4. Hash all opened roots with `JARDIN/T_k`.
fn verify_compact_fors_c_and_return_pk(
    sub_pk_seed: [u8; HASH_LEN],
    sub_pk_root: [u8; HASH_LEN],
    q: u8,
    message: &[u8],
    signature: &StatefulSignature,
) -> Option<[u8; HASH_LEN]> {
    // The digest is 260 bits for current params, so this returns a 33-byte buffer.
    let digest = compact_digest(
        &sub_pk_seed,
        &sub_pk_root,
        q,
        &signature.randomizer,
        signature.counter,
        message,
    );
    // The hidden tree is the final a-bit slice after the k_open explicit slices.
    if read_bits32(
        &digest,
        usize::from(STATEFUL_FORS_K_OPEN) * usize::from(STATEFUL_FORS_TREE_HEIGHT),
        u32::from(STATEFUL_FORS_TREE_HEIGHT),
    )? != 0
    {
        return None;
    }

    // Roots are concatenated in FORS tree order before the aggregate `T_k` hash.
    let mut roots = Vec::with_capacity(usize::from(STATEFUL_FORS_K_OPEN) * HASH_LEN);
    for fors_tree in 0..STATEFUL_FORS_K_OPEN {
        // Each signature entry corresponds to the same-index digest slice.
        let entry = &signature.fors_entries[usize::from(fors_tree)];
        // Decode the selected leaf for this opened FORS tree.
        let leaf = read_bits32(
            &digest,
            usize::from(fors_tree) * usize::from(STATEFUL_FORS_TREE_HEIGHT),
            u32::from(STATEFUL_FORS_TREE_HEIGHT),
        )?;
        // Reconstruct this FORS tree root from its revealed leaf and auth path.
        let root = compact_fors_entry_root(&sub_pk_seed, q, u32::from(fors_tree), leaf, entry)?;
        roots.extend_from_slice(&root);
    }
    Some(hash_packed(&[
        b"JARDIN/T_k",
        &sub_pk_seed,
        &jardin_address_word(ADDRESS_TYPE_FORS_ROOTS, q, 0, 0),
        &roots,
    ]))
}

// compact_fors_entry_root: Verify one opened FORS tree path.
// 1. Validate the secret leaf and a-level auth path lengths.
// 2. Hash the secret leaf into its addressed FORS leaf.
// 3. Climb the tree, ordering siblings by the current node index.
// 4. Return the reconstructed root.
fn compact_fors_entry_root(
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    fors_tree: u32,
    leaf: u32,
    entry: &ForsEntry,
) -> Option<[u8; HASH_LEN]> {
    if entry.secret_leaf.len() != HASH_LEN {
        return None;
    }
    if entry.auth_path.len() != usize::from(STATEFUL_FORS_TREE_HEIGHT) {
        return None;
    }
    let mut node = hash_packed(&[
        b"JARDIN/F",
        sub_pk_seed,
        &jardin_address_word(
            ADDRESS_TYPE_FORS_TREE,
            q,
            0,
            compact_fors_tree_low_leaf_index(fors_tree, leaf),
        ),
        &entry.secret_leaf,
    ]);
    // `index` tracks the current node's position at each level.
    let mut index = leaf;
    // `height` equals `a`, the FORS tree height.
    let height = u32::from(STATEFUL_FORS_TREE_HEIGHT);
    for level in 0..height {
        // Auth paths are bottom-up and each sibling must be exactly one hash word.
        let sibling = word32(entry.auth_path.get(level as usize)?)?;
        // Even index: current node is left. Odd index: current node is right.
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        // Parent addresses use one-based FORS node height.
        let node_height = level + 1;
        // Low index combines the FORS tree and the parent position inside that tree.
        let shifted_tree = u64::from(fors_tree) << (height - node_height);
        let parent_low_index = shifted_tree + u64::from(index >> 1);
        // Hash the parent at the exact JARDIN FORS tree address.
        node = hash_packed(&[
            b"JARDIN/H",
            sub_pk_seed,
            &jardin_address_word(ADDRESS_TYPE_FORS_TREE, q, node_height, parent_low_index),
            &left,
            &right,
        ]);
        // Move from child index to parent index.
        index >>= 1;
    }
    Some(node)
}

// root_from_jardin_merkle_path: Reconstruct `subPkRoot` from one slot leaf.
// 1. Start at the slot's FORS+C public key.
// 2. Use q bits to order each bottom-up sibling.
// 3. Hash parents with JARDIN balanced-tree addresses.
// 4. Return the candidate compact-path root.
fn root_from_jardin_merkle_path(
    sub_pk_seed: [u8; HASH_LEN],
    q: u8,
    leaf: [u8; HASH_LEN],
    auth_path: &[[u8; HASH_LEN]],
) -> Option<[u8; HASH_LEN]> {
    if auth_path.len() != usize::from(STATEFUL_MERKLE_HEIGHT) {
        return None;
    }
    // The starting leaf is the FORS+C public key for slot q.
    let mut node = leaf;
    // Keep q widened for bit extraction.
    let q_u32 = u32::from(q);
    for j in 0..u32::from(STATEFUL_MERKLE_HEIGHT) {
        // Auth path is bottom-up: sibling 0 is at the leaf level.
        let sibling = auth_path[j as usize];
        // Address levels count down from h-1 to 0 as we climb.
        let level = u32::from(STATEFUL_MERKLE_HEIGHT) - 1 - j;
        // Parent index is q shifted past the child bits already consumed.
        let parent_index = q_u32 >> (j + 1);
        // The current q bit determines whether `node` is the left or right child.
        let (left, right) = if (q_u32 >> j) & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        // Hash the ordered pair at this balanced-tree address.
        node = hash_packed(&[
            b"JARDIN/H",
            &sub_pk_seed,
            &jardin_merkle_address_word(level, parent_index),
            &left,
            &right,
        ]);
    }
    Some(node)
}

// compact_digest: Rebuild the FORS+C digest consumed by signer and verifier.
// 1. Compute k_total*a digest bits.
// 2. Bind the message to `subPkSeed`, `subPkRoot`, and q through `M*`.
// 3. Build `H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)`.
// 4. Expand Keccak output to the required byte length.
fn compact_digest(
    sub_pk_seed: &[u8; HASH_LEN],
    sub_pk_root: &[u8; HASH_LEN],
    q: u8,
    randomizer: &[u8; HASH_LEN],
    counter: u32,
    message: &[u8],
) -> Vec<u8> {
    let digest_bits = usize::from(STATEFUL_FORS_K_TOTAL) * usize::from(STATEFUL_FORS_TREE_HEIGHT);
    // Round 260 bits up to 33 bytes for the current parameter set.
    let digest_bytes = (digest_bits + 7) / 8;
    // `M*` is the JARDIN TYPE2 message body.
    let m_star = compact_m_star(sub_pk_seed, sub_pk_root, q, message);
    // This is the JARDIN H_msg input: R || subPkSeed || subPkRoot || counter || M*.
    let base = pack(&[
        b"JARDIN/H_msg/v1",
        randomizer,
        sub_pk_seed,
        sub_pk_root,
        &counter.to_be_bytes(),
        &m_star,
    ]);
    expand_digest(&base, digest_bytes)
}

// compact_m_star: Build `M* = tag || subPkSeed || subPkRoot || q || message`.
fn compact_m_star(
    sub_pk_seed: &[u8; HASH_LEN],
    sub_pk_root: &[u8; HASH_LEN],
    q: u8,
    message: &[u8],
) -> Vec<u8> {
    let q_bytes = [q];
    let mut out = Vec::with_capacity(16 + HASH_LEN + HASH_LEN + 1 + message.len());
    // Domain tag separates compact-path message hashing from every other hash use.
    out.extend_from_slice(b"JARDIN/TYPE2/v1");
    out.extend_from_slice(sub_pk_seed);
    out.extend_from_slice(sub_pk_root);
    out.extend_from_slice(&q_bytes);
    out.extend_from_slice(message);
    out
}

// expand_digest: Produce an arbitrary byte-length digest from Keccak words.
// 1. Use a single word when enough.
// 2. Otherwise append counter-suffixed words.
// 3. Truncate the final word to the requested length.
fn expand_digest(base: &[u8], digest_bytes: usize) -> Vec<u8> {
    if digest_bytes <= HASH_LEN {
        return hash_packed(&[base])[..digest_bytes].to_vec();
    }
    let mut out = Vec::with_capacity(digest_bytes);
    let mut block_counter = 0u32;
    while out.len() < digest_bytes {
        // Counter-suffixed blocks match the signer and Solidity expansion.
        let digest_word = hash_packed(&[base, &block_counter.to_be_bytes()]);
        // Copy a full hash unless this is the final partial block.
        let remaining = digest_bytes - out.len();
        out.extend_from_slice(&digest_word[..remaining.min(HASH_LEN)]);
        block_counter = block_counter.wrapping_add(1);
    }
    out
}

// compact_fors_tree_low_leaf_index: Pack `(forsTree, leaf)` into the flattened JARDIN low-leaf-index field.
fn compact_fors_tree_low_leaf_index(fors_tree: u32, leaf: u32) -> u64 {
    (u64::from(fors_tree) << u32::from(STATEFUL_FORS_TREE_HEIGHT)) | u64::from(leaf)
}

// jardin_address_word: Pack the 32-byte JARDIN ADRS word for FORS+C nodes.
fn jardin_address_word(address_type: u32, q: u8, x: u32, y: u64) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    // Bytes 12..16 carry the address type.
    out[12..16].copy_from_slice(&address_type.to_be_bytes());
    // The Compact Path note uses one-indexed `ci`, so verifier maps q to q+1.
    out[20..24].copy_from_slice(&(u32::from(q) + 1).to_be_bytes());
    // Bytes 24..28 carry x, usually node height.
    out[24..28].copy_from_slice(&x.to_be_bytes());
    // Bytes 28..32 carry y, usually the low node/leaf index.
    out[28..32].copy_from_slice(&(y as u32).to_be_bytes());
    out
}

// jardin_merkle_address_word: Pack the 32-byte ADRS for the balanced q tree.
fn jardin_merkle_address_word(level: u32, node_index: u32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    // Keep Merkle hashing in its own address domain.
    out[12..16].copy_from_slice(&ADDRESS_TYPE_JARDIN_MERKLE.to_be_bytes());
    // Bytes 24..28 carry the balanced tree level.
    out[24..28].copy_from_slice(&level.to_be_bytes());
    // Bytes 28..32 carry the parent node index.
    out[28..32].copy_from_slice(&node_index.to_be_bytes());
    out
}
