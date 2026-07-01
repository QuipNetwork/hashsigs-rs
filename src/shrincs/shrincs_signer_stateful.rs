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

//! JARDIN compact-path FORS+C signing for the stateful fast path.

use super::shrincs_signer_types::{ShrincsSignerResult, ShrincsSigningKey};
use super::shrincs_signer_utils::{hash_packed, read_bits32, FORS_C_MAX_GRIND_COUNTER};
use super::verifier::{
    ForsEntry, StatefulSignature, ADDRESS_TYPE_FORS_PRF, ADDRESS_TYPE_FORS_ROOTS,
    ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_JARDIN_MERKLE, HASH_LEN, STATEFUL_FORS_K_OPEN,
    STATEFUL_FORS_K_TOTAL, STATEFUL_FORS_TREE_HEIGHT, STATEFUL_MERKLE_HEIGHT, STATEFUL_Q_MAX,
};

const DETERMINISTIC_OPT_RAND: [u8; HASH_LEN] = [0u8; HASH_LEN];

// sign_stateful_raw: Sign with the next compact-path slot.
// 1. Read the next zero-indexed slot q from the signing key.
// 2. Reject exhausted keys and slots beyond Q_MAX.
// 3. Build the FORS+C opening plus balanced Merkle auth path for q.
// 4. Advance the local stateful slot counter after successful signing.
pub(crate) fn sign_stateful_raw(
    signing_key: &mut ShrincsSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    let q = signing_key.next_stateful_leaf_index;
    if q >= signing_key.max_stateful_signatures || q >= STATEFUL_Q_MAX {
        return None;
    }

    let signature = sign_stateful_raw_at_leaf(signing_key, q, message)?;
    signing_key.next_stateful_leaf_index = q.saturating_add(1);
    Some(signature)
}

// sign_stateful_raw_at_leaf: Deterministically sign with a caller-supplied compact slot.
// 1. Enforce the key usage budget and global Q_MAX bound.
// 2. Convert q to the one-byte signature field used by JARDIN compact path.
// 3. Grind a FORS+C digest whose omitted tree opens at leaf 0.
// 4. Attach the balanced h=7 Merkle path proving this slot under subPkRoot.
pub(crate) fn sign_stateful_raw_at_leaf(
    signing_key: &ShrincsSigningKey,
    q: u32,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    if q >= signing_key.max_stateful_signatures || q >= STATEFUL_Q_MAX {
        return None;
    }
    // Solidity carries q as uint8, so Rust rejects any non-encodable slot before signing.
    let q_byte = u8::try_from(q).ok()?;
    // The FORS+C signer returns the randomizer, grind counter, and k_open entries.
    let (randomizer, counter, fors_entries) = sign_compact_fors_c(
        &signing_key.stateful_sk_seed,
        &signing_key.stateful_prf_seed,
        &signing_key.stateful_pk_seed,
        &signing_key.stateful_root,
        q_byte,
        message,
    )?;
    Some(StatefulSignature {
        q: q_byte,
        randomizer,
        counter,
        fors_entries,
        auth_path: stateful_auth_path(
            &signing_key.stateful_sk_seed,
            &signing_key.stateful_pk_seed,
            q_byte,
        ),
    })
}

// stateful_subtree_root: Commit all Q_MAX compact FORS+C slot public keys.
// 1. Instantiate the FORS+C public key for every q in 0..Q_MAX.
// 2. Pairwise hash the leaves through the balanced h=7 JARDIN Merkle tree.
// 3. Return the root stored as `subPkRoot` in the stateful public key.
pub(crate) fn stateful_subtree_root(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    _leaf_index: u32,
    _max_signatures: u32,
) -> [u8; HASH_LEN] {
    // Each leaf is a full FORS+C public key for one compact-path slot.
    let mut level_nodes = (0..STATEFUL_Q_MAX)
        .map(|q| compact_fors_c_public_key(sk_seed, sub_pk_seed, q as u8))
        .collect::<Vec<_>>();

    // level 0 is the root, and level h-1 is the leaves. We are doing bottom up hashing 
    for level in (0..STATEFUL_MERKLE_HEIGHT).rev() {
        let mut parents = Vec::with_capacity(level_nodes.len() / 2);
        for (parent_index, pair) in level_nodes.chunks_exact(2).enumerate() {
            parents.push(jardin_merkle_parent_hash(
                sub_pk_seed,
                u32::from(level),
                parent_index as u32,
                pair[0],
                pair[1],
            ));
        }
        level_nodes = parents;
    }
    level_nodes[0]
}

// sign_compact_fors_c: Produce the opened FORS+C body for one compact slot.
// 1. Grind randomizer/counter pairs until the omitted FORS tree selects leaf 0.
// 2. Read each opened tree's leaf index from the digest.
// 3. Reveal that leaf secret and its auth path.
// 4. Return exactly k_open entries plus the randomizer/counter needed to recompute the digest.
fn sign_compact_fors_c(
    sk_seed: &[u8; HASH_LEN],
    sk_prf: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    sub_pk_root: &[u8; HASH_LEN],
    q: u8,
    message: &[u8],
) -> ShrincsSignerResult<([u8; HASH_LEN], u32, Vec<ForsEntry>)> {
    for counter in 0..FORS_C_MAX_GRIND_COUNTER {
        // Build M* exactly as in the JARDIN TYPE2 compact digest.
        // M* = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
        let m_star = compact_m_star(sub_pk_seed, sub_pk_root, q, message);
        // R = PRF_msg(slot_sk_prf, opt_rand, uint32_be(counter) || M*).
        let randomizer = compact_randomizer(sk_prf, &DETERMINISTIC_OPT_RAND, counter, &m_star);
        // The digest encodes k_total leaf indices of a bits each.
        // digest = H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)
        let digest = compact_digest(sub_pk_seed, sub_pk_root, q, &randomizer, counter, message);
        // The hidden tree is the final digest slice; compact path requires it to be zero.
        if read_bits32(
            &digest,
            usize::from(STATEFUL_FORS_K_OPEN) * usize::from(STATEFUL_FORS_TREE_HEIGHT),
            u32::from(STATEFUL_FORS_TREE_HEIGHT),
        )? != 0
        {
            continue;
        }

        // Only k_open trees are revealed; the verifier infers the omitted tree as leaf 0.
        let mut entries = Vec::with_capacity(usize::from(STATEFUL_FORS_K_OPEN));
        for fors_tree in 0..STATEFUL_FORS_K_OPEN {
            // Select the leaf opened for this FORS tree.
            let leaf = read_bits32(
                &digest,
                usize::from(fors_tree) * usize::from(STATEFUL_FORS_TREE_HEIGHT),
                u32::from(STATEFUL_FORS_TREE_HEIGHT),
            )?;
            // Compute the auth path while also confirming the tree root locally.
            let (_root, auth_path) = compact_fors_tree_root_and_auth_path(
                sk_seed,
                sub_pk_seed,
                q,
                u32::from(fors_tree),
                leaf,
            );
            entries.push(ForsEntry {
                // The secret leaf is revealed as bytes so Solidity can hash it with `JARDIN/F`.
                secret_leaf: compact_fors_leaf_secret(
                    sk_seed,
                    sub_pk_seed,
                    q,
                    compact_fors_tree_low_leaf_index(u32::from(fors_tree), leaf),
                )
                .to_vec(),
                auth_path,
            });
        }
        return Some((randomizer, counter, entries));
    }
    None
}

// compact_fors_c_public_key: Build the slot commitment stored as a Merkle leaf.
// 1. Compute all k_open FORS tree roots for this q.
// 2. Concatenate them in tree order.
// 3. Hash with `JARDIN/T_k` and the FORS-roots address.
fn compact_fors_c_public_key(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
) -> [u8; HASH_LEN] {
    let mut roots = Vec::with_capacity(usize::from(STATEFUL_FORS_K_OPEN) * HASH_LEN);
    for fors_tree in 0..STATEFUL_FORS_K_OPEN {
        // Slot public keys commit to the root of each opened FORS tree.
        let root = compact_fors_tree_root(sk_seed, sub_pk_seed, q, u32::from(fors_tree));
        roots.extend_from_slice(&root);
    }
    compact_fors_roots_hash(sub_pk_seed, q, &roots)
}

fn compact_fors_tree_root(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    fors_tree: u32,
) -> [u8; HASH_LEN] {
    compact_fors_tree_root_and_auth_path(sk_seed, sub_pk_seed, q, fors_tree, 0).0
}

// compact_fors_tree_root_and_auth_path: Build one small FORS tree and auth path.
// 1. Materialize all 2^a leaves for the selected FORS tree.
// 2. Save the sibling at each level for the selected leaf.
// 3. Hash pairs upward with JARDIN FORS tree addresses.
// 4. Return the tree root and bottom-up auth path.
fn compact_fors_tree_root_and_auth_path(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    fors_tree: u32,
    leaf: u32,
) -> ([u8; HASH_LEN], Vec<Vec<u8>>) {
    let height = u32::from(STATEFUL_FORS_TREE_HEIGHT);
    let leaf_count = 1usize << height;
    let mut level_nodes = (0..leaf_count)
        .map(|index| {
            // Low leaf indices combine the FORS tree number and the within-tree leaf index.
            let low_index = compact_fors_tree_low_leaf_index(fors_tree, index as u32);
            compact_fors_leaf_hash(sk_seed, sub_pk_seed, q, low_index)
        })
        .collect::<Vec<_>>();
    // Track the selected node as the tree is reduced level by level.
    let mut index = leaf as usize;
    let mut auth_path = Vec::with_capacity(height as usize);

    for node_height in 1..=height {
        // The sibling at this level is the auth path element the verifier needs.
        auth_path.push(level_nodes[index ^ 1].to_vec());
        let mut parents = Vec::with_capacity(level_nodes.len() / 2);
        for (parent_index, pair) in level_nodes.chunks_exact(2).enumerate() {
            // JARDIN's low-index field identifies this parent inside the flattened FORS forest.
            let shifted_tree = u64::from(fors_tree) << (height - node_height);
            let parent_low_index = shifted_tree + parent_index as u64;
            parents.push(compact_fors_node_hash(
                sub_pk_seed,
                q,
                node_height,
                parent_low_index,
                pair[0],
                pair[1],
            ));
        }
        level_nodes = parents;
        // Move the selected node index to its parent.
        index >>= 1;
    }
    (level_nodes[0], auth_path)
}

// stateful_auth_path: Prove one compact slot under the balanced Q_MAX Merkle root.
// 1. Recompute every slot's FORS+C public key.
// 2. Save the sibling for q at each level.
// 3. Hash upward using JARDIN Merkle addresses.
// 4. Return the bottom-up h=7 auth path.
fn stateful_auth_path(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
) -> Vec<[u8; HASH_LEN]> {
    let mut level_nodes = (0..STATEFUL_Q_MAX)
        .map(|slot| compact_fors_c_public_key(sk_seed, sub_pk_seed, slot as u8))
        .collect::<Vec<_>>();
    // `index` follows q as each tree level is compressed.
    let mut index = usize::from(q);
    let mut auth_path = Vec::with_capacity(usize::from(STATEFUL_MERKLE_HEIGHT));

    // 0 is the root and STATEFUL_MERKLE_HEIGHT-1 is the leaves. We are doing bottom up hashing
    for level in (0..STATEFUL_MERKLE_HEIGHT).rev() {
        // Store the sibling before reducing this level.
        auth_path.push(level_nodes[index ^ 1]);
        let mut parents = Vec::with_capacity(level_nodes.len() / 2);
        for (parent_index, pair) in level_nodes.chunks_exact(2).enumerate() {
            parents.push(jardin_merkle_parent_hash(
                sub_pk_seed,
                u32::from(level),
                parent_index as u32,
                pair[0],
                pair[1],
            ));
        }
        level_nodes = parents;
        index >>= 1;
    }
    auth_path
}

// compact_randomizer: Build the per-signature randomizer R for one compact slot.
// R = PRF_msg(slot_sk_prf, opt_rand, uint32_be(counter) || M*)

fn compact_randomizer(
    sk_prf: &[u8; HASH_LEN],
    opt_rand: &[u8; HASH_LEN],
    counter: u32,
    m_star: &[u8],
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"JARDIN/PRF_msg/v1",
        sk_prf,
        opt_rand,
        &counter.to_be_bytes(),
        m_star,
    ])
}

// compact_digest: Build the exact H_msg digest that selects FORS leaves.
// 1. Compute k_total*a bits and round to bytes.
// 2. Build the JARDIN TYPE2 `M*` body.
// 3. Build `H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)`.
// 4. Expand Keccak words to the required byte length.
fn compact_digest(
    sub_pk_seed: &[u8; HASH_LEN],
    sub_pk_root: &[u8; HASH_LEN],
    q: u8,
    randomizer: &[u8; HASH_LEN],
    counter: u32,
    message: &[u8],
) -> Vec<u8> {
    let digest_bits = usize::from(STATEFUL_FORS_K_TOTAL) * usize::from(STATEFUL_FORS_TREE_HEIGHT);
    // Current parameters need 260 bits, i.e. 33 bytes.
    let digest_bytes = (digest_bits + 7) / 8;
    // `M*` binds the slot q to the stateful subkey and user message.
    // M*     = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
    let m_star = compact_m_star(sub_pk_seed, sub_pk_root, q, message);
    // This is the JARDIN digest = H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)
    let base = super::shrincs_signer_utils::pack(&[
        b"JARDIN/H_msg/v1",
        randomizer,
        sub_pk_seed,
        sub_pk_root,
        &counter.to_be_bytes(),
        &m_star,
    ]);
    expand_digest(&base, digest_bytes)
}

// compact_m_star: Build `M* = domain || subPkSeed || subPkRoot || q || message`.
fn compact_m_star(
    sub_pk_seed: &[u8; HASH_LEN],
    sub_pk_root: &[u8; HASH_LEN],
    q: u8,
    message: &[u8],
) -> Vec<u8> {
    let q_bytes = [q];
    let mut out = Vec::with_capacity(16 + HASH_LEN + HASH_LEN + 1 + message.len());
    // The TYPE2 domain follows the Compact Path note and prevents cross-mode reuse.
    out.extend_from_slice(b"JARDIN/TYPE2/v1");
    out.extend_from_slice(sub_pk_seed);
    out.extend_from_slice(sub_pk_root);
    out.extend_from_slice(&q_bytes);
    out.extend_from_slice(message);
    out
}

// expand_digest: Expand Keccak to the byte length required by k_total*a.
// 1. Use one hash word when it fits.
// 2. Otherwise append counter-suffixed words.
// 3. Truncate the last word to exactly `digest_bytes`.
fn expand_digest(base: &[u8], digest_bytes: usize) -> Vec<u8> {
    if digest_bytes <= HASH_LEN {
        return hash_packed(&[base])[..digest_bytes].to_vec();
    }
    // Preallocate the exact output length so no extra bytes can be read by bit extraction.
    let mut out = Vec::with_capacity(digest_bytes);
    let mut block_counter = 0u32;
    while out.len() < digest_bytes {
        // The expansion counter is encoded big-endian to match Solidity abi.encodePacked(uint32).
        let digest_word = hash_packed(&[base, &block_counter.to_be_bytes()]);
        // Only the final iteration may copy fewer than 32 bytes.
        let remaining = digest_bytes - out.len();
        out.extend_from_slice(&digest_word[..remaining.min(HASH_LEN)]);
        block_counter = block_counter.wrapping_add(1);
    }
    out
}

fn compact_fors_leaf_secret(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    tree_index: u64,
) -> [u8; HASH_LEN] {
    // Secret leaves are PRF outputs addressed by compact slot q and low leaf index.
    hash_packed(&[
        b"JARDIN/FORS_PRF",
        sk_seed,
        sub_pk_seed,
        &jardin_address_word(ADDRESS_TYPE_FORS_PRF, q, 0, tree_index),
    ])
}

fn compact_fors_leaf_hash(
    sk_seed: &[u8; HASH_LEN],
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    tree_index: u64,
) -> [u8; HASH_LEN] {
    // First derive the secret leaf, then hash it into the public FORS leaf.
    let secret = compact_fors_leaf_secret(sk_seed, sub_pk_seed, q, tree_index);
    hash_packed(&[
        b"JARDIN/F",
        sub_pk_seed,
        &jardin_address_word(ADDRESS_TYPE_FORS_TREE, q, 0, tree_index),
        &secret,
    ])
}

fn compact_fors_node_hash(
    sub_pk_seed: &[u8; HASH_LEN],
    q: u8,
    node_height: u32,
    tree_index: u64,
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"JARDIN/H",
        sub_pk_seed,
        &jardin_address_word(ADDRESS_TYPE_FORS_TREE, q, node_height, tree_index),
        &left,
        &right,
    ])
}

fn compact_fors_roots_hash(sub_pk_seed: &[u8; HASH_LEN], q: u8, roots: &[u8]) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"JARDIN/T_k",
        sub_pk_seed,
        &jardin_address_word(ADDRESS_TYPE_FORS_ROOTS, q, 0, 0),
        roots,
    ])
}

fn jardin_merkle_parent_hash(
    sub_pk_seed: &[u8; HASH_LEN],
    level: u32,
    node_index: u32,
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"JARDIN/H",
        sub_pk_seed,
        &jardin_merkle_address_word(level, node_index),
        &left,
        &right,
    ])
}

// compact_fors_tree_low_leaf_index: Pack `(forsTree, leaf)` into the JARDIN low-leaf-index field.
fn compact_fors_tree_low_leaf_index(fors_tree: u32, leaf: u32) -> u64 {
    (u64::from(fors_tree) << u32::from(STATEFUL_FORS_TREE_HEIGHT)) | u64::from(leaf)
}

// jardin_address_word: Pack the 32-byte JARDIN ADRS word used by FORS+C.
fn jardin_address_word(address_type: u32, q: u8, x: u32, y: u64) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    // Bytes 12..16 carry the JARDIN address type.
    out[12..16].copy_from_slice(&address_type.to_be_bytes());
    // JARDIN `ci` is one-indexed, so explicit slot q becomes q+1 in ADRS.
    out[20..24].copy_from_slice(&(u32::from(q) + 1).to_be_bytes());
    // Bytes 24..28 carry the x field, usually node height.
    out[24..28].copy_from_slice(&x.to_be_bytes());
    // Bytes 28..32 carry the y field, usually low leaf/node index.
    out[28..32].copy_from_slice(&(y as u32).to_be_bytes());
    out
}

// jardin_merkle_address_word: Pack the balanced compact-path Merkle ADRS word.
fn jardin_merkle_address_word(level: u32, node_index: u32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    // Use the dedicated JARDIN Merkle address type, separate from FORS tree hashing.
    out[12..16].copy_from_slice(&ADDRESS_TYPE_JARDIN_MERKLE.to_be_bytes());
    // Bytes 24..28 carry the Merkle level.
    out[24..28].copy_from_slice(&level.to_be_bytes());
    // Bytes 28..32 carry the parent node index at that level.
    out[28..32].copy_from_slice(&node_index.to_be_bytes());
    out
}
