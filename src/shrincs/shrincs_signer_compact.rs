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

//! JARDIN-style compact Type 2 signing.
//!
//! References:
//! - [JARDIN §3.3]: FORS+C, ADRS, and the balanced Merkle tree.
//! - [JARDIN §5]: FORS+C parameter selection.
//! - [JARDIN signer]: reference Rust signer implementation.
//! - [JARDIN verifier]: reference on-chain verifier implementation.
//! - [FIPS 205]: Algorithms 14–17, FORS key generation and signing.
//!
//! This matches Solidity `ShrincsCompact`.
//! One device slot has 128 compact FORS+C public keys.
//! `q` picks which one is used for a signature.
//! `sub_pk_root` is a Merkle root over those 128 public keys.
//! The account stores `(sub_pk_seed, sub_pk_root)`.
//! Each raw signature contains `R`, `counter`, 51 FORS+C openings, `q`,
//! and a Merkle path back to `sub_pk_root`.
//!
//! JARDIN §6 derives each device slot from fresh hardware randomness:
//!   `r = hardware_rng(32)`
//!   `slot_sk_seed = HMAC-SHA512(masterSkSeed,
//!       "JARDIN/SKSEED" || r)[0:32]`
//!   `slot_sk_prf = HMAC-SHA512(masterSkSeed,
//!       "JARDIN/SKPRF" || r)[0:n]`
//! This n=32 profile keeps `slot_sk_prf` as 32 bytes.
//!
//! The signer-wasm code derives `pk_seed` with labeled Keccak.
//! This file does the same for `sub_pk_seed`.
//!
//! [JARDIN §3.3]: https://notes.ethereum.org/@niard/JARDIN
//! [JARDIN §5]: https://notes.ethereum.org/@niard/JARDIN
//! [JARDIN signer]: https://github.com/nconsigny/JARDIN
//! (`signer-wasm/src`)
//! [JARDIN verifier]: https://github.com/nconsigny/JARDIN (`src`)
//! [FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205

use super::shrincs_signer_types::{CompactSignature, CompactSigningKey, ShrincsSignerResult};
use super::shrincs_signer_utils::{hash_packed, pack, read_bits32, word32};
use super::verifier::HASH_LEN;
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

// Different from [JARDIN §5]: this file uses n=32 and k=52.
// JARDIN §5 uses n=16 and k=26. Both use a=5.
const COMPACT_FORS_TREE_HEIGHT: u8 = 5;
// We sign 51 of the 52 FORS trees.
const COMPACT_OPEN_FORS_TREES: u8 = 51;
// h = 7 means the compact Merkle tree has 128 leaves.
const COMPACT_MERKLE_HEIGHT: u8 = 7;
// Q_MAX = 2^h = 2^7 = 128.
const COMPACT_Q_MAX: u8 = 128;
const COMPACT_MERKLE_LEAVES: usize = COMPACT_Q_MAX as usize;
const COMPACT_C_MAX_GRIND_COUNTER: u32 = 1 << 24;

// ceil(k * a / 8) = ceil(52 * 5 / 8) = 33.
const COMPACT_DIGEST_BYTES: usize = 33;
// len(R32 || counter4) = 32 + 4 = 36.
const COMPACT_FORS_OFFSET: usize = 36;
// secret_leaf32 + auth_path(5 * 32) = 192.
const COMPACT_FORS_ENTRY_BYTES: usize = 192;
// 36 + 51 * 192 = 9828.
const COMPACT_Q_OFFSET: usize = 9828;
// COMPACT_Q_OFFSET + q1 = 9829.
const COMPACT_MERKLE_AUTH_OFFSET: usize = 9829;
// 32 + 4 + 51*192 + 1 + 7*32 = 10053.
const COMPACT_SIGNATURE_BYTES: usize = 10053;
// len(sub_pk_seed32 || ADRS32 || roots[51]32) = 32 + 32 + 51*32.
const COMPACT_FORS_PK_INPUT_BYTES: usize = 1696;

// FIPS 205 ADRS type values preserved by JARDIN for FORS.
const ADDRESS_TYPE_FORS_TREE: u32 = 3;
const ADDRESS_TYPE_FORS_ROOTS: u32 = 4;
const ADDRESS_TYPE_FORS_PRF: u32 = 6;
// JARDIN reserves type 16 for the outer compact Merkle tree.
const ADDRESS_TYPE_JARDIN_MERKLE: u32 = 16;

// compact_keygen: Build one compact signing key for one device slot.
//
// `q` in JARDIN is `fors_key_index` here. It chooses one of the
// 128 FORS keys under this same device slot.
//
// 1. Check that q is in 0..128.
// 2. Derive the two slot secrets.
// 3. Derive the public seed for this slot.
// 4. Build the Merkle root over all 128 FORS public keys.
// 5. Return the data the signer needs for this q.
pub(crate) fn compact_keygen(
    master_sk_seed: &[u8; HASH_LEN],
    slot_randomness: &[u8; HASH_LEN],
    fors_key_index: u8,
) -> ShrincsSignerResult<CompactSigningKey> {
    // q must point to one of the 128 FORS keys in this slot.
    if fors_key_index >= COMPACT_Q_MAX {
        return None;
    }

    // Used only by the signer to derive FORS secret leaves.
    let slot_sk_seed = hmac_sha512_32(master_sk_seed, b"JARDIN/SKSEED", slot_randomness)?;
    // Used only by the signer to derive R for a signature.
    let slot_sk_prf = hmac_sha512_32(master_sk_seed, b"JARDIN/SKPRF", slot_randomness)?;
    // Public seed for this slot.
    let sub_pk_seed = compact_pk_seed_from_slot_seed(&slot_sk_seed);
    // Merkle root registered on-chain as subPkRoot.
    let sub_pk_root = compact_merkle_root_and_auth(&slot_sk_seed, &sub_pk_seed, fors_key_index).0;

    Some(CompactSigningKey {
        slot_randomness: *slot_randomness,
        slot_sk_seed,
        slot_sk_prf,
        sub_pk_seed,
        sub_pk_root,
        q: fors_key_index,
    })
}

// sign_compact_raw: Sign one 32-byte Type 2 message hash.
//
// This follows JARDIN §3.3 and FIPS 205 Algorithm 16.
//
// Raw signature:
// R32 || counter4 || opened_fors[51] || q1 || merkle_auth[7]
//
// 1. Check that the message is exactly 32 bytes.
// 2. Rebuild the Merkle root and check it matches the key.
// 3. Try counters until the skipped FORS tree selects leaf 0.
// 4. Write R, counter, q, FORS openings, and Merkle auth path.
pub(crate) fn sign_compact_raw(
    signing_key: &CompactSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<CompactSignature> {
    // The verifier expects a bytes32 hash, not an arbitrary message.
    let message = word32(message)?;
    // q must point to one of the 128 FORS keys in this slot.
    if signing_key.q >= COMPACT_Q_MAX {
        return None;
    }

    let fors_key_index = signing_key.q;
    // Rebuild the root from the slot seed. If it differs, this key is stale
    // or malformed, so do not sign.
    let (computed_root, merkle_auth) = compact_merkle_root_and_auth(
        &signing_key.slot_sk_seed,
        &signing_key.sub_pk_seed,
        fors_key_index,
    );
    if computed_root != signing_key.sub_pk_root {
        return None;
    }

    let mut message_digest = [0u8; COMPACT_DIGEST_BYTES];
    let mut randomizer = [0u8; HASH_LEN];
    let mut grind_counter = None;
    for counter in 0..COMPACT_C_MAX_GRIND_COUNTER {
        // Derive R for this counter.
        // Different counters give different H_msg outputs.
        randomizer = compact_prf_msg(
            &signing_key.slot_sk_prf,
            &signing_key.sub_pk_seed,
            &signing_key.sub_pk_root,
            fors_key_index,
            &message,
            counter,
        );
        // H_msg gives 52 five-bit FORS leaf indexes.
        // We open the first 51 trees and skip the last one.
        message_digest = compact_h_msg(
            &signing_key.sub_pk_seed,
            &signing_key.sub_pk_root,
            &message,
            &randomizer,
            counter,
            fors_key_index,
        );
        // The 52nd FORS tree is skipped. It must select leaf 0.
        if compact_base2b(&message_digest, u32::from(COMPACT_OPEN_FORS_TREES)) == Some(0) {
            grind_counter = Some(counter);
            break;
        }
    }
    // Give up if no counter made the skipped tree select leaf 0.
    let counter = grind_counter?;

    // Allocate the exact byte layout that Solidity verifies.
    let mut raw_signature = vec![0u8; COMPACT_SIGNATURE_BYTES];
    // R32 at bytes [0, 32).
    raw_signature[0..HASH_LEN].copy_from_slice(&randomizer);
    // counter4 at bytes [32, 36), encoded as uint32_be.
    raw_signature[32..36].copy_from_slice(&counter.to_be_bytes());
    // q1 at byte 9828, after all opened FORS entries.
    raw_signature[COMPACT_Q_OFFSET] = fors_key_index;

    for tree in 0..COMPACT_OPEN_FORS_TREES as u32 {
        // Pick the leaf to open in this FORS tree.
        let leaf_index = compact_base2b(&message_digest, tree)?;
        // Reveal that secret leaf and the 5 siblings needed for its root.
        let (secret, auth_path) = compact_fors_secret_and_auth(
            &signing_key.slot_sk_seed,
            &signing_key.sub_pk_seed,
            fors_key_index,
            tree,
            leaf_index,
        );
        // Each FORS entry is secret_leaf32 || auth_node[5]32.
        let offset = COMPACT_FORS_OFFSET + tree as usize * COMPACT_FORS_ENTRY_BYTES;
        raw_signature[offset..offset + HASH_LEN].copy_from_slice(&secret);
        for (level, auth) in auth_path.iter().enumerate() {
            // Store the siblings right after the secret leaf.
            let auth_offset = offset + HASH_LEN + level * HASH_LEN;
            raw_signature[auth_offset..auth_offset + HASH_LEN].copy_from_slice(auth);
        }
    }

    for level in 0..COMPACT_MERKLE_HEIGHT as u32 {
        // These 7 siblings prove this FORS key is under sub_pk_root.
        let offset = COMPACT_MERKLE_AUTH_OFFSET + level as usize * HASH_LEN;
        raw_signature[offset..offset + HASH_LEN].copy_from_slice(&merkle_auth[level as usize]);
    }

    Some(CompactSignature {
        sub_pk_seed: signing_key.sub_pk_seed,
        sub_pk_root: signing_key.sub_pk_root,
        raw_signature,
    })
}

// compact_merkle_root_and_auth: Build the 128-leaf compact Merkle tree.
//
// Leaves are the 128 compact FORS public keys for this device slot.
// This is the balanced tree from JARDIN §3.3.
//
// 1. Build all 128 leaves.
// 2. Save one sibling per level for the selected q.
// 3. Hash pairs of nodes until one root remains.
// 4. Return the root and the saved siblings.
fn compact_merkle_root_and_auth(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
) -> (
    [u8; HASH_LEN],
    [[u8; HASH_LEN]; COMPACT_MERKLE_HEIGHT as usize],
) {
    // Start with one leaf per compact FORS key.
    let mut nodes = [[0u8; HASH_LEN]; COMPACT_MERKLE_LEAVES];
    // One sibling per level proves the selected leaf belongs to the root.
    let mut auth_path = [[0u8; HASH_LEN]; COMPACT_MERKLE_HEIGHT as usize];

    for (fors_key, node) in nodes.iter_mut().enumerate() {
        // Build the FORS public key for this q value.
        *node = compact_fors_pk(sk_seed, pk_seed, fors_key as u8);
    }

    // Track the selected node as we move up the tree.
    let mut path_index = usize::from(fors_key_index);
    // Only the first node_count entries still belong to this level.
    let mut node_count = COMPACT_MERKLE_LEAVES;
    for level_from_leaf in 0..COMPACT_MERKLE_HEIGHT as u32 {
        // XOR 1 gives the sibling: even -> next, odd -> previous.
        auth_path[level_from_leaf as usize] = nodes[path_index ^ 1];
        // JARDIN numbers these levels from root to leaves.
        let level = u32::from(COMPACT_MERKLE_HEIGHT) - 1 - level_from_leaf;
        for parent in 0..(node_count >> 1) {
            // Read the two children that make this parent.
            let left = nodes[parent << 1];
            let right = nodes[(parent << 1) | 1];
            // Address includes the level and parent index.
            let address = compact_adrs(ADDRESS_TYPE_JARDIN_MERKLE, 0, 0, level, parent as u32);
            // Store the parent in the front half of the same array.
            nodes[parent] = compact_h(pk_seed, &address, &left, &right);
        }
        // Move from the selected node to its parent.
        path_index >>= 1;
        // The next level has half as many nodes.
        node_count >>= 1;
    }
    (nodes[0], auth_path)
}

// compact_fors_pk: Compute one compact FORS public key for q.
//
// T_k input:
// sub_pk_seed32 || ADRS(type=FORS_ROOTS, ci=q)32 || roots[51]32
//
// 1. Start with sub_pk_seed.
// 2. Add the FORS_ROOTS address for q.
// 3. Add the 51 FORS tree roots.
// 4. Hash everything into one public key.
fn compact_fors_pk(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
) -> [u8; HASH_LEN] {
    // Reserve the exact input size used by Solidity.
    let mut input = Vec::with_capacity(COMPACT_FORS_PK_INPUT_BYTES);
    // Add the public seed.
    input.extend_from_slice(pk_seed);
    // Add the address for this q value.
    input.extend_from_slice(&compact_adrs(
        ADDRESS_TYPE_FORS_ROOTS,
        0,
        u32::from(fors_key_index),
        0,
        0,
    ));
    for tree in 0..COMPACT_OPEN_FORS_TREES as u32 {
        // Add one root per signed FORS tree.
        let root = compact_fors_tree_root(sk_seed, pk_seed, fors_key_index, tree);
        input.extend_from_slice(&root);
    }
    // This is T_k from FORS, implemented with keccak256.
    hash_packed(&[&input])
}

// compact_fors_tree_root: Build one full height-5 FORS tree root.
//
// This follows FIPS 205 Algorithm 15.
//
// 1. Derive all 32 secret leaves.
// 2. Hash each secret leaf into a public leaf.
// 3. Hash pairs of leaves upward until one root remains.
fn compact_fors_tree_root(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
    tree: u32,
) -> [u8; HASH_LEN] {
    // A height-5 tree has 32 leaves.
    let mut nodes = [[0u8; HASH_LEN]; 32];
    for leaf in 0..32u32 {
        // Derive the secret for this leaf.
        let secret = compact_fors_secret(sk_seed, pk_seed, fors_key_index, tree, leaf);
        // tree_index is the leaf number across all FORS trees.
        let tree_index = (tree << COMPACT_FORS_TREE_HEIGHT) + leaf;
        // Hash the secret into a public leaf node.
        let address = compact_adrs(
            ADDRESS_TYPE_FORS_TREE,
            0,
            u32::from(fors_key_index),
            0,
            tree_index,
        );
        // Store this public leaf in the tree buffer.
        nodes[leaf as usize] = compact_f(pk_seed, &address, &secret);
    }
    compact_fors_tree_root_from_leaves(pk_seed, fors_key_index, tree, &mut nodes)
}

// compact_fors_secret_and_auth: Build one FORS signature entry.
//
// One entry is:
// secret_leaf32 || auth_node[5]32
//
// This follows the FORS signing step in FIPS 205 Algorithm 16.
//
// 1. Derive the selected secret leaf. This goes in the signature.
// 2. Build the 32 public leaves for this tree.
// 3. Save the sibling beside the selected leaf at each level.
// 4. Hash upward until the root is reached.
fn compact_fors_secret_and_auth(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
    tree: u32,
    mut leaf_index: u32,
) -> ([u8; HASH_LEN], [[u8; HASH_LEN]; 5]) {
    // This is the secret leaf that the signature reveals.
    let secret = compact_fors_secret(sk_seed, pk_seed, fors_key_index, tree, leaf_index);
    // The auth path has one sibling for each of the five levels.
    let mut auth_path = [[0u8; HASH_LEN]; 5];
    // The tree is small, so build all 32 leaves.
    let mut nodes = [[0u8; HASH_LEN]; 32];

    for leaf in 0..32u32 {
        // Build each public leaf.
        let leaf_secret = compact_fors_secret(sk_seed, pk_seed, fors_key_index, tree, leaf);
        let tree_index = (tree << COMPACT_FORS_TREE_HEIGHT) + leaf;
        let address = compact_adrs(
            ADDRESS_TYPE_FORS_TREE,
            0,
            u32::from(fors_key_index),
            0,
            tree_index,
        );
        // Hash the secret leaf into a public leaf.
        nodes[leaf as usize] = compact_f(pk_seed, &address, &leaf_secret);
    }

    for level in 0..COMPACT_FORS_TREE_HEIGHT as u32 {
        // XOR 1 gives the sibling of the selected node.
        auth_path[level as usize] = nodes[(leaf_index ^ 1) as usize];
        // Number of parents at this level: 16, 8, 4, 2, 1.
        let parent_count = 1u32 << (u32::from(COMPACT_FORS_TREE_HEIGHT) - 1 - level);
        for parent in 0..parent_count {
            // Parent height is one above the child level.
            let height = level + 1;
            // Parent index across all FORS trees.
            let tree_index = (tree << (u32::from(COMPACT_FORS_TREE_HEIGHT) - height)) + parent;
            let address = compact_adrs(
                ADDRESS_TYPE_FORS_TREE,
                0,
                u32::from(fors_key_index),
                height,
                tree_index,
            );
            // Hash two children into their parent.
            nodes[parent as usize] = compact_h(
                pk_seed,
                &address,
                &nodes[(parent << 1) as usize],
                &nodes[((parent << 1) | 1) as usize],
            );
        }
        // Move from the selected node to its parent.
        leaf_index >>= 1;
    }
    (secret, auth_path)
}

// compact_fors_tree_root_from_leaves: Hash 32 FORS leaves into one root.
//
// 1. Read pairs from the current level.
// 2. Hash each pair into a parent.
// 3. Store parents at the front of the same array.
// 4. After five levels, nodes[0] is the root.
fn compact_fors_tree_root_from_leaves(
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
    tree: u32,
    nodes: &mut [[u8; HASH_LEN]; 32],
) -> [u8; HASH_LEN] {
    for level in 0..COMPACT_FORS_TREE_HEIGHT as u32 {
        // Number of parents at this level: 16, 8, 4, 2, 1.
        let parent_count = 1u32 << (u32::from(COMPACT_FORS_TREE_HEIGHT) - 1 - level);
        for parent in 0..parent_count {
            let height = level + 1;
            let tree_index = (tree << (u32::from(COMPACT_FORS_TREE_HEIGHT) - height)) + parent;
            let address = compact_adrs(
                ADDRESS_TYPE_FORS_TREE,
                0,
                u32::from(fors_key_index),
                height,
                tree_index,
            );
            // Store the parent in the front half of the array.
            nodes[parent as usize] = compact_h(
                pk_seed,
                &address,
                &nodes[(parent << 1) as usize],
                &nodes[((parent << 1) | 1) as usize],
            );
        }
    }
    nodes[0]
}

// compact_fors_secret: Derive one secret FORS leaf.
//
// This is the FORS_PRF step from FIPS 205 Algorithm 14.
//
// 1. Convert (tree, leaf) into one index.
// 2. Build the FORS_PRF address for that index.
// 3. Hash the seeds and address into a secret leaf.
fn compact_fors_secret(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    fors_key_index: u8,
    tree: u32,
    leaf: u32,
) -> [u8; HASH_LEN] {
    // tree_index counts leaves across all FORS trees.
    let tree_index = (tree << COMPACT_FORS_TREE_HEIGHT) + leaf;
    hash_packed(&[
        b"jardin-fors-prf",
        sk_seed,
        pk_seed,
        &compact_adrs(
            ADDRESS_TYPE_FORS_PRF,
            0,
            u32::from(fors_key_index),
            0,
            tree_index,
        ),
    ])
}

// hmac_sha512_32: Derive one 32-byte slot seed.
//
// HMAC input:
// label || slot_randomness32
//
// 1. Start HMAC-SHA512 with the master secret seed.
// 2. Add the label, such as JARDIN/SKSEED.
// 3. Add the slot randomness.
// 4. Return the first 32 bytes.
fn hmac_sha512_32(
    master_sk_seed: &[u8; HASH_LEN],
    label: &[u8],
    slot_randomness: &[u8; HASH_LEN],
) -> Option<[u8; HASH_LEN]> {
    // This should succeed for a 32-byte key. Return None if it does not.
    let mut mac = HmacSha512::new_from_slice(master_sk_seed).ok()?;
    // Add the label so SKSEED and SKPRF are different.
    mac.update(label);
    // Add the per-device random value.
    mac.update(slot_randomness);
    // HMAC-SHA512 gives 64 bytes. This profile uses the first 32.
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&bytes[..HASH_LEN]);
    Some(out)
}

// compact_pk_seed_from_slot_seed: Derive the public seed for this slot.
//
// This matches signer-wasm:
// pk_seed = keccak256("pk_seed" || master[..32])
fn compact_pk_seed_from_slot_seed(slot_sk_seed: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    // This matches signer-wasm's labeled Keccak derivation.
    hash_packed(&[b"pk_seed", slot_sk_seed])
}

// compact_prf_msg: Compute R for a signature.
//
// JARDIN:
// M* = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
// R  = PRF_msg(slot_sk_prf, opt_rand, uint32_be(counter) || M*)
//
// This code uses sub_pk_seed as opt_rand so signing is deterministic.
fn compact_prf_msg(
    slot_sk_prf: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    pk_root: &[u8; HASH_LEN],
    fors_key_index: u8,
    message: &[u8; HASH_LEN],
    counter: u32,
) -> [u8; HASH_LEN] {
    // M* is the Type 2 message that both PRF_msg and H_msg use.
    let m_star = compact_type2_message(pk_seed, pk_root, fors_key_index, message);
    let counter_bytes = counter.to_be_bytes();

    // JARDIN uses subPkSeed as the deterministic opt_rand value.
    hash_packed(&[
        b"JARDIN/PRF_MSG/v1", // PRF_msg label.
        slot_sk_prf,          // Secret PRF seed.
        pk_seed,              // opt_rand = subPkSeed.
        &counter_bytes,       // uint32_be(counter).
        &m_star,              // M*.
    ])
}

// compact_h_msg: Compute the digest that chooses FORS leaves.
//
// JARDIN:
// M*     = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
// digest = H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)
//
// Solidity ShrincsCompact.hMsg defines the exact Keccak block layout.
// We need 33 bytes because 52 FORS indexes * 5 bits = 260 bits.
fn compact_h_msg(
    pk_seed: &[u8; HASH_LEN],
    pk_root: &[u8; HASH_LEN],
    message: &[u8; HASH_LEN],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
    fors_key_index: u8,
) -> [u8; COMPACT_DIGEST_BYTES] {
    // M* is the Type 2 message that both PRF_msg and H_msg use.
    let m_star = compact_type2_message(pk_seed, pk_root, fors_key_index, message);
    let counter_bytes = counter.to_be_bytes();

    // This part is the same for both hash blocks.
    let prefix = pack(&[
        b"JARDIN/H_MSG/v1", // H_msg label.
        randomizer,         // R.
        pk_seed,            // subPkSeed.
        pk_root,            // subPkRoot.
        &counter_bytes,     // uint32_be(counter).
        &m_star,            // M*.
    ]);
    // First 32 bytes.
    let first = hash_packed(&[&prefix, &0u32.to_be_bytes()]);
    // One more byte. 52 * 5 bits = 260 bits = 33 bytes.
    let second = hash_packed(&[&prefix, &1u32.to_be_bytes()]);
    let mut out = [0u8; COMPACT_DIGEST_BYTES];
    out[..HASH_LEN].copy_from_slice(&first);
    out[HASH_LEN] = second[0];
    out
}

// compact_type2_message: Build the Type 2 message M*.
//
// M* = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
fn compact_type2_message(
    pk_seed: &[u8; HASH_LEN],
    pk_root: &[u8; HASH_LEN],
    fors_key_index: u8,
    message: &[u8; HASH_LEN],
) -> Vec<u8> {
    pack(&[
        b"JARDIN/TYPE2/v1", // Type 2 label.
        pk_seed,            // subPkSeed.
        pk_root,            // subPkRoot.
        &[fors_key_index],  // q.
        message,            // 32-byte account/action hash.
    ])
}

// compact_base2b: Read one 5-bit FORS leaf index from H_msg.
//
// This is the base_2b step from FIPS 205.
// a = 5, so every returned value is in 0..32.
fn compact_base2b(message_digest: &[u8; COMPACT_DIGEST_BYTES], digit_index: u32) -> Option<u32> {
    // a = 5, so each FORS leaf index is 5 bits.
    read_bits32(
        message_digest,
        digit_index as usize * COMPACT_FORS_TREE_HEIGHT as usize,
        u32::from(COMPACT_FORS_TREE_HEIGHT),
    )
}

// compact_adrs: Pack a JARDIN/FIPS address into 32 bytes.
//
// JARDIN names:
// kp = keypair_index
// ci = compact_index, which is q for FORS addresses
// x  = tree_height
// y  = tree_index
//
// Layout:
// layer4 || tree8 || type4 || kp4 || ci4 || x4 || y4
fn compact_adrs(
    address_type: u32,
    keypair_index: u32,
    compact_index: u32,
    tree_height: u32,
    tree_index: u32,
) -> [u8; HASH_LEN] {
    // layer=0 and tree=0, so bytes 0..12 stay zero.
    let mut out = [0u8; HASH_LEN];
    // bytes 12..16: address type.
    out[12..16].copy_from_slice(&address_type.to_be_bytes());
    // bytes 16..20: keypair address. This profile uses zero.
    out[16..20].copy_from_slice(&keypair_index.to_be_bytes());
    // bytes 20..24: q, named `ci` in JARDIN.
    out[20..24].copy_from_slice(&compact_index.to_be_bytes());
    // bytes 24..28: tree height, named `x` in JARDIN.
    out[24..28].copy_from_slice(&tree_height.to_be_bytes());
    // bytes 28..32: node index, named `y` in JARDIN.
    out[28..32].copy_from_slice(&tree_index.to_be_bytes());
    out
}

// compact_f: Hash a FORS secret leaf into a public leaf.
//
// Preimage:
// sub_pk_seed32 || ADRS32 || input32
fn compact_f(
    pk_seed: &[u8; HASH_LEN],
    address_word: &[u8; HASH_LEN],
    input: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // Solidity uses keccak256 over the same packed fields.
    hash_packed(&[pk_seed, address_word, input])
}

// compact_h: Hash two child nodes into one parent node.
//
// Preimage:
// sub_pk_seed32 || ADRS32 || left32 || right32
fn compact_h(
    pk_seed: &[u8; HASH_LEN],
    address_word: &[u8; HASH_LEN],
    left: &[u8; HASH_LEN],
    right: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // Do not sort children. Left/right order matters.
    hash_packed(&[pk_seed, address_word, left, right])
}

#[cfg(test)]
mod tests {
    use super::super::verifier::ActionContext;
    use super::*;
    use crate::shrincs::ShrincsSigner;

    // verify_compact_raw: Test-only verifier for the compact raw signature.
    //
    // This follows Solidity ShrincsCompact.verifyCompactRaw.
    //
    // 1. Check the message and signature sizes.
    // 2. Recompute H_msg and check the skipped FORS tree.
    // 3. Rebuild the FORS public key from the signature.
    // 4. Rebuild the Merkle root and compare it to sub_pk_root.
    fn verify_compact_raw(
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        // Bad message length means invalid signature.
        let Some(message) = word32(message) else {
            return false;
        };
        // Check length before reading fixed offsets.
        if signature.len() != COMPACT_SIGNATURE_BYTES {
            return false;
        }
        let fors_key_index = signature[COMPACT_Q_OFFSET];
        if fors_key_index >= COMPACT_Q_MAX {
            return false;
        }

        // Read R and counter from the signature header.
        let mut randomizer = [0u8; HASH_LEN];
        randomizer.copy_from_slice(&signature[0..HASH_LEN]);
        let counter = u32::from_be_bytes(signature[32..36].try_into().unwrap());
        let message_digest = compact_h_msg(
            sub_pk_seed,
            sub_pk_root,
            &message,
            &randomizer,
            counter,
            fors_key_index,
        );
        if compact_base2b(&message_digest, u32::from(COMPACT_OPEN_FORS_TREES)) != Some(0) {
            return false;
        }

        let fors_pk =
            compact_fors_pk_from_signature(signature, &message_digest, sub_pk_seed, fors_key_index);
        let root = compact_root_from_auth_path(signature, sub_pk_seed, fors_key_index, fors_pk);
        root == *sub_pk_root
    }

    // compact_fors_pk_from_signature: Rebuild a FORS public key in tests.
    //
    // This matches the verifier.
    //
    // 1. Start the same input as compact_fors_pk.
    // 2. Use the message digest to choose one leaf per FORS tree.
    // 3. Rebuild each FORS tree root from the signature.
    // 4. Hash the roots into the FORS public key.
    fn compact_fors_pk_from_signature(
        signature: &[u8],
        message_digest: &[u8; COMPACT_DIGEST_BYTES],
        pk_seed: &[u8; HASH_LEN],
        fors_key_index: u8,
    ) -> [u8; HASH_LEN] {
        // Rebuild the same T_k input as compact_fors_pk.
        let mut input = Vec::with_capacity(COMPACT_FORS_PK_INPUT_BYTES);
        // Add the public seed.
        input.extend_from_slice(pk_seed);
        // Add the address for this q value.
        input.extend_from_slice(&compact_adrs(
            ADDRESS_TYPE_FORS_ROOTS,
            0,
            u32::from(fors_key_index),
            0,
            0,
        ));
        for tree in 0..COMPACT_OPEN_FORS_TREES as u32 {
            // This digest digit chooses the signed leaf in this tree.
            let leaf_index = compact_base2b(message_digest, tree)
                .expect("compact digest contains all opened tree digits");
            // Rebuild that tree root from the signature.
            input.extend_from_slice(&compact_fors_node_from_signature(
                signature,
                pk_seed,
                fors_key_index,
                tree,
                leaf_index,
            ));
        }
        // Hash the recovered roots into the FORS public key.
        hash_packed(&[&input])
    }

    // compact_fors_node_from_signature: Rebuild one FORS tree root.
    //
    // This follows FIPS 205 Algorithm 17.
    //
    // 1. Read the secret leaf from the signature.
    // 2. Hash it into a public leaf.
    // 3. Read one sibling at each level.
    // 4. Put the two children in the right order.
    // 5. Hash upward until we reach the root.
    fn compact_fors_node_from_signature(
        signature: &[u8],
        pk_seed: &[u8; HASH_LEN],
        fors_key_index: u8,
        tree: u32,
        mut leaf_index: u32,
    ) -> [u8; HASH_LEN] {
        // This entry is secret_leaf32 || auth_path[5]32.
        let offset = COMPACT_FORS_OFFSET + tree as usize * COMPACT_FORS_ENTRY_BYTES;
        // Safe because verify_compact_raw checked signature length.
        let secret: [u8; HASH_LEN] = signature[offset..offset + HASH_LEN].try_into().unwrap();
        // tree_index is the leaf number across all FORS trees.
        let tree_index = (tree << COMPACT_FORS_TREE_HEIGHT) + leaf_index;
        // Hash the secret into a public leaf node.
        let mut node = compact_f(
            pk_seed,
            &compact_adrs(
                ADDRESS_TYPE_FORS_TREE,
                0,
                u32::from(fors_key_index),
                0,
                tree_index,
            ),
            &secret,
        );

        for level in 0..COMPACT_FORS_TREE_HEIGHT as u32 {
            // Read the sibling for this level.
            let auth_offset = offset + HASH_LEN + level as usize * HASH_LEN;
            let auth: [u8; HASH_LEN] = signature[auth_offset..auth_offset + HASH_LEN]
                .try_into()
                .unwrap();
            // The low bit says whether our node is left or right.
            let (left, right) = if leaf_index & 1 == 0 {
                (node, auth)
            } else {
                (auth, node)
            };
            // Move one level up.
            let height = level + 1;
            leaf_index >>= 1;
            // Parent index across all FORS trees.
            let tree_index = (tree << (u32::from(COMPACT_FORS_TREE_HEIGHT) - height)) + leaf_index;
            let address = compact_adrs(
                ADDRESS_TYPE_FORS_TREE,
                0,
                u32::from(fors_key_index),
                height,
                tree_index,
            );
            // Hash the two children into their parent.
            node = compact_h(pk_seed, &address, &left, &right);
        }
        node
    }

    // compact_root_from_auth_path: Rebuild sub_pk_root in tests.
    //
    // 1. Read one Merkle sibling from the signature.
    // 2. Use the bits of q to put left and right in the correct order.
    // 3. Hash the pair into its parent.
    // 4. Repeat until one root remains.
    fn compact_root_from_auth_path(
        signature: &[u8],
        pk_seed: &[u8; HASH_LEN],
        fors_key_index: u8,
        mut node: [u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        for level_from_leaf in 0..COMPACT_MERKLE_HEIGHT as u32 {
            // Read one Merkle sibling from the end of the signature.
            let offset = COMPACT_MERKLE_AUTH_OFFSET + level_from_leaf as usize * HASH_LEN;
            let auth: [u8; HASH_LEN] = signature[offset..offset + HASH_LEN].try_into().unwrap();
            // This q bit says whether our node is left or right.
            let (left, right) = if u32::from(fors_key_index) & (1 << level_from_leaf) == 0 {
                (node, auth)
            } else {
                (auth, node)
            };
            // JARDIN numbers these levels from root to leaves.
            let level = u32::from(COMPACT_MERKLE_HEIGHT) - 1 - level_from_leaf;
            // This is the parent index at that level.
            let parent_index = u32::from(fors_key_index) >> (level_from_leaf + 1);
            let address = compact_adrs(ADDRESS_TYPE_JARDIN_MERKLE, 0, 0, level, parent_index);
            // Move one level up.
            node = compact_h(pk_seed, &address, &left, &right);
        }
        node
    }

    // Builds a fixed action context for tests.
    //
    // 1. Use a different byte value for each field.
    // 2. Return the context that gets hashed before signing.
    fn action_context() -> ActionContext {
        ActionContext {
            domain_separator: [7u8; HASH_LEN],
            nonce: [1u8; HASH_LEN],
            key_version: [2u8; HASH_LEN],
            action_type: [3u8; HASH_LEN],
            payload_hash: [4u8; HASH_LEN],
        }
    }

    // Builds a fixed master seed for tests.
    //
    // 1. Add a test-only label.
    // 2. Add the caller label so each test gets different bytes.
    fn compact_master_seed(label: &[u8]) -> [u8; HASH_LEN] {
        hash_packed(&[b"rust compact master seed", label])
    }

    // Builds fixed slot randomness for tests.
    //
    // 1. Add a test-only label.
    // 2. Add the caller label so each test gets different bytes.
    fn compact_slot_randomness(label: &[u8]) -> [u8; HASH_LEN] {
        hash_packed(&[b"rust compact slot randomness", label])
    }

    #[test]
    // Tests the normal compact signing path.
    //
    // 1. Derive one compact key for FORS key 11.
    // 2. Sign one bytes32 message.
    // 3. Check the signature fields.
    // 4. Verify the signature.
    fn compact_signer_outputs_fixed_shape_that_verifies() {
        let master = compact_master_seed(b"fixed shape");
        let slot_randomness = compact_slot_randomness(b"fixed shape");
        let key = compact_keygen(&master, &slot_randomness, 11).unwrap();
        let message = hash_packed(&[b"rust compact message"]);
        let signature = sign_compact_raw(&key, &message).unwrap();

        assert_eq!(key.slot_randomness, slot_randomness);
        assert_eq!(signature.sub_pk_seed, key.sub_pk_seed);
        assert_eq!(signature.sub_pk_root, key.sub_pk_root);
        assert_eq!(signature.q(), Some(key.q));
        assert_eq!(signature.raw_signature.len(), COMPACT_SIGNATURE_BYTES);
        assert_eq!(signature.raw_signature[COMPACT_Q_OFFSET], 11);
        assert!(verify_compact_raw(
            &key.sub_pk_seed,
            &key.sub_pk_root,
            &message,
            &signature.raw_signature,
        ));
    }

    #[test]
    // Checks that one slot has one shared root.
    //
    // 1. Derive two keys from the same master seed and slot randomness.
    // 2. Use two different q values.
    // 3. Check that only q changes.
    fn compact_keygen_builds_one_root_for_all_fors_keys() {
        let master = compact_master_seed(b"shared root");
        let slot_randomness = compact_slot_randomness(b"shared root");
        let left = compact_keygen(&master, &slot_randomness, 3).unwrap();
        let right = compact_keygen(&master, &slot_randomness, 87).unwrap();

        assert_eq!(left.sub_pk_seed, right.sub_pk_seed);
        assert_eq!(left.sub_pk_root, right.sub_pk_root);
        assert_ne!(left.q, right.q);
    }

    #[test]
    // Checks that slot randomness separates devices.
    //
    // 1. Use the same master seed and q.
    // 2. Change only the slot randomness.
    // 3. Check that the derived keys are different.
    fn compact_keygen_separates_devices_with_random_slot_values() {
        let master = compact_master_seed(b"same mnemonic");
        let slot_a = compact_slot_randomness(b"device a");
        let slot_b = compact_slot_randomness(b"device b");

        let device_a = compact_keygen(&master, &slot_a, 11).unwrap();
        let device_b = compact_keygen(&master, &slot_b, 11).unwrap();

        assert_ne!(device_a.slot_randomness, device_b.slot_randomness);
        assert_ne!(device_a.slot_sk_seed, device_b.slot_sk_seed);
        assert_ne!(device_a.slot_sk_prf, device_b.slot_sk_prf);
        assert_ne!(device_a.sub_pk_seed, device_b.sub_pk_seed);
        assert_ne!(device_a.sub_pk_root, device_b.sub_pk_root);
    }

    #[test]
    // Tests the account action signing wrapper.
    //
    // 1. Derive a compact key through ShrincsSigner.
    // 2. Hash an ActionContext into the message.
    // 3. Sign and verify the signature.
    fn compact_action_signer_uses_context_hash() {
        let master = compact_master_seed(b"action fixture");
        let slot_randomness = compact_slot_randomness(b"action fixture");
        let key = ShrincsSigner::compact_keygen(&master, &slot_randomness, 9).unwrap();
        let context = action_context();
        let signature = ShrincsSigner::sign_compact_action(&key, &context).unwrap();
        let message = ShrincsSigner::compact_action_message_hash(&context);

        assert!(verify_compact_raw(
            &signature.sub_pk_seed,
            &signature.sub_pk_root,
            &message,
            &signature.raw_signature,
        ));
    }
}
