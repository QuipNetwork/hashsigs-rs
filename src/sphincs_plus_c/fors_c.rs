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


//! FORS-C sign and verify.
//!
//! Signs the external message digest with `NUM_FORS_TREES - 1` few-time
//! secret-tree openings, mirroring Solidity's `ForsC.sol`. Builds on the
//! shared `hash`/`treehash` helpers and is consumed by `sphincs_plus_c`, which
//! chains the reconstructed FORS root into the hypertree.

use alloc::format;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::primitives::hash::{fors_address_word, hash_node, hash_packed, read_bits32, read_bits64, word32};
use crate::primitives::profiles::{
    FORS_C_MAX_GRIND_COUNTER, FORS_TREE_HEIGHT, HYPERTREE_HEIGHT, NUM_FORS_TREES,
    NUM_HYPERTREE_LAYERS,
};
use super::key::Key;
use crate::types::{ForsEntry, ForsSignature, HASH_LEN};

/// Signed FORS trees per signature: the final tree is omitted (FORS-C).
const SIGNED_TREES: usize = NUM_FORS_TREES as usize - 1;

/// FORS digest length: `NUM_FORS_TREES * FORS_TREE_HEIGHT` leaf-index bits
/// plus `HYPERTREE_HEIGHT` coordinate bits, rounded up to whole bytes.
const FORS_DIGEST_BYTES: usize =
    (NUM_FORS_TREES as usize * FORS_TREE_HEIGHT as usize + HYPERTREE_HEIGHT as usize).div_ceil(8);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForsDigest {
    tree_index: u64,
    leaf_index: u32,
    digest: [u8; FORS_DIGEST_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningForsDigest {
    pub tree_index: u64,
    pub leaf_index: u32,
    pub signed_tree_indices: [u32; SIGNED_TREES],
    pub omitted_final_tree_is_zero: bool,
}

pub(crate) fn verify_fors_c_and_return_root(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    signature: &ForsSignature,
) -> Option<([u8; HASH_LEN], u64, u32)> {
    let signed_trees = NUM_FORS_TREES as usize - 1;
    if signature.entries.len() != signed_trees {
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

    let mut roots = [[0u8; HASH_LEN]; SIGNED_TREES];
    for (fors_tree_index, root_slot) in roots.iter_mut().enumerate() {
        let entry = signature.entries.get(fors_tree_index)?;
        if entry.auth_path.len() != fors_tree_height {
            return None;
        }
        let entry_leaf_index = read_bits32(
            &digest.digest,
            fors_tree_index * fors_tree_height,
            FORS_TREE_HEIGHT as u32,
        )?;
        *root_slot = fors_entry_root32(
            fors_tree_height as u32,
            pk_seed,
            ForsLeafCoords {
                tree_index: digest.tree_index,
                leaf_index: digest.leaf_index,
                fors_tree: fors_tree_index as u32,
                leaf: entry_leaf_index,
            },
            entry,
        )?;
    }

    Some((
        fors_public_key_hash(pk_seed, &roots),
        digest.tree_index,
        digest.leaf_index,
    ))
}

/// Aggregate FORS public key hash: `"fors-pk" ‖ pk_seed ‖ root_0 ‖ …` fed to
/// the hash vectored, byte-identical to the packed form.
fn fors_public_key_hash(
    pk_seed: &[u8],
    roots: &[[u8; HASH_LEN]; SIGNED_TREES],
) -> [u8; HASH_LEN] {
    let mut parts: [&[u8]; SIGNED_TREES + 2] = [&[]; SIGNED_TREES + 2];
    parts[0] = b"fors-pk";
    parts[1] = pk_seed;
    for (part, root) in parts[2..].iter_mut().zip(roots) {
        *part = root.as_ref();
    }
    hash_node(&parts)
}

pub(crate) fn signer_fors_digest(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    counter: u32,
) -> Option<SigningForsDigest> {
    let index_bits = u32::from(NUM_FORS_TREES) * u32::from(FORS_TREE_HEIGHT);
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    let tree_bits = u32::from(HYPERTREE_HEIGHT) - subtree_height;
    let digest = fors_digest_bytes(pk_seed, hypertree_root, randomizer, counter, message);
    let mut signed_tree_indices = [0u32; SIGNED_TREES];
    for (tree, index_slot) in signed_tree_indices.iter_mut().enumerate() {
        *index_slot = read_bits32(
            &digest,
            tree * FORS_TREE_HEIGHT as usize,
            FORS_TREE_HEIGHT as u32,
        )?;
    }
    let omitted_final_tree_is_zero = read_bits32(
        &digest,
        SIGNED_TREES * FORS_TREE_HEIGHT as usize,
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

/// ADRS coordinates for one FORS leaf (hypertree position + FORS tree/leaf).
#[derive(Clone, Copy)]
pub(crate) struct ForsLeafCoords {
    pub tree_index: u64,
    pub leaf_index: u32,
    pub fors_tree: u32,
    pub leaf: u32,
}

pub(crate) fn fors_leaf_secret(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    coords: ForsLeafCoords,
) -> [u8; HASH_LEN] {
    let tree_leaf = (u64::from(coords.fors_tree) << FORS_TREE_HEIGHT) + u64::from(coords.leaf);
    let address_word = fors_address_word(coords.tree_index, coords.leaf_index, 0, tree_leaf);
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
    coords: ForsLeafCoords,
) -> [u8; HASH_LEN] {
    let secret = Zeroizing::new(fors_leaf_secret(pk_seed, sk_seed, coords));
    fors_leaf_hash_from_secret(pk_seed, coords, &secret)
}

fn fors_leaf_hash_from_secret(
    pk_seed: &[u8; HASH_LEN],
    coords: ForsLeafCoords,
    secret: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let tree_leaf = (u64::from(coords.fors_tree) << FORS_TREE_HEIGHT) + u64::from(coords.leaf);
    let address_word = fors_address_word(coords.tree_index, coords.leaf_index, 0, tree_leaf);
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
    coords: ForsLeafCoords,
) -> ([u8; HASH_LEN], [u8; HASH_LEN], Vec<[u8; HASH_LEN]>) {
    let height = u32::from(FORS_TREE_HEIGHT);
    // Compute the selected leaf secret once and reuse it for both the revealed
    // signature field and the leaf-hash step (avoids a second SK derivation).
    let selected_secret_leaf = fors_leaf_secret(pk_seed, sk_seed, coords);

    let (root, auth_path) = crate::primitives::treehash::treehash_root_and_auth_path(
        height,
        coords.leaf,
        |index| {
            if index == coords.leaf {
                fors_leaf_hash_from_secret(pk_seed, coords, &selected_secret_leaf)
            } else {
                fors_leaf_hash(
                    pk_seed,
                    sk_seed,
                    ForsLeafCoords {
                        leaf: index,
                        ..coords
                    },
                )
            }
        },
        |node_height, parent_index, left, right| {
            let shifted_tree = u64::from(coords.fors_tree) << (height - node_height);
            let parent_low_index = shifted_tree + parent_index;
            let address_word = fors_address_word(
                coords.tree_index,
                coords.leaf_index,
                node_height,
                parent_low_index,
            );
            hash_node(&[
                b"fors-node".as_ref(),
                pk_seed.as_ref(),
                address_word.as_ref(),
                left.as_ref(),
                right.as_ref(),
            ])
        },
    );

    (root, selected_secret_leaf, auth_path)
}

fn fors_entry_root32(
    height: u32,
    pk_seed: &[u8],
    coords: ForsLeafCoords,
    entry: &ForsEntry,
) -> Option<[u8; HASH_LEN]> {
    let shifted_fors_tree = u64::from(coords.fors_tree) << height;
    let leaf_low_index = shifted_fors_tree + u64::from(coords.leaf);
    let mut node = hash_fors_leaf32(
        pk_seed,
        fors_address_word(coords.tree_index, coords.leaf_index, 0, leaf_low_index),
        &entry.secret_leaf,
    )?;
    let mut index = coords.leaf;
    for level in 0..height {
        let sibling = word32(entry.auth_path.get(level as usize)?)?;
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let node_height = level + 1;
        let shifted_tree = u64::from(coords.fors_tree) << (height - node_height);
        let parent_index = u64::from(index >> 1);
        let parent_low_index = shifted_tree + parent_index;
        let address_word = fors_address_word(
            coords.tree_index,
            coords.leaf_index,
            node_height,
            parent_low_index,
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
    let digest = fors_digest_bytes(pk_seed, hypertree_root, randomizer, counter, message);

    let cursor = index_bits as usize;
    Some(ForsDigest {
        tree_index: read_bits64(&digest, cursor, tree_bits)?,
        leaf_index: read_bits32(&digest, cursor + tree_bits as usize, subtree_height)?,
        digest,
    })
}

/// FORS message digest, MGF1-style: block `i` is
/// `H("fors-digest" ‖ pk_seed ‖ root ‖ randomizer ‖ counter ‖ message [‖ i])`,
/// with the block counter suffix only in the multi-block (>32 byte) regime.
/// The preimage parts are fed to the hash vectored, byte-identical to the
/// previously packed `base` buffer.
fn fors_digest_bytes(
    pk_seed: &[u8],
    hypertree_root: &[u8],
    randomizer: &[u8],
    counter: u32,
    message: &[u8],
) -> [u8; FORS_DIGEST_BYTES] {
    let counter_be = counter.to_be_bytes();
    let mut out = [0u8; FORS_DIGEST_BYTES];
    if FORS_DIGEST_BYTES <= HASH_LEN {
        let word = hash_packed(&[
            b"fors-digest",
            pk_seed,
            hypertree_root,
            randomizer,
            &counter_be,
            message,
        ]);
        // `min` keeps the wide-digest profiles (which never reach this
        // compile-time-dead branch) borrow-checkable and lint-clean.
        let take = FORS_DIGEST_BYTES.min(HASH_LEN);
        out[..take].copy_from_slice(&word[..take]);
        return out;
    }

    let mut filled = 0usize;
    let mut block_counter = 0u32;
    while filled < FORS_DIGEST_BYTES {
        let digest_word = hash_packed(&[
            b"fors-digest",
            pk_seed,
            hypertree_root,
            randomizer,
            &counter_be,
            message,
            &block_counter.to_be_bytes(),
        ]);
        let take = (FORS_DIGEST_BYTES - filled).min(HASH_LEN);
        out[filled..filled + take].copy_from_slice(&digest_word[..take]);
        filled += take;
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

        let coords = ForsLeafCoords {
            tree_index,
            leaf_index,
            fors_tree,
            leaf,
        };
        let secret = fors_leaf_secret(&pk_seed, &sk_seed, coords);
        let reused = fors_leaf_hash_from_secret(&pk_seed, coords, &secret);
        let direct = fors_leaf_hash(&pk_seed, &sk_seed, coords);

        assert_eq!(reused, direct);
    }
}

// ---- signing ----

fn stateless_trace_enabled() -> bool {
    #[cfg(feature = "std")]
    {
        matches!(
            std::env::var("SHRINCS_TRACE_STATELESS").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        )
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

#[cfg(not(feature = "parallel"))]
fn stateless_trace_counter_every() -> u32 {
    #[cfg(feature = "std")]
    {
        std::env::var("SHRINCS_TRACE_COUNTER_EVERY")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1 << 20)
    }
    #[cfg(not(feature = "std"))]
    {
        1 << 20
    }
}

fn stateless_trace(message: &str) {
    #[cfg(feature = "std")]
    if stateless_trace_enabled() {
        hashsigs_println!("{message}");
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = message;
    }
}

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
    signing_key: &Key,
    message: &[u8],
) -> Option<SignedForsC> {
    if stateless_trace_enabled() {
        stateless_trace(&format!(
            "stateless trace: FORS start message_len={} signed_trees={} max_counter={}",
            message.len(),
            SIGNED_TREES,
            FORS_C_MAX_GRIND_COUNTER
        ));
    }
    // FORS-C signs k - 1 trees. The final tree is omitted only when the digest
    // selects leaf zero for that final tree, so the signer grinds the counter
    // until that condition holds.

    // This is the FORS-C local message randomizer. It is deterministic for the
    // same stateless PRF seed and message, matching the SPHINCS-style separation
    // between SK.seed-derived signing secrets and SK.prf-derived randomness.
    let randomizer =
        hash_packed(&[b"fors-randomizer", signing_key.secret.prf_seed.as_bytes(), message]);
    stateless_trace("stateless trace: FORS randomizer ready");

    if let Some((counter, digest)) =
        winning_fors_counter_and_digest(signing_key, message, &randomizer, FORS_C_MAX_GRIND_COUNTER)
    {
        if stateless_trace_enabled() {
            stateless_trace(&format!(
                "stateless trace: FORS winner counter={} tree_index={} leaf_index={}",
                counter, digest.tree_index, digest.leaf_index
            ));
        }

        let mut roots = [[0u8; HASH_LEN]; SIGNED_TREES];
        let mut entries = Vec::with_capacity(SIGNED_TREES);
        for (fors_tree, root_slot) in roots.iter_mut().enumerate() {
            if stateless_trace_enabled() && (fors_tree == 0 || fors_tree + 1 == SIGNED_TREES) {
                hashsigs_println!(
                    "stateless trace: FORS materializing tree {}/{}",
                    fors_tree + 1,
                    SIGNED_TREES
                );
            }
            // For each selected tree, reveal exactly the chosen secret leaf and
            // provide the siblings needed to recompute that tree's root.
            let leaf = digest.signed_tree_indices[fors_tree];
            let (root, secret_leaf, auth_path) = fors_tree_root_and_auth_path(
                signing_key.public_key.pk_seed.as_bytes(),
                signing_key.secret.sk_seed.as_bytes(),
                ForsLeafCoords {
                    tree_index: digest.tree_index,
                    leaf_index: digest.leaf_index,
                    fors_tree: fors_tree as u32,
                    leaf,
                },
            );
            *root_slot = root;
            entries.push(ForsEntry {
                secret_leaf,
                auth_path,
            });
        }

        // The verifier aggregates the reconstructed per-tree roots the same way.
        // The public seed is included so roots from a different FORS key cannot
        // be transplanted into this key.
        return Some(SignedForsC {
            root: fors_public_key_hash(signing_key.public_key.pk_seed.as_bytes(), &roots),
            signature: ForsSignature {
                randomizer,
                counter,
                entries,
            },
            tree_index: digest.tree_index,
            leaf_index: digest.leaf_index,
        });
    }

    stateless_trace("stateless trace: FORS no winning counter found");
    None
}

/// Sequential fallback (default / `parallel` feature off). Kept byte-identical
/// to the parallel version below: both return the lowest winning counter.
#[cfg(not(feature = "parallel"))]
fn winning_fors_counter_and_digest(
    signing_key: &Key,
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    limit: u32,
) -> Option<(u32, SigningForsDigest)> {
    let trace_enabled = stateless_trace_enabled();
    let trace_every = stateless_trace_counter_every();
    if trace_enabled {
        hashsigs_println!("stateless trace: FORS counter search start limit={limit}");
    }
    for counter in 0..limit {
        if trace_enabled && counter > 0 && counter % trace_every == 0 {
            hashsigs_println!("stateless trace: FORS counter search tried={counter}/{limit}");
        }
        // The counter is public and stored in the signature. Its only job is to
        // find a digest whose omitted final FORS tree opens leaf zero.
        let Some(digest) = signer_fors_digest(
            signing_key.public_key.pk_seed.as_bytes(),
            signing_key.public_key.root.as_bytes(),
            message,
            randomizer,
            counter,
        ) else {
            continue;
        };
        if digest.omitted_final_tree_is_zero {
            if trace_enabled {
                hashsigs_println!("stateless trace: FORS counter search success counter={counter}");
            }
            return Some((counter, digest));
        }
    }
    if trace_enabled {
        hashsigs_println!("stateless trace: FORS counter search exhausted limit={limit}");
    }
    None
}

/// Parallel grind: shards the counter range across the rayon global pool.
/// Uses `find_map_first` so the winner is always the lowest matching counter,
/// matching the sequential search and keeping signature bytes identical.
#[cfg(feature = "parallel")]
fn winning_fors_counter_and_digest(
    signing_key: &Key,
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    limit: u32,
) -> Option<(u32, SigningForsDigest)> {
    use rayon::prelude::*;
    let trace_enabled = stateless_trace_enabled();
    if trace_enabled {
        hashsigs_println!("stateless trace: FORS counter search start (parallel) limit={limit}");
    }
    let winner = (0..limit).into_par_iter().find_map_first(|counter| {
        let digest = signer_fors_digest(
            signing_key.public_key.pk_seed.as_bytes(),
            signing_key.public_key.root.as_bytes(),
            message,
            randomizer,
            counter,
        )?;
        digest
            .omitted_final_tree_is_zero
            .then_some((counter, digest))
    });
    if trace_enabled {
        match &winner {
            Some((counter, _)) => {
                hashsigs_println!("stateless trace: FORS counter search success counter={counter}")
            }
            None => hashsigs_println!("stateless trace: FORS counter search exhausted limit={limit}"),
        }
    }
    winner
}

#[cfg(all(test, any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
mod measurement_tests {
    use super::{signer_fors_digest, SigningForsDigest};
    use crate::primitives::hash::hash_packed;
    use crate::primitives::profiles::FORS_C_MAX_GRIND_COUNTER;
    use crate::types::SphincsPlusCSigningKey;
    use crate::types::HASH_LEN;

    fn measurement_key(seed: &[u8], _max: u32) -> SphincsPlusCSigningKey {
        hashsigs_println!(
            "measurement setup: deriving stateless key profile={}",
            crate::primitives::profiles::PROFILE_NAME
        );
        fn d(domain: &[u8], seed: &[u8]) -> [u8; HASH_LEN] {
            hash_packed(&[domain, seed, &[]])
        }
        let key = SphincsPlusCSigningKey {
            stateless_sk_seed: d(b"shrincs-stateless-sk-seed", seed),
            stateless_prf_seed: d(b"shrincs-stateless-prf-seed", seed),
            pk_seed: d(b"shrincs-pk-seed", seed),
            hypertree_root: d(b"placeholder-hypertree-root", seed),
        };
        hashsigs_println!("measurement setup: key material ready");
        key
    }

    fn measurement_env_u32(name: &str, default: u32) -> u32 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(default)
    }

    fn measurement_progress_interval(samples: u32) -> u32 {
        let default = if samples <= 10 { 1 } else { samples / 10 };
        measurement_env_u32("SHRINCS_FORS_MEASURE_PROGRESS_EVERY", default).max(1)
    }

    fn measurement_counter_progress_interval(limit: u32) -> u32 {
        let default = (limit / 16).max(1);
        measurement_env_u32("SHRINCS_FORS_MEASURE_COUNTER_PROGRESS_EVERY", default).max(1)
    }

    /// Progress reporting knobs for the ignored measurement harness.
    struct MeasurementProgress {
        sample_index: u32,
        counter_progress_every: u32,
    }

    fn measured_winning_fors_counter_and_digest(
        signing_key: &SphincsPlusCSigningKey,
        message: &[u8],
        randomizer: &[u8; HASH_LEN],
        limit: u32,
        progress: MeasurementProgress,
    ) -> Option<(u32, SigningForsDigest)> {
        for counter in 0..limit {
            if counter > 0 && counter % progress.counter_progress_every == 0 {
                hashsigs_println!(
                    "counter progress profile={} sample={}/? tried={counter}/{limit}",
                    crate::primitives::profiles::PROFILE_NAME,
                    progress.sample_index + 1
                );
            }
            let Some(digest) = signer_fors_digest(
                &signing_key.pk_seed,
                &signing_key.hypertree_root,
                message,
                randomizer,
                counter,
            ) else {
                continue;
            };
            if digest.omitted_final_tree_is_zero {
                return Some((counter, digest));
            }
        }
        None
    }

    #[test]
    #[ignore = "manual 128s FORS-C success/failure measurement"]
    fn measure_128_fors_signature_success_rate() {
        let samples = measurement_env_u32("SHRINCS_FORS_MEASURE_SAMPLES", 32);
        let limit =
            measurement_env_u32("SHRINCS_FORS_MEASURE_LIMIT", FORS_C_MAX_GRIND_COUNTER);
        let progress_every = measurement_progress_interval(samples);
        let counter_progress_every = measurement_counter_progress_interval(limit);
        hashsigs_println!(
            "starting FORS measurement profile={} samples={samples} limit={limit} progress_every={progress_every} counter_progress_every={counter_progress_every}",
            crate::primitives::profiles::PROFILE_NAME,
        );
        let signing_key = measurement_key(b"fors success-rate measurement key", 4);

        let mut successes = 0u32;
        let mut failures = 0u32;
        let mut max_success_counter = 0u32;
        let mut sum_success_counters = 0u64;

        for i in 0..samples {
            let counter_bytes = i.to_be_bytes();
            let message = hash_packed(&[
                b"fors-success-rate-measurement".as_ref(),
                counter_bytes.as_ref(),
            ]);
            let randomizer = hash_packed(&[
                b"fors-randomizer".as_ref(),
                signing_key.stateless_prf_seed.as_ref(),
                message.as_ref(),
            ]);
            match measured_winning_fors_counter_and_digest(
                &signing_key,
                &message,
                &randomizer,
                limit,
                MeasurementProgress {
                    sample_index: i,
                    counter_progress_every,
                },
            ) {
                Some((counter, _)) => {
                    successes += 1;
                    sum_success_counters += u64::from(counter);
                    max_success_counter = max_success_counter.max(counter);
                }
                None => failures += 1,
            }

            let completed = i + 1;
            if completed % progress_every == 0 || completed == samples {
                hashsigs_println!(
                    "progress profile={} completed={completed}/{samples} successes={successes} failures={failures}",
                    crate::primitives::profiles::PROFILE_NAME
                );
            }
        }

        let success_pct = if samples == 0 {
            0.0
        } else {
            (successes as f64 * 100.0) / samples as f64
        };
        let failure_pct = if samples == 0 {
            0.0
        } else {
            (failures as f64 * 100.0) / samples as f64
        };
        let avg_success_counter = if successes == 0 {
            0.0
        } else {
            sum_success_counters as f64 / successes as f64
        };

        hashsigs_println!(
            "profile={} samples={samples} limit={limit} successes={successes} failures={failures} success_pct={success_pct:.2} failure_pct={failure_pct:.2} avg_success_counter={avg_success_counter:.2} max_success_counter={max_success_counter}",
            crate::primitives::profiles::PROFILE_NAME
        );
    }
}
