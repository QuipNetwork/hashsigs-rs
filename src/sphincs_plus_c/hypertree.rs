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


//! Stateless hypertree sign and verify.
//!
//! Carries a FORS-C root up through `NUM_HYPERTREE_LAYERS` WOTS-C-authenticated
//! subtrees to the pinned hypertree root, mirroring Solidity's `Hypertree.sol`.
//! Sits above `wotsplusc` and `treehash` in the DAG and is consumed by
//! `sphincs_plus_c` to assemble a full stateless signature.

use alloc::vec::Vec;

use zeroize::Zeroizing;
use crate::primitives::hash::{
    base_w_digit, hash_node, hash_packed, hypertree_address_word, word32,
    wots_address_base, wots_digest_bytes,
};
use crate::primitives::profiles::{
    HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN,
    WOTS_TARGET_SUM_STATELESS,
};
use crate::types::{HypertreeLayerSignature, WotsCSignature, HASH_LEN};
use super::key::Key;
use crate::primitives::wotsplusc;
use crate::primitives::wotsplusc::WOTS_C_MAX_GRIND_COUNTER;

/// Layer-0 seed coordinates selected by the FORS message digest.
#[derive(Clone, Copy)]
pub(crate) struct HypertreeSeed {
    pub tree_index: u64,
    pub leaf_index: u32,
}

pub(crate) fn verify_hypertree(
    pk_seed: &[u8; HASH_LEN],
    expected_hypertree_root: &[u8; HASH_LEN],
    fors_root: [u8; HASH_LEN],
    seed: HypertreeSeed,
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
    let mut expected_tree_index = seed.tree_index;
    let mut expected_leaf_index = seed.leaf_index;

    for (layer_index, layer_signature) in layers.iter().enumerate() {
        if expected_leaf_index >= leaf_count
            || layer_signature.auth_path.len() != subtree_height as usize
        {
            return false;
        }
        let coords = WotsKeypair {
            layer: layer_index as u32,
            tree: expected_tree_index,
            keypair: expected_leaf_index,
        };
        if !verify_wots_c32(
            pk_seed,
            coords,
            &layer_signature.wots_c_pk_hash,
            current_root,
            &layer_signature.wots_c_signature,
        ) {
            return false;
        }
        let Some(next_root) = hypertree_root_from_path32(
            subtree_height,
            pk_seed,
            HypertreePath {
                layer: layer_index as u32,
                tree_index: expected_tree_index,
                leaf_index: expected_leaf_index,
            },
            layer_signature.wots_c_pk_hash,
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
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"wots-c-msg".as_ref(),
        pk_seed.as_ref(),
        expected_pk_hash.as_ref(),
        randomizer.as_ref(),
        counter.to_be_bytes().as_ref(),
        message.as_ref(),
    ])
}

pub(crate) fn stateless_wots_public_key_hash(
    pk_seed: &[u8; HASH_LEN],
    endpoints: &[[u8; HASH_LEN]],
) -> [u8; HASH_LEN] {
    // Vectored preimage: tag ‖ pk_seed ‖ endpoint_0 ‖ … — byte-identical to
    // the packed form without materializing a chains-wide buffer.
    const MAX_PARTS: usize = NUM_WOTS_CHAINS as usize + 2;
    let mut parts: [&[u8]; MAX_PARTS] = [&[]; MAX_PARTS];
    parts[0] = b"wots-c-pk";
    parts[1] = pk_seed.as_ref();
    let used = 2 + endpoints.len().min(NUM_WOTS_CHAINS as usize);
    for (part, endpoint) in parts[2..used].iter_mut().zip(endpoints) {
        *part = endpoint.as_ref();
    }
    hash_node(&parts[..used])
}

fn verify_wots_c32(
    pk_seed: &[u8; HASH_LEN],
    coords: WotsKeypair,
    expected_pk_hash: &[u8; HASH_LEN],
    message: [u8; HASH_LEN],
    signature: &WotsCSignature,
) -> bool {
    let chain_count = NUM_WOTS_CHAINS as usize;
    if signature.chains.len() != chain_count || wots_digest_bytes() > HASH_LEN {
        return false;
    }
    let digest = stateless_wots_message_digest(
        pk_seed,
        expected_pk_hash,
        &signature.randomizer,
        signature.counter,
        &message,
    );

    let address_base = wots_address_base(coords.layer, coords.tree, coords.keypair);

    // Pass 1 (cheap, sequential): validate every chain value is present and
    // accumulate the digit sum. Must stay sequential so a missing/overflowing
    // chain fails closed before any chain walk runs.
    let mut digit_sum = 0u32;
    let mut digits = [0u32; NUM_WOTS_CHAINS as usize];
    for (chain_index, digit_slot) in digits.iter_mut().enumerate() {
        let digit = base_w_digit(WOTS_CHAIN_LEN, &digest, chain_index);
        let Some(next_sum) = digit_sum.checked_add(digit) else {
            return false;
        };
        digit_sum = next_sum;
        *digit_slot = digit;
    }
    if digit_sum != WOTS_TARGET_SUM_STATELESS {
        return false;
    }

    // Pass 2 (expensive): walk each chain to its endpoint, writing into a
    // fixed-capacity segment buffer (stack by default, Solana heap — see
    // `buf`). Chain order must match the signer's so the pk-hash preimage is
    // byte-identical, which is why segments are stored in index order.
    let mut segments = crate::primitives::buf::node_buf::<{ NUM_WOTS_CHAINS as usize }>();
    let segment_at = |chain_index: usize| -> Option<[u8; HASH_LEN]> {
        let chain_value = signature.chains.get(chain_index).copied()?;
        Some(wots_chain32_no_mask_base(
            WOTS_CHAIN_LEN,
            *pk_seed,
            wotsplusc::AddressBaseChain {
                address_base,
                chain_index: chain_index as u32,
            },
            chain_value,
            digits[chain_index],
        ))
    };
    #[cfg(feature = "parallel")]
    let filled = {
        use rayon::prelude::*;
        segments
            .par_iter_mut()
            .enumerate()
            .all(|(chain_index, segment)| match segment_at(chain_index) {
                Some(endpoint) => {
                    *segment = endpoint;
                    true
                }
                None => false,
            })
    };
    #[cfg(not(feature = "parallel"))]
    let filled = segments
        .iter_mut()
        .enumerate()
        .all(|(chain_index, segment)| match segment_at(chain_index) {
            Some(endpoint) => {
                *segment = endpoint;
                true
            }
            None => false,
        });
    if !filled {
        return false;
    }

    let computed_pk_hash = stateless_wots_public_key_hash(pk_seed, segments.as_ref());
    computed_pk_hash == *expected_pk_hash
}

fn wots_chain32_no_mask_base(
    w: u16,
    pk_seed: [u8; HASH_LEN],
    addr: wotsplusc::AddressBaseChain,
    value: [u8; HASH_LEN],
    digit: u32,
) -> [u8; HASH_LEN] {
    let steps = u32::from(w - 1) - digit;
    wotsplusc::stateless_wots_chain_from_address_base(
        &pk_seed,
        addr,
        wotsplusc::ChainWalk {
            value,
            start: digit,
            steps,
        },
    )
}

/// Layer / tree / leaf coordinates for a hypertree auth-path climb.
#[derive(Clone, Copy)]
struct HypertreePath {
    layer: u32,
    tree_index: u64,
    leaf_index: u32,
}

fn hypertree_root_from_path32(
    height: u32,
    pk_seed: &[u8],
    path: HypertreePath,
    leaf: [u8; HASH_LEN],
    auth_path: &[[u8; HASH_LEN]],
) -> Option<[u8; HASH_LEN]> {
    if auth_path.len() != height as usize {
        return None;
    }
    let pk_seed = word32(pk_seed)?;
    let mut node = leaf;
    let mut index = path.leaf_index;
    for level in 0..height {
        let sibling = word32(auth_path.get(level as usize)?)?;
        let (left, right) = if index & 1 == 0 {
            (node, sibling)
        } else {
            (sibling, node)
        };
        let address_word =
            hypertree_address_word(path.layer, path.tree_index, level + 1, u64::from(index >> 1));
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

// ---- signing ----

fn derive32(domain: &[u8], seed: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    hash_packed(&[domain, seed, data])
}

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

/// ADRS coordinates identifying one stateless WOTS-C keypair (its Merkle-leaf
/// position). Grouping `layer`/`tree`/`keypair` keeps the signing entry points
/// under the positional-argument limit without a `too_many_arguments` allow.
#[derive(Clone, Copy)]
struct WotsKeypair {
    layer: u32,
    tree: u64,
    keypair: u32,
}

impl WotsKeypair {
    /// Extend a keypair position with a chain index for one chain step-walk.
    fn chain(self, chain: u32) -> WotsChain {
        WotsChain {
            layer: self.layer,
            tree: self.tree,
            keypair: self.keypair,
            chain,
        }
    }
}

/// Full ADRS coordinates for one WOTS-C chain step-walk (keypair position plus
/// the chain index). Bound into every chain hash so a value cannot be replayed
/// at another layer/tree/leaf/chain.
#[derive(Clone, Copy)]
struct WotsChain {
    layer: u32,
    tree: u64,
    keypair: u32,
    chain: u32,
}

/// Seed material threaded through a stateless WOTS-C signature: the public seed,
/// the WOTS secret seed, and the stateless PRF seed. Bundling them keeps
/// `sign_stateless_wots_c` within the positional-argument limit.
struct WotsSeeds<'a> {
    pk_seed: &'a [u8; HASH_LEN],
    sk_seed: &'a [u8; HASH_LEN],
    prf_seed: &'a [u8; HASH_LEN],
}

struct HypertreeSubtree {
    root: [u8; HASH_LEN],
    selected_leaf_hash: [u8; HASH_LEN],
    auth_path: Vec<[u8; HASH_LEN]>,
}

pub(crate) fn sign_hypertree(
    signing_key: &Key,
    fors_root: [u8; HASH_LEN],
    bottom_tree: u64,
    bottom_leaf: u32,
) -> Option<Vec<HypertreeLayerSignature>> {
    if stateless_trace_enabled() {
        hashsigs_println!(
            "stateless trace: hypertree start bottom_tree={} bottom_leaf={} layers={}",
            bottom_tree,
            bottom_leaf,
            NUM_HYPERTREE_LAYERS
        );
    }
    // Layer 0 starts at the FORS-selected coordinate. Every higher layer must
    // follow the verifier's recurrence, so the signature cannot choose arbitrary
    // upper-layer tree/leaf positions.
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    // Mirror the verifier's guard so a retuned profile fails closed instead of
    // panicking on the shift below.
    if subtree_height == 0 || subtree_height >= u32::BITS {
        return None;
    }
    let leaf_mask = (1u64 << subtree_height) - 1;
    // `stateless_sk_seed` is the shared SK.seed-style master for FORS-C and
    // hypertree WOTS-C signing secrets.
    // `pk_seed` is the global public seed used for stateless hashing.
    let layer_seeds = hypertree_layer_seeds(signing_key.secret.sk_seed.as_bytes());
    let mut layers = Vec::with_capacity(NUM_HYPERTREE_LAYERS as usize);

    // `current` is the value being authenticated by the current layer. At layer
    // 0 it is the FORS aggregate root. After each layer, it becomes that layer's
    // subtree root, which the next layer signs.
    let mut current = fors_root;
    let mut tree = bottom_tree;
    let mut leaf = bottom_leaf;

    for layer in 0..u32::from(NUM_HYPERTREE_LAYERS) {
        if stateless_trace_enabled() {
            hashsigs_println!(
                "stateless trace: hypertree layer={} tree={} leaf={}",
                layer, tree, leaf
            );
        }
        // Build the whole subtree once, then reuse the selected leaf hash for
        // signing and extract the auth path and next root from the same node
        // table instead of recomputing them separately.
        let subtree = hypertree_subtree(
            signing_key.public_key.pk_seed.as_bytes(),
            &layer_seeds[layer as usize],
            layer,
            tree,
            leaf,
        )?;
        let coords = WotsKeypair { layer, tree, keypair: leaf };
        let (_, sk_seed) = hypertree_leaf_seeds(&layer_seeds[layer as usize], tree, leaf);
        let seeds = WotsSeeds {
            pk_seed: signing_key.public_key.pk_seed.as_bytes(),
            sk_seed: &sk_seed,
            prf_seed: signing_key.secret.prf_seed.as_bytes(),
        };
        let wots_c_signature =
            sign_stateless_wots_c(&seeds, &coords, &subtree.selected_leaf_hash, &current)?;

        // The auth path proves that this WOTS public-key hash belongs to the
        // current layer's XMSS-like subtree at `tree`.
        let auth_path = subtree.auth_path;

        // Compute the subtree root that the next hypertree layer must sign. This
        // is also what the verifier obtains after it applies the auth path.
        current = subtree.root;
        // The tree/leaf coordinates are fully derived by the verifier (layer 0
        // from the FORS digest, upper layers by the recurrence below), so they
        // are not serialized into the signature.
        layers.push(HypertreeLayerSignature {
            wots_c_pk_hash: subtree.selected_leaf_hash,
            wots_c_signature,
            auth_path,
        });

        // Production recurrence used by the verifier: each upper-layer coordinate
        // is derived from the lower layer's tree index.
        //
        // For an 8-bit subtree, this is exactly:
        // next_leaf_index = current_tree_index & 0xff because height of subtree = 8
        // next_tree_index = current_tree_index >> 8
        leaf = (tree & leaf_mask) as u32;
        tree >>= subtree_height;
    }
    if stateless_trace_enabled() {
        hashsigs_println!("stateless trace: hypertree complete");
    }
    Some(layers)
}

pub(crate) fn hypertree_public_root(
    stateless_sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // With a 64-bit hypertree split into eight 8-bit layers, the layer-0 tree
    // coordinate is fully consumed by the top layer. The top tree index is
    // therefore zero for the public root.
    //A full bottom-layer position needs 64 bits: [ L7 ][ L6 ][ L5 ][ L4 ][ L3 ][ L2 ][ L1 ][ L0 ]
    // Lowest layer has 2^64/2^8 = 2^56 subtrees so 7 of 8 bits are used for the tree index
    let layer_seeds = hypertree_layer_seeds(stateless_sk_seed);
    let top_layer = u32::from(NUM_HYPERTREE_LAYERS - 1);
    match hypertree_subtree(pk_seed, &layer_seeds[top_layer as usize], top_layer, 0, 0) {
        Some(subtree) => subtree.root,
        None => {
            // Internal invariant: leaf 0 is always in range for the top-layer
            // subtree rooted at tree index 0, so this path should be unreachable.
            [0u8; HASH_LEN]
        }
    }
}

fn hypertree_layer_seeds(
    stateless_sk_seed: &[u8; HASH_LEN],
) -> [[u8; HASH_LEN]; NUM_HYPERTREE_LAYERS as usize] {
    // One seed per hypertree layer keeps the subtrees domain-separated while
    // still deriving the entire stateless tree from one SK.seed-style seed.
    let mut seeds = [[0u8; HASH_LEN]; NUM_HYPERTREE_LAYERS as usize];
    for (layer, seed) in seeds.iter_mut().enumerate() {
        *seed = derive32(b"hypertree-layer-seed", stateless_sk_seed, &[layer as u8]);
    }
    seeds
}

fn hypertree_subtree(
    pk_seed: &[u8; HASH_LEN],
    layer_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    selected_leaf: u32,
) -> Option<HypertreeSubtree> {
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    if subtree_height == 0 || subtree_height >= u32::BITS {
        return None;
    }
    let leaf_count = 1u32 << subtree_height;
    if selected_leaf >= leaf_count {
        return None;
    }

    // Generate the selected leaf once so the returned hash matches the value
    // folded into the tree (same leaf secret derivation path).
    let selected_leaf_hash = hypertree_leaf(pk_seed, layer_seed, layer, tree, selected_leaf);

    let (root, auth_path) = crate::primitives::treehash::treehash_root_and_auth_path(
        subtree_height,
        selected_leaf,
        |leaf| {
            if leaf == selected_leaf {
                selected_leaf_hash
            } else {
                hypertree_leaf(pk_seed, layer_seed, layer, tree, leaf)
            }
        },
        |node_height, parent_index, left, right| {
            let address_word = hypertree_address_word(layer, tree, node_height, parent_index);
            hash_node(&[
                b"hypertree-node".as_ref(),
                pk_seed.as_ref(),
                address_word.as_ref(),
                left.as_ref(),
                right.as_ref(),
            ])
        },
    );

    Some(HypertreeSubtree {
        root,
        selected_leaf_hash,
        auth_path,
    })
}

fn hypertree_leaf_seeds(
    layer_seed: &[u8; HASH_LEN],
    tree: u64,
    leaf: u32,
) -> (Zeroizing<[u8; HASH_LEN]>, Zeroizing<[u8; HASH_LEN]>) {
    let mut leaf_context = [0u8; 12];
    leaf_context[..8].copy_from_slice(&tree.to_be_bytes());
    leaf_context[8..].copy_from_slice(&leaf.to_be_bytes());
    let leaf_seed = Zeroizing::new(derive32(b"hypertree-leaf-seed", layer_seed, &leaf_context));
    let sk_seed = Zeroizing::new(derive32(b"hypertree-wots-sk-seed", &*leaf_seed, &[]));
    (leaf_seed, sk_seed)
}

fn hypertree_leaf(
    pk_seed: &[u8; HASH_LEN],
    layer_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    leaf: u32,
) -> [u8; HASH_LEN] {
    // A hypertree leaf is the public hash of the stateless WOTS-C keypair at this
    // coordinate. No per-leaf secret is stored; it is derived from `layer_seed`.
    // The derived seed and WOTS secret seed are zeroized on drop.
    let (_leaf_seed, sk_seed) = hypertree_leaf_seeds(layer_seed, tree, leaf);
    let coords = WotsKeypair {
        layer,
        tree,
        keypair: leaf,
    };
    stateless_wots_c_public_key(pk_seed, &sk_seed, &coords)
}

fn stateless_wots_c_public_key(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    coords: &WotsKeypair,
) -> [u8; HASH_LEN] {
    let chain_count = usize::from(NUM_WOTS_CHAINS);
    let endpoint_at = |chain: usize| -> [u8; HASH_LEN] {
        let secret = Zeroizing::new(stateless_wots_c_secret(sk_seed, chain as u32));
        stateless_wots_c_chain(
            pk_seed,
            &coords.chain(chain as u32),
            *secret,
            0,
            u32::from(WOTS_CHAIN_LEN - 1),
        )
    };

    #[cfg(feature = "parallel")]
    let endpoints: Vec<[u8; HASH_LEN]> = {
        use rayon::prelude::*;
        (0..chain_count).into_par_iter().map(endpoint_at).collect()
    };
    #[cfg(not(feature = "parallel"))]
    let endpoints: Vec<[u8; HASH_LEN]> = (0..chain_count).map(endpoint_at).collect();

    stateless_wots_public_key_hash(pk_seed, &endpoints)
}

fn sign_stateless_wots_c(
    seeds: &WotsSeeds,
    coords: &WotsKeypair,
    pk_hash: &[u8; HASH_LEN],
    message: &[u8; HASH_LEN],
) -> Option<WotsCSignature> {
    // The WOTS-C challenge signs the current root for this layer. The expected
    // WOTS public-key hash is included in the digest, binding the challenge to
    // the key whose Merkle path is supplied next.
    let randomizer = hash_packed(&[b"wots-c-randomizer", seeds.prf_seed, message]);
    let digest_bytes = wots_digest_bytes();

    let result = crate::primitives::wotsplusc::grind_digit_sum(
        WOTS_C_MAX_GRIND_COUNTER,
        WOTS_TARGET_SUM_STATELESS,
        |counter| {
            let digest = stateless_wots_message_digest(
                seeds.pk_seed,
                pk_hash,
                &randomizer,
                counter,
                message,
            );
            let digest = &digest[..digest_bytes];
            let mut digits = Vec::with_capacity(NUM_WOTS_CHAINS as usize);
            let mut digit_sum = 0u32;
            for index in 0..NUM_WOTS_CHAINS as usize {
                let value = base_w_digit(WOTS_CHAIN_LEN, digest, index);
                digit_sum = digit_sum.checked_add(value)?;
                digits.push(value);
            }
            Some((digit_sum, digits))
        },
        |digits| {
            let chain_at = |chain: usize, digit: u32| -> [u8; HASH_LEN] {
                let secret = Zeroizing::new(stateless_wots_c_secret(seeds.sk_seed, chain as u32));
                stateless_wots_c_chain(
                    seeds.pk_seed,
                    &coords.chain(chain as u32),
                    *secret,
                    0,
                    digit,
                )
            };

            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                digits
                    .par_iter()
                    .enumerate()
                    .map(|(chain, digit)| chain_at(chain, *digit))
                    .collect()
            }
            #[cfg(not(feature = "parallel"))]
            {
                digits
                    .iter()
                    .enumerate()
                    .map(|(chain, digit)| chain_at(chain, *digit))
                    .collect()
            }
        },
    )?;
    let (counter, chains) = result;
    Some(WotsCSignature {
        randomizer,
        counter,
        chains,
    })
}

fn stateless_wots_c_secret(sk_seed: &[u8; HASH_LEN], chain: u32) -> [u8; HASH_LEN] {
    // Each chain gets an independent starting secret derived from the WOTS secret
    // seed and the chain number.
    hash_packed(&[b"wots-c-secret", sk_seed, &chain.to_be_bytes()])
}

fn stateless_wots_c_chain(
    pk_seed: &[u8; HASH_LEN],
    coords: &WotsChain,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let ctx = wotsplusc::StatelessWotsChainCtx {
        pk_seed,
        layer: coords.layer,
        tree: coords.tree,
        keypair: coords.keypair,
        chain_index: coords.chain,
    };
    wotsplusc::stateless_wots_chain(
        &ctx,
        wotsplusc::ChainWalk {
            value,
            start,
            steps,
        },
    )
}
