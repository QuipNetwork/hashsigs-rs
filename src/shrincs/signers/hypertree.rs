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

//! Hypertree and stateless WOTS-C signing.

use zeroize::Zeroizing;

use super::super::components::hash::hypertree_address_word;
use super::super::components::hypertree;
use super::types::{ShrincsSignerResult, ShrincsSigningKey};
use super::utils::{
    base_w_digit, derive32, hash_node, hash_packed, wots_digest_bytes, WOTS_C_MAX_GRIND_COUNTER,
};
use super::super::types::{HypertreeLayerSignature, WotsCSignature, HASH_LEN};
use super::super::profiles::{
    HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN,
    WOTS_TARGET_SUM_STATELESS,
};

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
    auth_path: Vec<Vec<u8>>,
}

pub(crate) fn sign_hypertree(
    signing_key: &ShrincsSigningKey,
    fors_root: [u8; HASH_LEN],
    bottom_tree: u64,
    bottom_leaf: u32,
) -> ShrincsSignerResult<Vec<HypertreeLayerSignature>> {
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
    let layer_seeds = hypertree_layer_seeds(&signing_key.stateless_sk_seed);
    let mut layers = Vec::with_capacity(NUM_HYPERTREE_LAYERS as usize);

    // `current` is the value being authenticated by the current layer. At layer
    // 0 it is the FORS aggregate root. After each layer, it becomes that layer's
    // subtree root, which the next layer signs.
    let mut current = fors_root;
    let mut tree = bottom_tree;
    let mut leaf = bottom_leaf;

    for layer in 0..u32::from(NUM_HYPERTREE_LAYERS) {
        // Build the whole subtree once, then reuse the selected leaf hash for
        // signing and extract the auth path and next root from the same node
        // table instead of recomputing them separately.
        let subtree = hypertree_subtree(
            &signing_key.pk_seed,
            &layer_seeds[layer as usize],
            layer,
            tree,
            leaf,
        )?;
        let coords = WotsKeypair { layer, tree, keypair: leaf };
        let (_, sk_seed) = hypertree_leaf_seeds(&layer_seeds[layer as usize], tree, leaf);
        let seeds = WotsSeeds {
            pk_seed: &signing_key.pk_seed,
            sk_seed: &sk_seed,
            prf_seed: &signing_key.stateless_prf_seed,
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
            wots_c_pk_hash: subtree.selected_leaf_hash.to_vec(),
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

fn hypertree_layer_seeds(stateless_sk_seed: &[u8; HASH_LEN]) -> Vec<[u8; HASH_LEN]> {
    // One seed per hypertree layer keeps the subtrees domain-separated while
    // still deriving the entire stateless tree from one SK.seed-style seed.
    (0..NUM_HYPERTREE_LAYERS)
        .map(|layer| derive32(b"hypertree-layer-seed", stateless_sk_seed, &[layer]))
        .collect()
}

fn hypertree_subtree(
    pk_seed: &[u8; HASH_LEN],
    layer_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    selected_leaf: u32,
) -> Option<HypertreeSubtree> {
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    let leaf_count = 1usize << subtree_height;
    if selected_leaf as usize >= leaf_count {
        return None;
    }
    let mut current_level = Vec::with_capacity(leaf_count);
    for leaf in 0..leaf_count as u32 {
        current_level.push(hypertree_leaf(pk_seed, layer_seed, layer, tree, leaf));
    }

    let selected_leaf_hash = current_level[selected_leaf as usize];
    let mut auth_path = Vec::with_capacity(subtree_height as usize);
    let mut index = selected_leaf as usize;

    for node_height in 1..=subtree_height {
        auth_path.push(current_level[index ^ 1].to_vec());
        let mut parents = Vec::with_capacity(current_level.len() / 2);
        for (parent_index, pair) in current_level.chunks_exact(2).enumerate() {
            let address_word = hypertree_address_word(layer, tree, node_height, parent_index as u64);
            parents.push(hash_node(&[
                b"hypertree-node".as_ref(),
                pk_seed.as_ref(),
                address_word.as_ref(),
                pair[0].as_ref(),
                pair[1].as_ref(),
            ]));
        }
        current_level = parents;
        index >>= 1;
    }

    Some(HypertreeSubtree {
        root: current_level[0],
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
    let mut endpoints = Vec::with_capacity(NUM_WOTS_CHAINS as usize);
    for chain in 0..NUM_WOTS_CHAINS {
        let secret = Zeroizing::new(stateless_wots_c_secret(sk_seed, u32::from(chain)));
        let endpoint = stateless_wots_c_chain(
            pk_seed,
            &coords.chain(u32::from(chain)),
            *secret,
            0,
            u32::from(WOTS_CHAIN_LEN - 1),
        );
        endpoints.push(endpoint);
    }
    hypertree::stateless_wots_public_key_hash(pk_seed, &endpoints)
}

fn sign_stateless_wots_c(
    seeds: &WotsSeeds,
    coords: &WotsKeypair,
    pk_hash: &[u8; HASH_LEN],
    message: &[u8; HASH_LEN],
) -> ShrincsSignerResult<WotsCSignature> {
    // The WOTS-C challenge signs the current root for this layer. The expected
    // WOTS public-key hash is included in the digest, binding the challenge to
    // the key whose Merkle path is supplied next.
    let randomizer = hash_packed(&[b"wots-c-randomizer", seeds.prf_seed, message]);
    let digest_bytes = wots_digest_bytes();

    for counter in 0..WOTS_C_MAX_GRIND_COUNTER {
        // The verifier derives the same digits from this digest. Grinding keeps
        // only counters whose base-w digits sum to the configured target, which
        // replaces the usual WOTS+ checksum field in this compact variant.
        let digest = hypertree::stateless_wots_message_digest(
            seeds.pk_seed,
            pk_hash,
            &randomizer,
            counter,
            message,
        );
        let digest = &digest[..digest_bytes];
        let mut digits = [0u32; NUM_WOTS_CHAINS as usize];
        let mut digit_sum = 0u32;
        for (index, digit) in digits.iter_mut().enumerate() {
            let value = base_w_digit(WOTS_CHAIN_LEN, digest, index);
            *digit = value;
            digit_sum += value;
        }
        if digit_sum != WOTS_TARGET_SUM_STATELESS {
            continue;
        }

        let mut chains = Vec::with_capacity(NUM_WOTS_CHAINS as usize);
        for (chain, digit) in digits.iter().enumerate() {
            // A signature chain stops at the selected digit. The verifier
            // continues the chain from that digit to the endpoint and checks
            // that the reconstructed public-key hash matches `pk_hash`.
            // The chain start is private WOTS material; zeroize it on drop.
            let secret = Zeroizing::new(stateless_wots_c_secret(seeds.sk_seed, chain as u32));
            chains.push(
                stateless_wots_c_chain(
                    seeds.pk_seed,
                    &coords.chain(chain as u32),
                    *secret,
                    0,
                    *digit,
                )
                .to_vec(),
            );
        }
        return Some(WotsCSignature {
            randomizer: randomizer.to_vec(),
            counter,
            chains,
        });
    }

    None
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
    let ctx = hypertree::StatelessWotsChainCtx {
        pk_seed,
        layer: coords.layer,
        tree: coords.tree,
        keypair: coords.keypair,
        chain_index: coords.chain,
    };
    hypertree::stateless_wots_chain(
        &ctx,
        value,
        start,
        steps,
    )
}
