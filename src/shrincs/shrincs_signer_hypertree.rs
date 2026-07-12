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

use super::shrincs_signer_types::{ShrincsSignerResult, ShrincsSigningKey};
use super::shrincs_signer_utils::{
    address_word32, base_w_digit, derive32, hash_node, hash_packed, hypertree_address_word,
    wots_digest_bytes, WOTS_C_MAX_GRIND_COUNTER,
};
use super::verifier::{
    HypertreeLayerSignature, WotsCSignature, HASH_LEN, HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS,
    NUM_WOTS_CHAINS, WOTS_CHAIN_LEN, WOTS_TARGET_SUM_STATEFUL,
};

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
        // Each WOTS keypair is derived from its exact coordinate. This makes the
        // stateless hypertree deterministic without storing every WOTS secret.
        let leaf_seed = derive32(
            b"hypertree-leaf-seed",
            &layer_seeds[layer as usize],
            &[tree.to_be_bytes().as_slice(), leaf.to_be_bytes().as_slice()].concat(),
        );
        let sk_seed = derive32(b"hypertree-wots-sk-seed", &leaf_seed, &[]);

        // The WOTS public-key hash is the Merkle leaf for this coordinate. It is
        // included in the layer signature so the verifier can bind the WOTS-C
        // chain reconstruction to the auth path that follows.
        let pk_hash =
            stateless_wots_c_public_key(&signing_key.pk_seed, &sk_seed, layer, tree, leaf);
        let wots_c_signature = sign_stateless_wots_c(
            &signing_key.pk_seed,
            &sk_seed,
            &signing_key.stateless_prf_seed,
            &pk_hash,
            layer,
            tree,
            leaf,
            &current,
        )?;

        // The auth path proves that this WOTS public-key hash belongs to the
        // current layer's XMSS-like subtree at `tree`.
        let auth_path = hypertree_auth_path(
            &signing_key.pk_seed,
            &layer_seeds[layer as usize],
            layer,
            tree,
            leaf,
        );

        // Compute the subtree root that the next hypertree layer must sign. This
        // is also what the verifier obtains after it applies the auth path.
        current = hypertree_virtual_node(
            &signing_key.pk_seed,
            &layer_seeds[layer as usize],
            layer,
            tree,
            subtree_height,
            0,
        );
        // The tree/leaf coordinates are fully derived by the verifier (layer 0
        // from the FORS digest, upper layers by the recurrence below), so they
        // are not serialized into the signature.
        layers.push(HypertreeLayerSignature {
            wots_c_pk_hash: pk_hash.to_vec(),
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
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    hypertree_virtual_node(
        pk_seed,
        &layer_seeds[top_layer as usize],
        top_layer,
        0,
        subtree_height,
        0,
    )
}

fn hypertree_layer_seeds(stateless_sk_seed: &[u8; HASH_LEN]) -> Vec<[u8; HASH_LEN]> {
    // One seed per hypertree layer keeps the subtrees domain-separated while
    // still deriving the entire stateless tree from one SK.seed-style seed.
    (0..NUM_HYPERTREE_LAYERS)
        .map(|layer| derive32(b"hypertree-layer-seed", stateless_sk_seed, &[layer]))
        .collect()
}

fn hypertree_virtual_node(
    pk_seed: &[u8; HASH_LEN],
    layer_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    height: u32,
    index: u32,
) -> [u8; HASH_LEN] {
    // This recursively materializes a virtual subtree root. The implementation is
    // simple and reviewable for the current small per-layer height; a production
    // signer can cache nodes if signing throughput later becomes important.
    if height == 0 {
        return hypertree_leaf(pk_seed, layer_seed, layer, tree, index);
    }
    let left = hypertree_virtual_node(pk_seed, layer_seed, layer, tree, height - 1, index << 1);
    let right_index = (index << 1) | 1;
    let right = hypertree_virtual_node(pk_seed, layer_seed, layer, tree, height - 1, right_index);
    let address_word = hypertree_address_word(layer, tree, height, u64::from(index));
    hash_node(&[b"hypertree-node", pk_seed, &address_word, &left, &right])
}

fn hypertree_auth_path(
    pk_seed: &[u8; HASH_LEN],
    layer_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    leaf: u32,
) -> Vec<Vec<u8>> {
    // Collect siblings from the signed leaf up to the subtree root. At level 0
    // the sibling is another WOTS public-key hash; at higher levels it is the
    // root of a virtual subtree of height `level`.
    let subtree_height = u32::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
    (0..subtree_height)
        .map(|level| {
            let sibling = (leaf >> level) ^ 1;
            hypertree_virtual_node(pk_seed, layer_seed, layer, tree, level, sibling).to_vec()
        })
        .collect()
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
    let leaf_seed = derive32(
        b"hypertree-leaf-seed",
        layer_seed,
        &[tree.to_be_bytes().as_slice(), leaf.to_be_bytes().as_slice()].concat(),
    );
    let sk_seed = derive32(b"hypertree-wots-sk-seed", &leaf_seed, &[]);
    stateless_wots_c_public_key(pk_seed, &sk_seed, layer, tree, leaf)
}

fn stateless_wots_c_public_key(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    keypair: u32,
) -> [u8; HASH_LEN] {
    // Build every WOTS chain all the way to its endpoint, then hash the endpoints
    // together. That aggregate hash is the Merkle leaf used by the hypertree.
    let mut endpoints = Vec::with_capacity(NUM_WOTS_CHAINS as usize * HASH_LEN);
    for chain in 0..NUM_WOTS_CHAINS {
        let secret = stateless_wots_c_secret(sk_seed, u32::from(chain));
        let endpoint = stateless_wots_c_chain(
            pk_seed,
            layer,
            tree,
            keypair,
            u32::from(chain),
            secret,
            0,
            u32::from(WOTS_CHAIN_LEN - 1),
        );
        endpoints.extend_from_slice(&endpoint);
    }
    hash_node(&[b"wots-c-pk", pk_seed, &endpoints])
}

fn sign_stateless_wots_c(
    pk_seed: &[u8; HASH_LEN],
    sk_seed: &[u8; HASH_LEN],
    stateless_prf_seed: &[u8; HASH_LEN],
    pk_hash: &[u8; HASH_LEN],
    layer: u32,
    tree: u64,
    keypair: u32,
    message: &[u8; HASH_LEN],
) -> ShrincsSignerResult<WotsCSignature> {
    // The WOTS-C challenge signs the current root for this layer. The expected
    // WOTS public-key hash is included in the digest, binding the challenge to
    // the key whose Merkle path is supplied next.
    let randomizer = hash_packed(&[b"wots-c-randomizer", stateless_prf_seed, message]);
    let digest_bytes = wots_digest_bytes();

    for counter in 0..WOTS_C_MAX_GRIND_COUNTER {
        // The verifier derives the same digits from this digest. Grinding keeps
        // only counters whose base-w digits sum to the configured target, which
        // replaces the usual WOTS+ checksum field in this compact variant.
        let digest = hash_packed(&[
            b"wots-c-msg",
            pk_seed,
            pk_hash,
            &randomizer,
            &counter.to_be_bytes(),
            message,
        ]);
        let digest = &digest[..digest_bytes];
        let digits = (0..NUM_WOTS_CHAINS as usize)
            .map(|index| base_w_digit(WOTS_CHAIN_LEN, digest, index))
            .collect::<Vec<_>>();
        if digits.iter().sum::<u32>() != WOTS_TARGET_SUM_STATEFUL {
            continue;
        }

        let chains = digits
            .iter()
            .enumerate()
            .map(|(chain, digit)| {
                // A signature chain stops at the selected digit. The verifier
                // continues the chain from that digit to the endpoint and checks
                // that the reconstructed public-key hash matches `pk_hash`.
                let secret = stateless_wots_c_secret(sk_seed, chain as u32);
                stateless_wots_c_chain(
                    pk_seed,
                    layer,
                    tree,
                    keypair,
                    chain as u32,
                    secret,
                    0,
                    *digit,
                )
                .to_vec()
            })
            .collect();
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
    layer: u32,
    tree: u64,
    keypair: u32,
    chain: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    // Advance a WOTS chain through address-bound Keccak steps. `start` is the
    // current digit position and `steps` is how far to move from there.
    let mut out = value;
    for step in start..start + steps {
        let address_word = address_word32(layer, tree, 0, keypair, chain, step);
        out = hash_node(&[b"wots-c-chain", pk_seed, &address_word, &out]);
    }
    out
}
