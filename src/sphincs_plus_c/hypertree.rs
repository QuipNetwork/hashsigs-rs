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

//! Stateless hypertree sign and verify, plus the hypertree layer signature
//! wire type and its ABI codec.
//!
//! Carries a FORS-C root up through `NUM_HYPERTREE_LAYERS` WOTS-C-authenticated
//! subtrees to the pinned hypertree root, mirroring Solidity's `Hypertree.sol`.
//! Sits above `wots_c` and `treehash` in the DAG and is consumed by
//! `sphincs_plus_c` to assemble a full stateless signature.
//!
//! `LayerSignature::to_bytes`/`from_bytes` are byte-identical to the
//! historical `envelope::encode_hypertree_layer_body`/
//! `decode_hypertree_layer_signature`, which now delegate here.

use alloc::vec::Vec;

use super::key::Key;
use crate::abi::{
    collect_hash_words, encode_bytes, encode_dynamic_array, encode_tuple, AbiReader, Field,
};
use crate::hash::{
    base_w_digit, derive32, hash_node, hash_packed, hypertree_address_word, word32,
    wots_address_base, wots_chain_address_word, wots_digest_bytes,
};
use crate::profiles::{HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN};
use crate::wots_c::{wots_chain_walk, ChainWalk, Signature, TARGET_SUM, WOTS_C_MAX_GRIND_COUNTER};
use crate::HASH_LEN;
use zeroize::Zeroizing;

/// Hypertree subtree height: one auth-path node per level per layer. Matches
/// the historical `envelope::HYPERTREE_SUBTREE_HEIGHT`, moved here with the
/// codec it bounds.
const HYPERTREE_SUBTREE_HEIGHT: usize =
    (HYPERTREE_HEIGHT as usize) / (NUM_HYPERTREE_LAYERS as usize);

/// One hypertree layer's signature: the WOTS-C signature proving
/// `current_root -> wots_c_pk_hash`, plus the Merkle auth path from
/// `wots_c_pk_hash` up to the next layer's root.
///
/// Kept `pub` (rather than `pub(crate)`) because it is part of the crate's
/// public wire-type surface: the `tests/` integration suite and the `solana`
/// workspace member reconstruct it from their DTOs, importing it at its
/// canonical path `crate::sphincs_plus_c::LayerSignature` (they alias it
/// locally as `HypertreeLayerSignature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerSignature {
    /// Expected WOTS-C public-key hash for this layer.
    pub wots_c_pk_hash: [u8; HASH_LEN],
    /// WOTS-C signature proving `current_root -> wots_c_pk_hash`.
    pub wots_c_signature: Signature,
    /// Merkle path from `wots_c_pk_hash` to the next layer root.
    pub auth_path: Vec<[u8; HASH_LEN]>,
}

impl LayerSignature {
    /// ABI-encode the hypertree layer signature body. Byte-identical to the
    /// historical `envelope::encode_hypertree_layer_body`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![
            Field::Dynamic(encode_bytes(&self.wots_c_pk_hash)),
            Field::Dynamic(self.wots_c_signature.to_bytes()),
            Field::Dynamic(encode_dynamic_array(
                self.auth_path
                    .iter()
                    .map(|node| encode_bytes(node))
                    .collect(),
            )),
        ])
    }

    /// Decode a hypertree layer signature already located at `base` within a
    /// shared `AbiReader`. No trailing-bytes check here: `base` commonly sits
    /// inside a larger encoded envelope, so exhaustion is the calling
    /// top-level decoder's responsibility (see `from_bytes` for the
    /// standalone entrypoint that does check).
    pub(crate) fn decode(reader: &AbiReader, base: usize) -> Option<Self> {
        let wots_head = base.checked_add(32)?;
        let wots_start = reader.decode_offset(base, wots_head)?;
        Some(Self {
            wots_c_pk_hash: reader.decode_bytes32_field(base, base)?,
            wots_c_signature: Signature::decode(reader, wots_start)?,
            auth_path: collect_hash_words(reader.decode_array_bytes(
                base,
                base.checked_add(64)?,
                HYPERTREE_SUBTREE_HEIGHT,
            )?)?,
        })
    }

    /// Decode a standalone byte blob produced by `to_bytes`. Byte-identical
    /// to the historical `envelope::decode_hypertree_layer_signature`, built
    /// as a top-level entrypoint: a fresh `AbiReader` at base 0, rejecting
    /// trailing bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let reader = AbiReader::new(data);
        let decoded = Self::decode(&reader, 0)?;
        reader.finish()?;
        Some(decoded)
    }
}

impl TryFrom<&[u8]> for LayerSignature {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

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
    layers: &[LayerSignature],
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
    signature: &Signature,
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
    if digit_sum != TARGET_SUM {
        return false;
    }

    // Pass 2 (expensive): walk each chain to its endpoint, writing into a
    // fixed-capacity segment buffer (stack by default, Solana heap — see
    // `buf`). Chain order must match the signer's so the pk-hash preimage is
    // byte-identical, which is why segments are stored in index order.
    let mut segments = crate::buf::node_buf::<{ NUM_WOTS_CHAINS as usize }>();
    let segment_at = |chain_index: usize| -> Option<[u8; HASH_LEN]> {
        let chain_value = signature.chains.get(chain_index).copied()?;
        Some(wots_chain32_no_mask_base(
            WOTS_CHAIN_LEN,
            *pk_seed,
            AddressBaseChain {
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

/// Precomputed address base plus chain index for a stateless chain walk.
#[derive(Clone, Copy)]
struct AddressBaseChain {
    address_base: [u8; HASH_LEN],
    chain_index: u32,
}

/// Stateless hypertree WOTS-C chain walk (`b"wots-c-chain"` + ADRS word).
fn stateless_wots_chain_from_address_base(
    pk_seed: &[u8; HASH_LEN],
    addr: AddressBaseChain,
    walk: ChainWalk,
) -> [u8; HASH_LEN] {
    wots_chain_walk(
        b"wots-c-chain",
        pk_seed,
        |step| wots_chain_address_word(addr.address_base, addr.chain_index, step),
        walk,
    )
}

fn wots_chain32_no_mask_base(
    w: u16,
    pk_seed: [u8; HASH_LEN],
    addr: AddressBaseChain,
    value: [u8; HASH_LEN],
    digit: u32,
) -> [u8; HASH_LEN] {
    let steps = u32::from(w - 1) - digit;
    stateless_wots_chain_from_address_base(
        &pk_seed,
        addr,
        ChainWalk {
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
    crate::treehash::root_from_auth_path(
        height,
        path.leaf_index,
        leaf,
        auth_path,
        |level, parent_index, left, right| {
            let address_word =
                hypertree_address_word(path.layer, path.tree_index, level, u64::from(parent_index));
            hash_node(&[
                b"hypertree-node".as_ref(),
                pk_seed.as_ref(),
                address_word.as_ref(),
                left.as_ref(),
                right.as_ref(),
            ])
        },
    )
}

// ---- signing ----

use crate::trace_macros::stateless_trace_enabled;

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
) -> Option<Vec<LayerSignature>> {
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
    let layer_seeds = hypertree_layer_seeds(signing_key.secret().as_sk_seed().as_bytes());
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
                layer,
                tree,
                leaf
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
        let coords = WotsKeypair {
            layer,
            tree,
            keypair: leaf,
        };
        let (_, sk_seed) = hypertree_leaf_seeds(&layer_seeds[layer as usize], tree, leaf);
        let seeds = WotsSeeds {
            pk_seed: signing_key.public_key.pk_seed.as_bytes(),
            sk_seed: &sk_seed,
            prf_seed: signing_key.secret().as_prf_seed().as_bytes(),
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
        layers.push(LayerSignature {
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

    let (root, auth_path) = crate::treehash::treehash_root_and_auth_path(
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

/// Builds a `Vec` of length `n` where element `i` is `f(i)`, collected in
/// index order. Runs the per-element work in parallel via rayon when the
/// `parallel` feature is enabled, sequentially otherwise; either way the
/// result order is identical since collection is always by index.
#[cfg(feature = "parallel")]
fn map_chains<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
    use rayon::prelude::*;
    (0..n).into_par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
fn map_chains<T>(n: usize, f: impl Fn(usize) -> T) -> Vec<T> {
    (0..n).map(f).collect()
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

    let endpoints: Vec<[u8; HASH_LEN]> = map_chains(chain_count, endpoint_at);

    stateless_wots_public_key_hash(pk_seed, &endpoints)
}

fn sign_stateless_wots_c(
    seeds: &WotsSeeds,
    coords: &WotsKeypair,
    pk_hash: &[u8; HASH_LEN],
    message: &[u8; HASH_LEN],
) -> Option<Signature> {
    // The WOTS-C challenge signs the current root for this layer. The expected
    // WOTS public-key hash is included in the digest, binding the challenge to
    // the key whose Merkle path is supplied next.
    let randomizer = hash_packed(&[b"wots-c-randomizer", seeds.prf_seed, message]);
    let digest_bytes = wots_digest_bytes();

    let result = crate::wots_c::grind_digit_sum(
        WOTS_C_MAX_GRIND_COUNTER,
        TARGET_SUM,
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

            map_chains(digits.len(), |chain| chain_at(chain, digits[chain]))
        },
    )?;
    let (counter, chains) = result;
    Some(Signature {
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

/// ADRS coordinates for one stateless WOTS-C chain step-walk.
struct StatelessWotsChainCtx<'a> {
    pk_seed: &'a [u8; HASH_LEN],
    layer: u32,
    tree: u64,
    keypair: u32,
    chain_index: u32,
}

/// Stateless hypertree WOTS-C chain walk with full ADRS coordinates.
fn stateless_wots_chain(ctx: &StatelessWotsChainCtx<'_>, walk: ChainWalk) -> [u8; HASH_LEN] {
    use crate::hash::{address_word32, AddressWord32};
    wots_chain_walk(
        b"wots-c-chain",
        ctx.pk_seed,
        |step| {
            address_word32(AddressWord32 {
                layer: ctx.layer,
                tree: ctx.tree,
                address_type: 0,
                keypair: ctx.keypair,
                chain: ctx.chain_index,
                step,
            })
        },
        walk,
    )
}

fn stateless_wots_c_chain(
    pk_seed: &[u8; HASH_LEN],
    coords: &WotsChain,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let ctx = StatelessWotsChainCtx {
        pk_seed,
        layer: coords.layer,
        tree: coords.tree,
        keypair: coords.keypair,
        chain_index: coords.chain,
    };
    stateless_wots_chain(
        &ctx,
        ChainWalk {
            value,
            start,
            steps,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wots_c::Signature as WotsCSignature;
    use alloc::vec;

    fn sample_layer_signature() -> LayerSignature {
        LayerSignature {
            wots_c_pk_hash: [0xA1; HASH_LEN],
            wots_c_signature: WotsCSignature {
                randomizer: [0xA2; HASH_LEN],
                counter: 0x0C0F_FEEDu32,
                chains: vec![[0xA3; HASH_LEN], [0xA4; HASH_LEN], [0xA5; HASH_LEN]],
            },
            // Any length up to HYPERTREE_SUBTREE_HEIGHT is accepted by the
            // standalone codec; keep it short for a cheap unit fixture.
            auth_path: vec![[0xA6; HASH_LEN], [0xA7; HASH_LEN]],
        }
    }

    #[test]
    fn layer_signature_to_bytes_from_bytes_round_trips() {
        let layer = sample_layer_signature();
        let encoded = layer.to_bytes();
        let decoded = LayerSignature::from_bytes(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, layer);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn layer_signature_from_bytes_rejects_trailing_bytes() {
        let mut encoded = sample_layer_signature().to_bytes();
        encoded.push(0x00);
        assert!(
            LayerSignature::from_bytes(&encoded).is_none(),
            "trailing junk on a standalone layer body must be rejected"
        );
        encoded.pop();
        encoded.extend_from_slice(&[0xAA, 0xBB]);
        assert!(LayerSignature::from_bytes(&encoded).is_none());
    }

    #[test]
    fn layer_signature_from_bytes_rejects_truncated() {
        let encoded = sample_layer_signature().to_bytes();
        assert!(LayerSignature::from_bytes(&encoded[..encoded.len() - 1]).is_none());
        assert!(LayerSignature::from_bytes(&[]).is_none());
    }

    #[test]
    fn layer_signature_try_from_delegates_to_from_bytes() {
        let layer = sample_layer_signature();
        let encoded = layer.to_bytes();
        let decoded =
            LayerSignature::try_from(encoded.as_slice()).expect("valid encoding must decode");
        assert_eq!(decoded, layer);
        assert!(LayerSignature::try_from(&encoded[..encoded.len() - 1]).is_err());
    }

    /// Full hypertree sign→verify round-trip at a non-zero bottom leaf.
    /// Gated off the 128s profiles: a single-layer height-18 subtree is too
    /// large for a unit-test budget (same gate as `sphincs_plus_c` round-trip).
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn hypertree_sign_verify_round_trip() {
        let key =
            crate::sphincs_plus_c::keygen([0x11; HASH_LEN], [0x22; HASH_LEN], [0x33; HASH_LEN]);
        let fors_root = [0xABu8; HASH_LEN];
        let seed = HypertreeSeed {
            tree_index: 0,
            leaf_index: 3,
        };
        let layers = sign_hypertree(&key, fors_root, seed.tree_index, seed.leaf_index)
            .expect("hypertree sign must succeed");
        assert_eq!(layers.len(), NUM_HYPERTREE_LAYERS as usize);
        for layer in &layers {
            assert_eq!(layer.auth_path.len(), HYPERTREE_SUBTREE_HEIGHT);
            // Each layer body must be a self-contained, trailing-clean blob.
            let encoded = layer.to_bytes();
            let decoded = LayerSignature::from_bytes(&encoded).expect("layer codec");
            assert_eq!(decoded, *layer);
        }
        assert!(
            verify_hypertree(
                key.public_key.pk_seed.as_bytes(),
                key.public_key.root.as_bytes(),
                fors_root,
                seed,
                &layers,
            ),
            "fresh hypertree signature must verify against keygen root"
        );
        // Wrong FORS root must not verify.
        assert!(!verify_hypertree(
            key.public_key.pk_seed.as_bytes(),
            key.public_key.root.as_bytes(),
            [0xCDu8; HASH_LEN],
            seed,
            &layers,
        ));
        // Wrong leaf index must not verify (auth path is leaf-bound).
        assert!(!verify_hypertree(
            key.public_key.pk_seed.as_bytes(),
            key.public_key.root.as_bytes(),
            fors_root,
            HypertreeSeed {
                tree_index: seed.tree_index,
                leaf_index: seed.leaf_index ^ 1,
            },
            &layers,
        ));
    }

    #[test]
    fn verify_hypertree_rejects_wrong_layer_count() {
        let pk_seed = [0x01u8; HASH_LEN];
        let root = [0x02u8; HASH_LEN];
        let fors_root = [0x03u8; HASH_LEN];
        let seed = HypertreeSeed {
            tree_index: 0,
            leaf_index: 0,
        };
        // Empty layers: always wrong count for every profile.
        assert!(!verify_hypertree(&pk_seed, &root, fors_root, seed, &[]));
        // One too many synthetic layers.
        let extra = vec![sample_layer_signature(); NUM_HYPERTREE_LAYERS as usize + 1];
        assert!(!verify_hypertree(&pk_seed, &root, fors_root, seed, &extra));
    }
}
