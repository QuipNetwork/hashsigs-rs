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

//! Shared signer helpers.
//!
//! These helpers intentionally mirror the verifier's byte layout and hashing
//! rules, but they are kept separate so the signer does not depend on verifier
//! internals. If a helper here looks "too small," it usually exists because the
//! Solidity verifier encoded the same idea explicitly and we want the Rust
//! signer to make those byte-level choices visible.

use super::verifier::{
    PublicKey, HASH_LEN, NUM_WOTS_CHAINS, STATEFUL_PUBLIC_KEY_BYTES, WOTS_CHAIN_LEN,
};
use solana_program::keccak::hash as keccak256_hash;

pub(crate) const WOTS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
pub(crate) const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;

pub(crate) fn public_key_from_components(
    stateful_public_key: Vec<u8>,
    pk_seed: [u8; HASH_LEN],
    hypertree_root: [u8; HASH_LEN],
) -> PublicKey {
    let public_key_commitment =
        public_key_commitment(&stateful_public_key, &pk_seed, &hypertree_root);
    PublicKey {
        stateful_public_key,
        public_key_commitment: public_key_commitment.to_vec(),
        pk_seed: pk_seed.to_vec(),
        hypertree_root: hypertree_root.to_vec(),
    }
}

pub(crate) fn public_key_commitment(
    stateful_public_key: &[u8],
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"shrincs-public-key",
        stateful_public_key,
        pk_seed,
        hypertree_root,
    ])
}

pub(crate) fn encode_stateful_public_key(
    pk_seed: [u8; HASH_LEN],
    root: [u8; HASH_LEN],
    max_signatures: u32,
) -> Vec<u8> {
    // Keep this byte layout identical to `decode_stateful_public_key`:
    // pk_seed || root || max_signatures as big-endian u32.
    let mut out = Vec::with_capacity(STATEFUL_PUBLIC_KEY_BYTES);
    out.extend_from_slice(&pk_seed);
    out.extend_from_slice(&root);
    out.extend_from_slice(&max_signatures.to_be_bytes());
    out
}

pub(crate) fn derive32(domain: &[u8], seed: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    // Small deterministic KDF used only inside SHRINCS key generation. Domain
    // tags separate the different seeds derived from the same master input.
    hash_packed(&[domain, seed, data])
}

pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    // Use Solana's built-in Keccak entry point directly. This keeps the signer
    // aligned with on-chain code and avoids pulling in a second hash crate.
    keccak256_hash(data).to_bytes()
}

pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Solidity's `abi.encodePacked(...)` hashes a concatenation of byte slices.
    // Rust has no implicit packed ABI encoding, so callers pass the exact slices
    // in the same order and this helper performs the concatenation before Keccak.
    keccak256(&pack(parts))
}

pub(crate) fn pack(parts: &[&[u8]]) -> Vec<u8> {
    // Allocate once, then copy each field exactly once. Most call sites are tiny,
    // but avoiding repeated reallocations makes the byte layout easier to review.
    let len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn word32(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    // Convert verifier-provided byte vectors back into fixed hash words. Returning
    // `None` instead of padding/truncating prevents malformed keys from being
    // accidentally accepted by the signer.
    input.try_into().ok()
}

pub(crate) fn base_w16_digit(digest: &[u8; HASH_LEN], index: usize) -> u32 {
    // Base-16 stores two WOTS digits per byte. Even indices use the high nibble,
    // odd indices use the low nibble, matching the verifier's digit reader.
    let byte = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(byte >> 4)
    } else {
        u32::from(byte & 0x0f)
    }
}

pub(crate) fn base_w_digit(w: u16, digest: &[u8], index: usize) -> u32 {
    // Stateless WOTS-C supports the compiled chain length. Base-256
    // consumes one byte per digit; base-16 consumes one nibble per digit.
    if w == 256 {
        return u32::from(digest[index]);
    }
    let byte = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(byte >> 4)
    } else {
        u32::from(byte & 0x0f)
    }
}

pub(crate) fn wots_digest_bytes() -> usize {
    // The signer only needs enough digest bytes to cover the configured WOTS
    // digits. The counter grinding checks the digit sum after this truncation.
    let bits_per_digit = if WOTS_CHAIN_LEN == 256 { 8 } else { 4 };
    (NUM_WOTS_CHAINS as usize * bits_per_digit + 7) / 8
}

pub(crate) fn read_bits32(input: &[u8], start_bit: usize, bit_len: u32) -> Option<u32> {
    // FORS digest fields are bit-packed, not byte-aligned. These readers use
    // big-endian bit order so the signer chooses the same leaves as the verifier.
    if bit_len > 32 {
        return None;
    }
    read_bits(input, start_bit, bit_len).map(|value| value as u32)
}

pub(crate) fn read_bits64(input: &[u8], start_bit: usize, bit_len: u32) -> Option<u64> {
    if bit_len > 64 {
        return None;
    }
    read_bits(input, start_bit, bit_len)
}

fn read_bits(input: &[u8], start_bit: usize, bit_len: u32) -> Option<u64> {
    // Walk one bit at a time because the digest fields are bit-packed.
    // This is slower than word slicing but much harder to get subtly wrong.
    let mut out = 0u64;
    for bit in 0..bit_len as usize {
        let absolute = start_bit + bit;
        let byte = *input.get(absolute >> 3)?;
        let bit_in_byte = 7 - (absolute & 7);
        let shifted_out = out << 1;
        let bit = u64::from((byte >> bit_in_byte) & 1);
        out = shifted_out | bit;
    }
    Some(out)
}

pub(crate) fn address_word32(
    layer: u32,
    tree: u64,
    address_type: u32,
    keypair: u32,
    chain: u32,
    step: u32,
) -> [u8; HASH_LEN] {
    // SPHINCS-style address words bind each chain step to a precise location:
    // layer, tree, WOTS keypair/leaf, chain number, and chain step. Hashing the
    // address prevents a valid chain value from being replayed at another point.
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree.to_be_bytes());
    out[16..20].copy_from_slice(&address_type.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out[24..28].copy_from_slice(&chain.to_be_bytes());
    out[28..32].copy_from_slice(&step.to_be_bytes());
    out
}

pub(crate) fn fors_address_word(
    tree_index: u64,
    leaf_index: u32,
    node_height: u32,
    low_index: u64,
) -> [u8; HASH_LEN] {
    // FORS addresses live at layer 0 and use address type 3. `low_index` carries
    // either a leaf number or a parent number, while `node_height` says which one.
    let mut out = [0u8; HASH_LEN];
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&3u32.to_be_bytes());
    out[20..24].copy_from_slice(&leaf_index.to_be_bytes());
    let low = (u64::from(node_height) << 32) | low_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}

pub(crate) fn hypertree_address_word(
    layer: u32,
    tree_index: u64,
    node_height: u32,
    parent_index: u64,
) -> [u8; HASH_LEN] {
    // Hypertree internal nodes use address type 2. The low word again combines
    // node height and parent index so two equal child hashes at different levels
    // do not produce interchangeable parents.
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&2u32.to_be_bytes());
    let low = (u64::from(node_height) << 32) | parent_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}
