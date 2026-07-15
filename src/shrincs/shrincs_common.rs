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

//! Byte-layout helpers shared by the SHRINCS signer and verifier.
//!
//! Signer and verifier must agree byte-for-byte on hashing, packing, address
//! words, base-w digit reads, and bit-packed digest reads. These helpers used to
//! be duplicated between `shrincs_signer_utils` and `shrincs_verifier_utils`;
//! keeping one copy removes the risk of the two sides drifting apart. Each side's
//! `*_utils` module re-exports the subset it uses, so call sites are unchanged.
//!
//! Profile constants are sourced from the `verifier` module (which re-exports the
//! compile-time `profile::*` tuple), so the same code tracks every build profile.

use crate::shrincs::verifier::{
    ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, HASH_LEN, HASH_TRUNC_LEN, NUM_WOTS_CHAINS,
    WOTS_CHAIN_LEN,
};
use solana_program::keccak::hash as keccak256_hash;

pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    // Ethereum/Solidity Keccak-256 via Solana's built-in entry point. This keeps
    // the Rust signer/verifier aligned with the on-chain code and avoids pulling
    // in a second hash crate.
    keccak256_hash(data).to_bytes()
}

pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Solidity's `keccak256(abi.encodePacked(...))`. Rust has no ABI packer here,
    // so all callers pass already-big-endian byte chunks and this helper
    // concatenates them with no lengths or padding before hashing.
    keccak256(&pack(parts))
}

pub(crate) fn pack(parts: &[&[u8]]) -> Vec<u8> {
    // Allocate once, then copy each field exactly once so the byte layout is easy
    // to review at every call site.
    let len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn mask_hash(mut hash: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    // High-aligned truncation to the profile's HASH_TRUNC_LEN, mirroring Solidity
    // `SHRINCSHash.maskHash` (`h & HASH_MASK`): keep the top HASH_TRUNC_LEN bytes
    // and zero the low (HASH_LEN - HASH_TRUNC_LEN). For the 256s profile
    // HASH_TRUNC_LEN == HASH_LEN, so this iterates zero times and output is
    // byte-identical to the raw keccak. [DESIGN §2(b)/§3.3]
    for byte in hash.iter_mut().skip(HASH_TRUNC_LEN) {
        *byte = 0;
    }
    hash
}

pub(crate) fn hash_node(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Truncated node/root/chain/pk-hash hash, applied at exactly the sites the
    // Solidity signer/verifier mask. Secrets, seeds, digit digests, the FORS
    // digest expansion, and commitments keep full 32-byte width.
    mask_hash(hash_packed(parts))
}

pub(crate) fn word32(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    // Solidity loads `bytes32` only after checking the length is 32. Returning
    // `None` instead of padding/truncating keeps that discipline in Rust so
    // malformed inputs are rejected rather than silently reshaped.
    input.try_into().ok()
}

pub(crate) fn base_w16_digit(digest: &[u8; HASH_LEN], index: usize) -> u32 {
    // Base-16 stores two WOTS digits per byte: high nibble first, then low nibble.
    let byte = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(byte >> 4)
    } else {
        u32::from(byte & 0x0f)
    }
}

pub(crate) fn base_w_digit(w: u16, digest: &[u8], index: usize) -> u32 {
    // Base-256 consumes one byte per digit; base-16 consumes one nibble per digit.
    // The base-256 branch is retained to match Solidity's helper if the chain
    // length is widened later.
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
    // Enough digest bytes to cover the configured WOTS digits. The grind loop
    // checks the digit sum after this truncation.
    let bits_per_digit = if WOTS_CHAIN_LEN == 256 { 8 } else { 4 };
    (NUM_WOTS_CHAINS as usize * bits_per_digit).div_ceil(8)
}

// Digest slicing/indexing in the stateless WOTS-C path reads `wots_digest_bytes()`
// out of a single 32-byte keccak word (`base_w_digit` indexes `digest[index]`,
// the signer slices `&digest[..wots_digest_bytes()]`). Guard the invariant at
// compile time so a retuned WOTS_CHAIN_LEN (e.g. 256) or NUM_WOTS_CHAINS that
// would over-read the word fails the build instead of panicking at runtime. The
// verifier keeps its own `wots_digest_bytes() > HASH_LEN` runtime fail-closed
// check for attacker-supplied inputs; this const guard documents the same bound
// for the signer's fixed-parameter slicing.
const _: () = {
    let bits_per_digit = if WOTS_CHAIN_LEN == 256 { 8 } else { 4 };
    assert!(
        (NUM_WOTS_CHAINS as usize * bits_per_digit).div_ceil(8) <= HASH_LEN,
        "wots_digest_bytes() must stay within HASH_LEN=32; retune WOTS_CHAIN_LEN/NUM_WOTS_CHAINS"
    );
};

pub(crate) fn read_bits32(input: &[u8], start_bit: usize, bit_len: u32) -> Option<u32> {
    // FORS digest fields are bit-packed, not byte-aligned. Big-endian bit order so
    // signer and verifier select the same leaves.
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
    // Walk one bit at a time because the digest fields are bit-packed. Slower than
    // word slicing but much harder to get subtly wrong: bit 0 is the high bit of
    // byte 0, matching Solidity's big-endian bit stream.
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
    // 32-byte SPHINCS-style address word:
    // layer(4) || zero(4) || tree(8) || type(4) || keypair(4) || chain(4) || step(4).
    // The zero bytes at 4..8 are intentional (Solidity shifts `tree` by 128 bits).
    // Hashing the address prevents a valid chain value from being replayed at
    // another point.
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
    // FORS addresses live at layer 0 and use address type 3. The low 64 bits carry
    // either a leaf number or a parent number, while `node_height` says which one.
    let mut out = [0u8; HASH_LEN];
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS_TYPE_FORS_TREE.to_be_bytes());
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
    // Hypertree internal nodes use address type 2. The low word combines node
    // height and parent index so two equal child hashes at different levels do not
    // produce interchangeable parents.
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS_TYPE_TREE.to_be_bytes());
    let low = (u64::from(node_height) << 32) | parent_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_word_matches_solidity_layout() {
        let word = address_word32(1, 2, 3, 4, 5, 6);
        assert_eq!(&word[0..4], &1u32.to_be_bytes());
        assert_eq!(&word[8..16], &2u64.to_be_bytes());
        assert_eq!(&word[16..20], &3u32.to_be_bytes());
        assert_eq!(&word[20..24], &4u32.to_be_bytes());
        assert_eq!(&word[24..28], &5u32.to_be_bytes());
        assert_eq!(&word[28..32], &6u32.to_be_bytes());
    }

    #[test]
    fn solana_keccak256_matches_known_empty_vector() {
        assert_eq!(
            keccak256(&[]),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ]
        );
    }
}
