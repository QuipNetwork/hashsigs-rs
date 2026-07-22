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

//! Shared hashing, packing, addressing, and bit-layout helpers.
//!
//! This is the Rust analogue of Solidity's shared scheme-hash support layer.
//! Primitive components (`uxmss`, `fors_c`, `hypertree`) build on these
//! helpers, while higher-level core and signer modules import the subset they
//! need. EVM-domain hashes such as canonical action-message construction and
//! public-key commitments stay on keccak under every suite and are therefore
//! owned outside this module.

use crate::hash_suite::scheme_hash;
use crate::profiles::{HASH_TRUNC_LEN, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN};
use crate::types::{ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, HASH_LEN};

pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    scheme_hash(&pack(parts))
}

/// EVM-domain keccak over packed preimage parts (action hashes, commitments).
/// Always keccak regardless of the scheme-hash suite.
pub(crate) fn keccak_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    solana_program::keccak::hash(&pack(parts)).to_bytes()
}

pub(crate) fn pack(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn mask_hash(mut hash: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    for byte in hash.iter_mut().skip(HASH_TRUNC_LEN) {
        *byte = 0;
    }
    hash
}

pub(crate) fn hash_node(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    mask_hash(hash_packed(parts))
}

pub(crate) fn word32(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    input.try_into().ok()
}

pub(crate) fn base_w16_digit(digest: &[u8; HASH_LEN], index: usize) -> u32 {
    let byte = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(byte >> 4)
    } else {
        u32::from(byte & 0x0f)
    }
}

pub(crate) fn base_w_digit(w: u16, digest: &[u8], index: usize) -> u32 {
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
    let bits_per_digit = if WOTS_CHAIN_LEN == 256 { 8 } else { 4 };
    (NUM_WOTS_CHAINS as usize * bits_per_digit).div_ceil(8)
}

const _: () = {
    let bits_per_digit = if WOTS_CHAIN_LEN == 256 { 8 } else { 4 };
    assert!(
        (NUM_WOTS_CHAINS as usize * bits_per_digit).div_ceil(8) <= HASH_LEN,
        "wots_digest_bytes() must stay within HASH_LEN=32; retune WOTS_CHAIN_LEN/NUM_WOTS_CHAINS"
    );
};

pub(crate) fn read_bits32(input: &[u8], start_bit: usize, bit_len: u32) -> Option<u32> {
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
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree.to_be_bytes());
    out[16..20].copy_from_slice(&address_type.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out[24..28].copy_from_slice(&chain.to_be_bytes());
    out[28..32].copy_from_slice(&step.to_be_bytes());
    out
}

pub(crate) fn wots_address_base(layer: u32, tree: u64, keypair: u32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out
}

pub(crate) fn wots_chain_address_word(
    mut address_base: [u8; HASH_LEN],
    chain_index: u32,
    step: u32,
) -> [u8; HASH_LEN] {
    address_base[24..28].copy_from_slice(&chain_index.to_be_bytes());
    address_base[28..32].copy_from_slice(&step.to_be_bytes());
    address_base
}

pub(crate) fn fors_address_word(
    tree_index: u64,
    leaf_index: u32,
    node_height: u32,
    low_index: u64,
) -> [u8; HASH_LEN] {
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
            solana_program::keccak::hash(&[]).to_bytes(),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ]
        );
    }
}
