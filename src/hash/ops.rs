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

//! Hashing, packing, and bit-layout helpers.

use crate::hash::backend;
use crate::hash::suite::scheme_hash_parts;
use crate::profiles::{HASH_TRUNC_LEN, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN};
use crate::HASH_LEN;

/// Scheme hash over the logical concatenation of `parts`. Hashing is vectored
/// (incremental absorb / Solana `hashv`), so no packed buffer is allocated.
pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    scheme_hash_parts(parts)
}

/// EVM-domain keccak over preimage parts (action hashes, commitments).
/// Always keccak regardless of the scheme-hash suite.
pub(crate) fn keccak_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    backend::keccak256v(parts)
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

/// Small deterministic KDF: `hash_packed(&[domain, seed, data])`. Domain tags
/// separate the different seeds derived from the same master input. Shared by
/// SHRINCS key generation and the SPHINCS+C hypertree layer-seed derivation so
/// the two sides can't drift apart.
pub(crate) fn derive32(domain: &[u8], seed: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    hash_packed(&[domain, seed, data])
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::address::{address_word32, AddressWord32};

    #[test]
    fn address_word_matches_solidity_layout() {
        let word = address_word32(AddressWord32 {
            layer: 1,
            tree: 2,
            address_type: 3,
            keypair: 4,
            chain: 5,
            step: 6,
        });
        assert_eq!(&word[0..4], &1u32.to_be_bytes());
        assert_eq!(&word[8..16], &2u64.to_be_bytes());
        assert_eq!(&word[16..20], &3u32.to_be_bytes());
        assert_eq!(&word[20..24], &4u32.to_be_bytes());
        assert_eq!(&word[24..28], &5u32.to_be_bytes());
        assert_eq!(&word[28..32], &6u32.to_be_bytes());
    }

    #[test]
    fn keccak256_matches_known_empty_vector() {
        assert_eq!(
            backend::keccak256(&[]),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ]
        );
    }
}
