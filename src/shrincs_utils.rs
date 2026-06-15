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

//! Shared helpers for the SHRINCS verifier.

use solana_program::keccak::hash as keccak256_hash;

use super::shrincs_types::{
    ActionContext, ParameterSetId, ParamsView, PublicKey, RotationContext, StatefulPublicKey,
    ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, HASH_LEN, HASH_SUITE_KECCAK_256,
    STATEFUL_PUBLIC_KEY_BYTES, WOTS_TARGET_SUM_STATEFUL,
};

pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    // Use the same Keccak implementation pattern already used by the existing
    // WOTS+ Solana processor and tests. This is Ethereum/Solidity Keccak-256,
    keccak256_hash(data).to_bytes()
}

pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Solidity's verifier uses `keccak256(abi.encodePacked(...))` throughout.
    // Rust has no ABI packer here, so all callers pass already-big-endian byte
    // chunks and this helper concatenates them with no lengths or padding.
    keccak256(&pack(parts))
}

pub(crate) fn pack(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn valid_parameter_set_binding(
    params: &ParamsView,
    requested_parameter_set_id: ParameterSetId,
    declared_parameter_set_id: ParameterSetId,
) -> bool {
    // There are three things to bind:
    // - the caller-requested profile,
    // - the profile declared by the public key,
    // - the concrete hash suite used inside signed messages.
    params.parameter_set_id == requested_parameter_set_id
        && declared_parameter_set_id == requested_parameter_set_id
        && params.hash_suite_id == HASH_SUITE_KECCAK_256
}

pub(crate) fn valid_action_context(context: &ActionContext) -> bool {
    // Zero domain/action/payload values are rejected so integrations cannot
    // accidentally verify under an unscoped or empty authorization domain.
    context.domain_separator != [0u8; HASH_LEN]
        && context.action_type != [0u8; HASH_LEN]
        && context.payload_hash != [0u8; HASH_LEN]
}

pub(crate) fn valid_rotation_context(context: &RotationContext) -> bool {
    context.domain_separator != [0u8; HASH_LEN]
}

pub(crate) fn matches_expected_composite_public_key(
    public_key: &PublicKey,
    expected_composite_public_key: [u8; HASH_LEN],
) -> bool {
    // The account or caller stores the stateless SPHINCS-style public root.
    // The supplied public key must carry the same hypertree root.
    expected_composite_public_key != [0u8; HASH_LEN]
        && word32(&public_key.hypertree_root) == Some(expected_composite_public_key)
}

pub(crate) fn valid_params(params: &ParamsView, public_key: &PublicKey) -> bool {
    // The current verifier is intentionally profile-specific. These checks make
    // accidental cross-profile verification fail closed instead of interpreting
    // byte arrays with the wrong dimensions.
    if params.parameter_set_id != ParameterSetId::Sphincs256sKeccakQ20 {
        return false;
    }
    if params.hash_len != 32 || params.parameter_set_id != public_key.parameter_set_id {
        return false;
    }
    if params.hypertree_height != 64
        || params.num_hypertree_layers != 8
        || params.fors_tree_height != 14
    {
        return false;
    }
    if params.num_fors_trees != 22 || params.chain_len != 16 || params.num_wots_chains != 64 {
        return false;
    }
    if params.wots_target_sum != WOTS_TARGET_SUM_STATEFUL {
        return false;
    }
    if !valid_stateful_composite_public_key(public_key) {
        return false;
    }
    (params.num_fors_trees as u64) * (1u64 << params.fors_tree_height) <= u32::MAX as u64
}

pub(crate) fn valid_stateful_composite_public_key(public_key: &PublicKey) -> bool {
    public_key.stateful_public_key.len() == STATEFUL_PUBLIC_KEY_BYTES
        && public_key.pk_seed.len() == HASH_LEN
        && public_key.hypertree_root.len() == HASH_LEN
}

pub(crate) fn decode_stateful_public_key(encoded: &[u8]) -> Option<StatefulPublicKey> {
    // Keep this byte layout identical to Solidity:
    // 0..32 pkSeed, 32..64 root, 64..68 maxSignatures as big-endian uint32.
    if encoded.len() != STATEFUL_PUBLIC_KEY_BYTES {
        return None;
    }
    let pk_seed = word32(&encoded[..32])?;
    let root = word32(&encoded[32..64])?;
    let max_signatures = u32::from_be_bytes(encoded[64..68].try_into().ok()?);
    Some(StatefulPublicKey {
        pk_seed,
        root,
        max_signatures,
    })
}

pub(crate) fn word32(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    // Solidity loads `bytes32` from calldata only after checking the length is 32.
    // This helper keeps the same discipline in Rust.
    input.try_into().ok()
}

pub(crate) fn base_w16_digit(digest: &[u8; HASH_LEN], index: usize) -> u32 {
    // Base-16 stores two digits per byte: high nibble first, then low nibble.
    let byte = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(byte >> 4)
    } else {
        u32::from(byte & 0x0f)
    }
}

pub(crate) fn base_w_digit(w: u16, digest: &[u8], index: usize) -> u32 {
    // The supported profile uses base 16. The base-256 branch is retained to
    // match Solidity's helper and make future parameter expansion obvious.
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

pub(crate) fn wots_digest_bytes(params: &ParamsView) -> usize {
    let bits_per_digit = if params.chain_len == 256 { 8 } else { 4 };
    (params.num_wots_chains as usize * bits_per_digit + 7) / 8
}

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
    // Solidity reads digest fields as a big-endian bit stream. This loop mirrors
    // that model directly: bit 0 is the high bit of byte 0.
    let mut out = 0u64;
    for bit in 0..bit_len as usize {
        let absolute = start_bit + bit;
        let byte = *input.get(absolute >> 3)?;
        let bit_in_byte = 7 - (absolute & 7);
        out = (out << 1) | u64::from((byte >> bit_in_byte) & 1);
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
    // 32-byte address word used by WOTS-C/stateful hashing:
    // layer(4) || zero(4) || tree(8) || type(4) || keypair(4) || chain(4) || step(4).
    // The zero bytes at 4..8 are intentional because Solidity shifts `tree` by 128 bits.
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
    // FORS addresses share the same 32-byte layout but use the low 64 bits for
    // either a leaf position or a parent node height/index pair.
    let mut out = [0u8; HASH_LEN];
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS_TYPE_FORS_TREE.to_be_bytes());
    out[20..24].copy_from_slice(&leaf_index.to_be_bytes());
    let low = (u64::from(node_height) << 32) | low_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}

pub(crate) fn wots_address_base(layer: u32, tree: u64, keypair: u32) -> [u8; HASH_LEN] {
    // Precompute the fields shared by all chains in one WOTS-C signature. The
    // chain and step are filled in by `wots_chain_address_word`.
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

pub(crate) fn hypertree_address_word(
    layer: u32,
    tree_index: u64,
    node_height: u32,
    parent_index: u64,
) -> [u8; HASH_LEN] {
    // Hypertree parent hashing binds the layer, tree, node height, and parent
    // index so a node from one position cannot be reused at another position.
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
