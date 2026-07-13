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

#[cfg(feature = "suite-sha2")]
use solana_program::hash::hash as sha256_hash;
use solana_program::keccak::hash as keccak256_hash;

use super::shrincs_verifier_types::{
    ActionContext, PublicKey, RotationContext, StatefulPublicKey, ADDRESS_TYPE_FORS_TREE,
    ADDRESS_TYPE_TREE, HASH_LEN, HASH_TRUNC_LEN, NUM_WOTS_CHAINS, PROFILE_NAME,
    STATEFUL_PUBLIC_KEY_BYTES, WOTS_CHAIN_LEN,
};

pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    // Ethereum/Solidity Keccak-256, always keccak regardless of the compiled
    // hash suite: the public-key commitment and account action/rotation framing
    // are EVM-domain and stay keccak so the on-chain identity is suite-agnostic.
    // [83d hash-seam design §1.2]
    keccak256_hash(data).to_bytes()
}

// Suite-selected scheme hash. Every SHRINCS scheme hash the verifier recomputes
// -- tree nodes, leaves, digests, chains -- routes through hash_packed/hash_node
// and therefore this one function, so the suite swap is a single edit. keccak by
// default; SHA-256 under `suite-sha2`. Tag strings and preimage layouts are
// identical across suites; only the hash primitive changes. [design §3.4/§5.2]
#[cfg(not(feature = "suite-sha2"))]
fn scheme_hash(data: &[u8]) -> [u8; HASH_LEN] {
    keccak256_hash(data).to_bytes()
}
#[cfg(feature = "suite-sha2")]
fn scheme_hash(data: &[u8]) -> [u8; HASH_LEN] {
    sha256_hash(data).to_bytes()
}

pub(crate) fn hash_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Solidity's verifier uses `<suite>(abi.encodePacked(...))` throughout.
    // Rust has no ABI packer here, so all callers pass already-big-endian byte
    // chunks and this helper concatenates them with no lengths or padding.
    scheme_hash(&pack(parts))
}

pub(crate) fn keccak_packed(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // EVM-domain packed keccak for the commitment/action framing (stays keccak
    // under every suite). Under the default keccak suite this is byte-identical
    // to hash_packed, so the keccak vectors are unchanged by the seam.
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

pub(crate) fn mask_hash(mut hash: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    // High-aligned truncation to the profile's HASH_TRUNC_LEN: keep the top
    // HASH_TRUNC_LEN bytes and zero the low (HASH_LEN - HASH_TRUNC_LEN),
    // mirroring Solidity `SHRINCSHash.maskHash` (`h & HASH_MASK`). For the 256s
    // profile HASH_TRUNC_LEN == HASH_LEN, so this iterates zero times and the
    // output is byte-identical to the raw keccak. [DESIGN §2(b)/§3.3]
    for byte in hash.iter_mut().skip(HASH_TRUNC_LEN) {
        *byte = 0;
    }
    hash
}

pub(crate) fn hash_node(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    // Node/root/chain/pk-hash sites truncate their keccak output to the active
    // profile's HASH_LEN. Solidity applies `maskHash` at exactly these nine
    // hash-producing sites; digit digests, chain secrets, seeds, the FORS
    // digest expansion, and public-key/action commitments stay full 32 bytes.
    mask_hash(hash_packed(parts))
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

pub(crate) fn public_key_commitment(public_key: &PublicKey) -> Option<[u8; HASH_LEN]> {
    let pk_seed = word32(&public_key.pk_seed)?;
    let hypertree_root = word32(&public_key.hypertree_root)?;
    // Profile-bound commitment tag: `shrincs-public-key/<PROFILE_NAME>`. The
    // commitment is EVM-domain framing and stays keccak under every suite; the
    // suite is separated by PROFILE_NAME's `-sha2`/`-keccak` suffix instead.
    Some(keccak_packed(&[
        b"shrincs-public-key/",
        PROFILE_NAME.as_bytes(),
        &public_key.stateful_public_key,
        &pk_seed,
        &hypertree_root,
    ]))
}

pub(crate) fn stateful_rotation_target_commitment(
    stateful_public_key: &[u8],
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // Rotation targets commit to the same profile-bound tag as live keys;
    // like the live-key commitment it is EVM-domain and stays keccak.
    keccak_packed(&[
        b"shrincs-public-key/",
        PROFILE_NAME.as_bytes(),
        stateful_public_key,
        pk_seed,
        hypertree_root,
    ])
}

pub(crate) fn rotation_target_commitment(
    target: &super::shrincs_verifier_types::RotationTarget,
) -> Option<[u8; HASH_LEN]> {
    let pk_seed = word32(&target.pk_seed)?;
    let hypertree_root = word32(&target.hypertree_root)?;
    Some(stateful_rotation_target_commitment(
        &target.stateful_public_key,
        &pk_seed,
        &hypertree_root,
    ))
}

pub(crate) fn matches_expected_public_key_commitment(
    public_key: &PublicKey,
    expected_public_key_commitment: [u8; HASH_LEN],
) -> bool {
    // The account or caller stores the installed hybrid-key commitment. The
    // supplied bundle must match that commitment exactly, not just the stateless
    // hypertree root inside it.
    expected_public_key_commitment != [0u8; HASH_LEN]
        && word32(&public_key.public_key_commitment) == Some(expected_public_key_commitment)
        && public_key_commitment(public_key) == Some(expected_public_key_commitment)
}

pub(crate) fn valid_public_key(public_key: &PublicKey) -> bool {
    public_key.stateful_public_key.len() == STATEFUL_PUBLIC_KEY_BYTES
        && public_key.public_key_commitment.len() == HASH_LEN
        && public_key.pk_seed.len() == HASH_LEN
        && public_key.hypertree_root.len() == HASH_LEN
        && public_key_commitment(public_key) == word32(&public_key.public_key_commitment)
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
    // The compiled constants use base 16. The base-256 branch is retained to
    // match Solidity's helper if the chain length is widened later.
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
    (NUM_WOTS_CHAINS as usize * bits_per_digit + 7) / 8
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
