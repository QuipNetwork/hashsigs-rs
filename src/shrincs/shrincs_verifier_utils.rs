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

//! Verifier-specific helpers.
//!
//! The byte-layout primitives (hashing, packing, address words, base-w digits,
//! bit-packed digest reads) are shared with the signer and live in
//! `shrincs_common`; they are re-exported here so verifier call sites keep the
//! same import path. Only the helpers that are genuinely verifier-specific
//! (public-key/context validation, commitment recomputation, stateful key
//! decoding, WOTS address bases) are defined below.

// Re-export the byte-identical helpers shared with the signer. Keeping one copy
// in `shrincs_common` prevents the two sides from drifting apart (F-08 / Q2).
pub(crate) use crate::shrincs::shrincs_common::{
    address_word32, base_w16_digit, base_w_digit, fors_address_word, hash_node, hash_packed, pack,
    hypertree_address_word, read_bits32, read_bits64, word32, wots_digest_bytes,
};

use crate::shrincs::profiles::PROFILE_NAME;
use crate::shrincs::types::{
    ActionContext, PublicKey, RotationContext, RotationTarget, StatefulPublicKey, HASH_LEN,
    STATEFUL_PUBLIC_KEY_BYTES,
};

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
    // Profile-bound commitment tag: `shrincs-public-key/<PROFILE_NAME>`.
    Some(hash_packed(&[
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
    // Rotation targets commit to the same profile-bound tag as live keys.
    hash_packed(&[
        b"shrincs-public-key/",
        PROFILE_NAME.as_bytes(),
        stateful_public_key,
        pk_seed,
        hypertree_root,
    ])
}

pub(crate) fn rotation_target_commitment(target: &RotationTarget) -> Option<[u8; HASH_LEN]> {
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
