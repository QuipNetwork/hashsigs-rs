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

//! Hybrid SHRINCS scheme orchestration.
//!
//! Owns the crypto-level verify decision logic shared by `verifier` and
//! `signer`: validates contexts and encoded public keys and dispatches into
//! `sphincs_plus_c` (stateless) and `uxmss` (stateful). `mod.rs` re-exports
//! the pieces `wasm` needs.

use alloc::vec::Vec;
use crate::primitives::hash::keccak_packed;
use crate::primitives::hash::word32;
use crate::primitives::hash_suite::HASH_SUITE_ID;
use crate::sphincs_plus_c;
use crate::types::{
    ActionContext, PublicKey, StatefulSignature, StatelessSignature, HASH_LEN,
    STATEFUL_PUBLIC_KEY_BYTES,
};
use crate::shrincs::uxmss;
use super::public_key::{
    decode_stateful_public_key, public_key_commitment as public_key_commitment_from_parts,
};

/// Canonical message hash for a stateful action verify, binding the
/// operation tag, active hash-suite ID, and the context's domain separator,
/// nonce, key version, action type, and payload hash.
pub(crate) fn stateful_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    let op = keccak_packed(&[b"shrincs-verify-stateful"]);
    keccak_packed(&[
        &op,
        &HASH_SUITE_ID.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &context.action_type,
        &context.payload_hash,
    ])
}

/// Canonical message hash for a stateless action verify. See
/// `stateful_action_message_hash`.
pub(crate) fn stateless_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    let op = keccak_packed(&[b"shrincs-verify-stateless"]);
    keccak_packed(&[
        &op,
        &HASH_SUITE_ID.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &context.action_type,
        &context.payload_hash,
    ])
}

fn verify_stateless_crypto(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    let Some(pk_seed) = word32(&public_key.pk_seed) else {
        return false;
    };
    let Some(hypertree_root) = word32(&public_key.hypertree_root) else {
        return false;
    };
    let pk = sphincs_plus_c::PublicKey {
        pk_seed: sphincs_plus_c::PkSeed::new(pk_seed),
        root: sphincs_plus_c::Root::new(hypertree_root),
    };
    sphincs_plus_c::verify(&pk, message, signature)
}

pub(crate) fn valid_action_context(context: &ActionContext) -> bool {
    context.domain_separator != [0u8; HASH_LEN]
        && context.action_type != [0u8; HASH_LEN]
        && context.payload_hash != [0u8; HASH_LEN]
}

fn recompute_public_key_commitment(public_key: &PublicKey) -> Option<[u8; HASH_LEN]> {
    let pk_seed = word32(&public_key.pk_seed)?;
    let hypertree_root = word32(&public_key.hypertree_root)?;
    Some(public_key_commitment_from_parts(
        &public_key.stateful_public_key,
        &pk_seed,
        &hypertree_root,
    ))
}

pub(crate) fn matches_expected_public_key_commitment(
    public_key: &PublicKey,
    expected_public_key_commitment: [u8; HASH_LEN],
) -> bool {
    expected_public_key_commitment != [0u8; HASH_LEN]
        && word32(&public_key.public_key_commitment) == Some(expected_public_key_commitment)
        && recompute_public_key_commitment(public_key) == Some(expected_public_key_commitment)
}

pub(crate) fn valid_public_key(public_key: &PublicKey) -> bool {
    public_key.stateful_public_key.len() == STATEFUL_PUBLIC_KEY_BYTES
        && public_key.public_key_commitment.len() == HASH_LEN
        && public_key.pk_seed.len() == HASH_LEN
        && public_key.hypertree_root.len() == HASH_LEN
        && recompute_public_key_commitment(public_key) == word32(&public_key.public_key_commitment)
}

pub(crate) fn verify_stateful(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    context: &ActionContext,
    signature: &StatefulSignature,
) -> bool {
    if !valid_action_context(context) {
        return false;
    }
    let message = stateful_action_message_hash(expected_public_key_commitment, context);
    verify_stateful_unsafe_raw(expected_public_key_commitment, public_key, &message, signature)
}

pub(crate) fn verify_stateless(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    context: &ActionContext,
    signature: &StatelessSignature,
) -> bool {
    if !valid_action_context(context) {
        return false;
    }
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    let message = stateless_action_message_hash(expected_public_key_commitment, context);
    verify_stateless_crypto(public_key, &message, signature)
}

pub(crate) fn verify_stateful_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    let Some(stateful_key) = decode_stateful_public_key(&public_key.stateful_public_key) else {
        return false;
    };
    uxmss::verify_stateful_unsafe_raw(&stateful_key, message, signature)
}

#[cfg(test)]
pub(crate) fn verify_stateless_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    if !valid_public_key(public_key) {
        return false;
    }
    verify_stateless_crypto(public_key, message, signature)
}

/// Mirrors `SHRINCS.prepareStatelessDelegation`: decode a stateless envelope,
/// require it to match the installed commitment and satisfy the fixed
/// public-key shape, then hand back the pinned-sibling delegate key (the
/// 64-byte `pkSeed || hypertreeRoot` `SPHINCSPlusCVerifier` key layout) and
/// delegate signature envelope. Returns `None` on any commitment mismatch,
/// shape failure, or malformed envelope — this function never panics.
pub fn prepare_stateless_delegation(
    expected_public_key_commitment: [u8; HASH_LEN],
    envelope: &[u8],
) -> Option<([u8; 64], Vec<u8>)> {
    let (public_key, signature) = crate::envelope::decode_stateless_envelope(envelope)?;
    if !matches_expected_public_key_commitment(&public_key, expected_public_key_commitment)
    {
        return None;
    }
    if !valid_public_key(&public_key) {
        return None;
    }
    // valid_public_key has proven both fields are exactly 32 bytes.
    let pk_seed: [u8; HASH_LEN] = public_key.pk_seed.try_into().ok()?;
    let hypertree_root: [u8; HASH_LEN] = public_key.hypertree_root.try_into().ok()?;
    Some((
        crate::envelope::encode_stateless_key(pk_seed, hypertree_root),
        crate::envelope::encode_stateless_signature_envelope(&signature),
    ))
}
