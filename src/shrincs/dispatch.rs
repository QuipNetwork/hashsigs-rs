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

use super::action_context::ActionContext;
use super::key::decode_stateful_public_key;
use super::key::PublicKey;
use super::signature::Signature;
use super::uxmss::STATEFUL_PUBLIC_KEY_BYTES;
use crate::hash::keccak_packed;
use crate::hash::suite::HASH_SUITE_ID;
use crate::hash::word32;
use crate::shrincs::uxmss;
use crate::sphincs_plus_c;
use crate::sphincs_plus_c::Signature as StatelessSignature;
use crate::HASH_LEN;
use alloc::vec::Vec;

/// Canonical action-verify message hash, binding the operation tag, active
/// hash-suite ID, and the context's domain separator, nonce, key version,
/// action type, and payload hash. Shared body for
/// `stateful_action_message_hash` and `stateless_action_message_hash`, which
/// differ only in `op_tag`.
fn action_message_hash(
    op_tag: &[u8],
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    let op = keccak_packed(&[op_tag]);
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

/// Canonical message hash for a stateful action verify. See
/// `action_message_hash`.
pub(crate) fn stateful_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    action_message_hash(
        b"shrincs-verify-stateful",
        expected_public_key_commitment,
        context,
    )
}

/// Canonical message hash for a stateless action verify. See
/// `action_message_hash`.
pub(crate) fn stateless_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    action_message_hash(
        b"shrincs-verify-stateless",
        expected_public_key_commitment,
        context,
    )
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
    Some(*public_key.commitment()?.as_bytes())
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
    signature: &Signature,
) -> bool {
    if !valid_action_context(context) {
        return false;
    }
    let message = stateful_action_message_hash(expected_public_key_commitment, context);
    verify_stateful_unsafe_raw(
        expected_public_key_commitment,
        public_key,
        &message,
        signature,
    )
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
    signature: &Signature,
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
    let (public_key, signature) = super::signature::decode_stateless_envelope(envelope)?;
    if !matches_expected_public_key_commitment(&public_key, expected_public_key_commitment) {
        return None;
    }
    if !valid_public_key(&public_key) {
        return None;
    }
    // valid_public_key has proven both fields are exactly 32 bytes.
    let pk_seed: [u8; HASH_LEN] = public_key.pk_seed.try_into().ok()?;
    let hypertree_root: [u8; HASH_LEN] = public_key.hypertree_root.try_into().ok()?;
    Some((
        sphincs_plus_c::encode_public_key(pk_seed, hypertree_root),
        signature.to_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::signature::encode_stateless_envelope;
    use crate::shrincs::signer::ShrincsSigner;

    fn keypair(seed: &[u8]) -> (crate::shrincs::Keys, PublicKey) {
        ShrincsSigner::keygen(seed, 4).expect("keygen must succeed for a valid seed/budget")
    }

    fn sample_context() -> ActionContext {
        ActionContext {
            domain_separator: [1u8; HASH_LEN],
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
            action_type: [2u8; HASH_LEN],
            payload_hash: [3u8; HASH_LEN],
        }
    }

    #[test]
    fn valid_action_context_accepts_a_well_formed_context() {
        assert!(valid_action_context(&sample_context()));
    }

    #[test]
    fn valid_action_context_rejects_each_zeroed_required_field() {
        let mut zero_domain = sample_context();
        zero_domain.domain_separator = [0u8; HASH_LEN];
        assert!(!valid_action_context(&zero_domain));

        let mut zero_action_type = sample_context();
        zero_action_type.action_type = [0u8; HASH_LEN];
        assert!(!valid_action_context(&zero_action_type));

        let mut zero_payload = sample_context();
        zero_payload.payload_hash = [0u8; HASH_LEN];
        assert!(!valid_action_context(&zero_payload));

        // nonce/key_version may legitimately be zero (a fresh account) --
        // only domain_separator/action_type/payload_hash are required non-zero.
        let mut zero_nonce_and_key_version = sample_context();
        zero_nonce_and_key_version.nonce = [0u8; HASH_LEN];
        zero_nonce_and_key_version.key_version = [0u8; HASH_LEN];
        assert!(valid_action_context(&zero_nonce_and_key_version));
    }

    #[test]
    fn prepare_stateless_delegation_rejects_a_mismatched_commitment() {
        let (signing_key, public_key) =
            keypair(b"dispatch prepare_stateless_delegation wrong commitment");
        let hash = [0x77u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash).expect("sign");
        let envelope = encode_stateless_envelope(&public_key, &signature);

        let mut wrong_commitment = [0u8; HASH_LEN];
        wrong_commitment.copy_from_slice(&public_key.public_key_commitment);
        wrong_commitment[0] ^= 0x01;

        assert!(prepare_stateless_delegation(wrong_commitment, &envelope).is_none());
    }

    #[test]
    fn prepare_stateless_delegation_rejects_a_malformed_envelope() {
        let (_signing_key, public_key) =
            keypair(b"dispatch prepare_stateless_delegation malformed envelope");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .try_into()
            .expect("commitment is 32 bytes");

        assert!(prepare_stateless_delegation(commitment, &[]).is_none());
        assert!(prepare_stateless_delegation(commitment, &[0xffu8; 3]).is_none());
    }
}
