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

use crate::shrincs::components::uxmss;
use crate::shrincs::core::sphincs_plus_c;
use crate::shrincs::shrincs_verifier_utils::{
    decode_stateful_public_key, hash_packed, matches_expected_public_key_commitment,
    rotation_target_commitment, stateful_rotation_target_commitment, valid_action_context,
    valid_public_key, valid_rotation_context, word32,
};
use crate::shrincs::types::{
    ActionContext, PublicKey, RotationContext, RotationTarget, StatefulRotationTarget,
    StatefulSignature, StatelessSignature, HASH_LEN, HASH_SUITE_KECCAK_256,
    STATEFUL_PUBLIC_KEY_BYTES,
};

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
    let message = stateless_action_message_hash(expected_public_key_commitment, context);
    sphincs_plus_c::verify_stateless_raw(
        expected_public_key_commitment,
        public_key,
        &message,
        signature,
    )
}

pub(crate) fn rotate_stateful_via_stateless(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &PublicKey,
    context: &RotationContext,
    recovery_signature: &StatelessSignature,
    next_stateful_key: &StatefulRotationTarget,
) -> Option<[u8; HASH_LEN]> {
    if !matches_expected_public_key_commitment(
        current_public_key,
        expected_public_key_commitment,
    ) {
        return None;
    }
    if !valid_rotation_context(context) {
        return None;
    }
    if !valid_public_key(current_public_key) {
        return None;
    }
    if next_stateful_key.stateful_public_key.len() != STATEFUL_PUBLIC_KEY_BYTES {
        return None;
    }
    let decoded_next_stateful_key =
        decode_stateful_public_key(&next_stateful_key.stateful_public_key)?;
    if decoded_next_stateful_key.max_signatures == 0 {
        return None;
    }
    let current_pk_seed = word32(&current_public_key.pk_seed)?;
    let current_hypertree_root = word32(&current_public_key.hypertree_root)?;
    let next_public_key_commitment = stateful_rotation_target_commitment(
        &next_stateful_key.stateful_public_key,
        &current_pk_seed,
        &current_hypertree_root,
    );
    if word32(&next_stateful_key.public_key_commitment) != Some(next_public_key_commitment) {
        return None;
    }

    let recovery_message = stateful_rotation_message_hash(
        expected_public_key_commitment,
        current_public_key,
        context,
        next_stateful_key,
    );
    if !sphincs_plus_c::verify_stateless_raw(
        expected_public_key_commitment,
        current_public_key,
        &recovery_message,
        recovery_signature,
    ) {
        return None;
    }

    Some(next_public_key_commitment)
}

pub(crate) fn stateless_rotate(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &PublicKey,
    context: &RotationContext,
    recovery_signature: &StatelessSignature,
    next_key: &RotationTarget,
) -> Option<[u8; HASH_LEN]> {
    if !matches_expected_public_key_commitment(
        current_public_key,
        expected_public_key_commitment,
    ) {
        return None;
    }
    if !valid_rotation_context(context) {
        return None;
    }
    if !valid_public_key(current_public_key) {
        return None;
    }
    if next_key.stateful_public_key.len() != STATEFUL_PUBLIC_KEY_BYTES
        || next_key.pk_seed.len() != HASH_LEN
        || next_key.hypertree_root.len() != HASH_LEN
    {
        return None;
    }
    let decoded_next_stateful_key = decode_stateful_public_key(&next_key.stateful_public_key)?;
    if decoded_next_stateful_key.max_signatures == 0 {
        return None;
    }
    let next_public_key_commitment = rotation_target_commitment(next_key)?;
    if word32(&next_key.public_key_commitment) != Some(next_public_key_commitment) {
        return None;
    }

    let recovery_message = full_rotation_message_hash(
        expected_public_key_commitment,
        current_public_key,
        context,
        next_key,
    );
    if !sphincs_plus_c::verify_stateless_raw(
        expected_public_key_commitment,
        current_public_key,
        &recovery_message,
        recovery_signature,
    ) {
        return None;
    }
    Some(next_public_key_commitment)
}

pub(crate) fn verify_stateful_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    uxmss::verify_stateful_unsafe_raw(
        expected_public_key_commitment,
        public_key,
        message,
        signature,
    )
}

#[cfg(any(test, feature = "wasm-bindings"))]
pub(crate) fn verify_stateless_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
        return false;
    }
    sphincs_plus_c::verify_stateless_raw(
        expected_public_key_commitment,
        public_key,
        message,
        signature,
    )
}

pub(crate) fn stateful_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    let op = hash_packed(&[b"shrincs-verify-stateful"]);
    hash_packed(&[
        &op,
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &context.action_type,
        &context.payload_hash,
    ])
}

pub(crate) fn stateless_action_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> [u8; HASH_LEN] {
    let op = hash_packed(&[b"shrincs-verify-stateless"]);
    hash_packed(&[
        &op,
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &context.action_type,
        &context.payload_hash,
    ])
}

pub(crate) fn stateful_rotation_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &PublicKey,
    context: &RotationContext,
    next_stateful_key: &StatefulRotationTarget,
) -> [u8; HASH_LEN] {
    let op = hash_packed(&[b"shrincs-rotate-stateful"]);
    hash_packed(&[
        &op,
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &current_public_key.public_key_commitment,
        &next_stateful_key.public_key_commitment,
    ])
}

pub(crate) fn full_rotation_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &PublicKey,
    context: &RotationContext,
    next_key: &RotationTarget,
) -> [u8; HASH_LEN] {
    let op = hash_packed(&[b"shrincs-rotate-full"]);
    hash_packed(&[
        &op,
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &current_public_key.public_key_commitment,
        &next_key.public_key_commitment,
    ])
}
