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

//! Shared canonical SHRINCS message-hash constructors.

use crate::hash::keccak_packed;
use crate::hash_suite::HASH_SUITE_ID;
use crate::types::{
    ActionContext, PublicKey, RotationContext, RotationTarget, StatefulRotationTarget, HASH_LEN,
};

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

pub(crate) fn stateful_rotation_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &PublicKey,
    context: &RotationContext,
    next_stateful_key: &StatefulRotationTarget,
) -> [u8; HASH_LEN] {
    let op = keccak_packed(&[b"shrincs-rotate-stateful"]);
    keccak_packed(&[
        &op,
        &HASH_SUITE_ID.to_be_bytes(),
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
    let op = keccak_packed(&[b"shrincs-rotate-full"]);
    keccak_packed(&[
        &op,
        &HASH_SUITE_ID.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        &current_public_key.public_key_commitment,
        &next_key.public_key_commitment,
    ])
}
