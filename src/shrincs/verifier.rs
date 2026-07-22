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

//! Public hybrid SHRINCS verifier surface.
//!
//! Thin, stateless facade (`ShrincsVerifier`) over `dispatch` and `messages`:
//! every method forwards directly, giving external callers (`account`,
//! `wasm`, the `solana` workspace member) one struct-shaped entry point
//! instead of free functions.

use crate::types::{
    ActionContext, PublicKey, RotationContext, RotationTarget, StatefulRotationTarget,
    StatefulSignature, StatelessSignature, HASH_LEN,
};
use super::dispatch as core_shrincs;
use super::messages::{
    full_rotation_message_hash, stateful_action_message_hash, stateful_rotation_message_hash,
    stateless_action_message_hash,
};
use super::public_key::public_key_commitment as public_key_commitment_from_parts;

pub struct ShrincsVerifier;

impl Default for ShrincsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ShrincsVerifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_stateful(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatefulSignature,
    ) -> bool {
        core_shrincs::verify_stateful(expected_public_key_commitment, public_key, context, signature)
    }

    pub fn verify_stateless(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatelessSignature,
    ) -> bool {
        core_shrincs::verify_stateless(expected_public_key_commitment, public_key, context, signature)
    }

    pub fn rotate_stateful_via_stateless(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        recovery_signature: &StatelessSignature,
        next_stateful_key: &StatefulRotationTarget,
    ) -> Option<[u8; HASH_LEN]> {
        core_shrincs::rotate_stateful_via_stateless(
            expected_public_key_commitment,
            current_public_key,
            context,
            recovery_signature,
            next_stateful_key,
        )
    }

    pub fn stateless_rotate(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        recovery_signature: &StatelessSignature,
        next_key: &RotationTarget,
    ) -> Option<[u8; HASH_LEN]> {
        core_shrincs::stateless_rotate(
            expected_public_key_commitment,
            current_public_key,
            context,
            recovery_signature,
            next_key,
        )
    }

    #[cfg(any(test, feature = "wasm-bindings"))]
    pub(crate) fn verify_stateful_unsafe_raw(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatefulSignature,
    ) -> bool {
        core_shrincs::verify_stateful_unsafe_raw(
            expected_public_key_commitment,
            public_key,
            message,
            signature,
        )
    }

    #[cfg(any(test, feature = "wasm-bindings"))]
    pub(crate) fn verify_stateless_unsafe_raw(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        core_shrincs::verify_stateless_unsafe_raw(
            expected_public_key_commitment,
            public_key,
            message,
            signature,
        )
    }

    pub fn stateful_action_message_hash(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        stateful_action_message_hash(expected_public_key_commitment, context)
    }

    pub fn stateless_action_message_hash(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        stateless_action_message_hash(expected_public_key_commitment, context)
    }

    pub fn stateful_rotation_message_hash(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        next_stateful_key: &StatefulRotationTarget,
    ) -> [u8; HASH_LEN] {
        stateful_rotation_message_hash(
            expected_public_key_commitment,
            current_public_key,
            context,
            next_stateful_key,
        )
    }

    pub fn full_rotation_message_hash(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        next_key: &RotationTarget,
    ) -> [u8; HASH_LEN] {
        full_rotation_message_hash(
            expected_public_key_commitment,
            current_public_key,
            context,
            next_key,
        )
    }

    /// Commitment binding an encoded stateful public key with a stateless
    /// `pk_seed`/`hypertree_root` pair, mirroring
    /// `SHRINCS.publicKeyCommitmentFromParts`. Exposed for callers that need
    /// to derive a candidate bundle's commitment before it is installed
    /// (e.g. building a `StatefulRotationTarget`, whose commitment mixes a
    /// replacement stateful key with the *current* key's stateless
    /// components rather than its own).
    pub fn public_key_commitment(
        &self,
        stateful_public_key: &[u8],
        pk_seed: [u8; HASH_LEN],
        hypertree_root: [u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        public_key_commitment_from_parts(stateful_public_key, &pk_seed, &hypertree_root)
    }
}
