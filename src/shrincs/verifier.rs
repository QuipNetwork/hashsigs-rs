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

//! Public SHRINCS verifier facade.
//!
//! Performs context binding, rotation-message construction, and high-level public-key
//! checks, then delegates the cryptographic work to the same component modules
//! as the Solidity verifier (`ShrincsForsC`, `ShrincsHypertree`, and the
//! compact signer/verifier helpers).

#[path = "shrincs_verifier_fors_c.rs"]
mod shrincs_verifier_fors_c;
#[path = "shrincs_verifier_hypertree.rs"]
mod shrincs_verifier_hypertree;
#[path = "shrincs_verifier_types.rs"]
mod shrincs_verifier_types;
#[path = "shrincs_verifier_utils.rs"]
mod shrincs_verifier_utils;

pub use self::shrincs_verifier_types::*;

use self::shrincs_verifier_fors_c::verify_fors_c_and_return_root;
use self::shrincs_verifier_hypertree::verify_hypertree;
use self::shrincs_verifier_utils::{
    hash_packed, matches_expected_stateless_key, valid_action_context, valid_public_key,
    valid_rotation_context,
};

pub struct ShrincsVerifier;

impl ShrincsVerifier {
    /// Construct a verifier.
    ///
    /// The verifier is stateless: all state needed for verification is supplied
    /// through the public key, signed context, and signature structures.
    pub fn new() -> Self {
        Self
    }

    /// Verify a stateless signature over an action context.
    ///
    /// This follows the same safe-context pattern as `verify_stateful`, but it
    /// verifies the message through FORS-C and the hypertree rather than through
    /// the stateful WOTS-C tree.
    pub fn verify_stateless(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatelessSignature,
    ) -> bool {
        if !valid_action_context(context) {
            return false;
        }
        let message =
            self.stateless_action_message_hash(expected_pk_seed, expected_hypertree_root, context);
        self.verify_stateless_raw_memory(
            expected_pk_seed,
            expected_hypertree_root,
            public_key,
            &message,
            signature,
        )
    }

    /// Rotate the full SHRINCS key bundle using a stateless recovery signature.
    ///
    /// This is stricter than `rotate_stateful_via_stateless`: every public
    /// component of the next bundle is supplied and signed into the recovery
    /// message before the next installed-key commitment is returned.
    pub fn stateless_rotate(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        recovery_signature: &StatelessSignature,
        next_key: &RotationTarget,
    ) -> bool {
        if !matches_expected_stateless_key(
            current_public_key,
            expected_pk_seed,
            expected_hypertree_root,
        ) {
            return false;
        }
        if !valid_rotation_context(context) {
            return false;
        }
        if !valid_public_key(current_public_key) {
            return false;
        }
        if next_key.pk_seed.len() != HASH_LEN || next_key.hypertree_root.len() != HASH_LEN {
            return false;
        }

        // The recovery message signs the replacement bundle fields so callers do
        // not authorize a different stateful/stateless tuple accidentally.
        let recovery_message = self.full_rotation_message_hash(
            expected_pk_seed,
            expected_hypertree_root,
            current_public_key,
            context,
            next_key,
        );
        if !self.verify_stateless_raw_memory(
            expected_pk_seed,
            expected_hypertree_root,
            current_public_key,
            &recovery_message,
            recovery_signature,
        ) {
            return false;
        }
        true
    }

    /// Verify a raw stateless message.
    ///
    /// Same warning as `verify_stateful_unsafe_raw`: callers own replay
    /// protection and domain separation when they use this path.
    pub(crate) fn verify_stateless_unsafe_raw(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        // Low-level verifier path. The caller supplies the signed message directly,
        // so replay protection and domain separation are entirely caller-managed.
        if !matches_expected_stateless_key(public_key, expected_pk_seed, expected_hypertree_root) {
            return false;
        }
        self.verify_stateless_raw_memory(
            expected_pk_seed,
            expected_hypertree_root,
            public_key,
            message,
            signature,
        )
    }

    /// Build the canonical message hash for a stateless action.
    ///
    /// The only difference from the stateful action hash is the operation tag.
    /// That prevents a valid stateful authorization from being replayed as a
    /// stateless authorization or vice versa.
    pub fn stateless_action_message_hash(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        let op = hash_packed(&[b"shrincs-verify-stateless"]);
        hash_packed(&[
            &op,
            &HASH_SUITE_KECCAK_256.to_be_bytes(),
            &expected_pk_seed,
            &expected_hypertree_root,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &context.action_type,
            &context.payload_hash,
        ])
    }

    /// Build the canonical message hash for a compact Type 2 action.
    ///
    /// Compact slots are authorized separately, so this hash binds only the
    /// compact operation tag, hash suite, and account action context.
    ///
    /// Packed preimage:
    ///   OP_VERIFY_COMPACT32 || HASH_SUITE_KECCAK_2564 ||
    ///   domain_separator32 || nonce32 || key_version32 ||
    ///   action_type32 || payload_hash32.
    pub fn compact_action_message_hash(&self, context: &ActionContext) -> [u8; HASH_LEN] {
        let op = hash_packed(&[b"shrincs-verify-compact"]);
        hash_packed(&[
            &op,
            &HASH_SUITE_KECCAK_256.to_be_bytes(),
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &context.action_type,
            &context.payload_hash,
        ])
    }

    /// Build the compact slot id used by account wrapper storage.
    ///
    /// Packed preimage:
    ///   sub_pk_seed32 || sub_pk_root32.
    pub fn compact_slot_id(
        &self,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        hash_packed(&[sub_pk_seed, sub_pk_root])
    }

    /// Build the stateless authorization hash for compact slot registration.
    ///
    /// Packed preimage:
    ///   OP_REGISTER_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    ///   domain_separator32 || nonce32 || key_version32 ||
    ///   slot_id32 || sub_pk_seed32 || sub_pk_root32.
    pub fn compact_slot_registration_message_hash(
        &self,
        context: &RotationContext,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        let op = hash_packed(&[b"shrincs-register-compact-slot"]);
        self.compact_slot_update_message_hash(&op, context, sub_pk_seed, sub_pk_root)
    }

    /// Build the stateless authorization hash for compact slot revocation.
    ///
    /// Packed preimage:
    ///   OP_REVOKE_COMPACT_SLOT32 || HASH_SUITE_KECCAK_2564 ||
    ///   domain_separator32 || nonce32 || key_version32 ||
    ///   slot_id32 || sub_pk_seed32 || sub_pk_root32.
    pub fn compact_slot_revocation_message_hash(
        &self,
        context: &RotationContext,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        let op = hash_packed(&[b"shrincs-revoke-compact-slot"]);
        self.compact_slot_update_message_hash(&op, context, sub_pk_seed, sub_pk_root)
    }

    /// Build the canonical message hash for full key-bundle rotation.
    ///
    /// The next key bundle is first compressed into `next_key_bundle_hash`, then
    /// that hash is included in the signed rotation message.
    pub fn full_rotation_message_hash(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        next_key: &RotationTarget,
    ) -> [u8; HASH_LEN] {
        let op = hash_packed(&[b"shrincs-rotate-full"]);
        hash_packed(&[
            &op,
            &HASH_SUITE_KECCAK_256.to_be_bytes(),
            &expected_pk_seed,
            &expected_hypertree_root,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &current_public_key.pk_seed,
            &current_public_key.hypertree_root,
            &next_key.pk_seed,
            &next_key.hypertree_root,
        ])
    }

    fn compact_slot_update_message_hash(
        &self,
        op: &[u8; HASH_LEN],
        context: &RotationContext,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        let slot_id = self.compact_slot_id(sub_pk_seed, sub_pk_root);
        hash_packed(&[
            op,
            &HASH_SUITE_KECCAK_256.to_be_bytes(),
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &slot_id,
            sub_pk_seed,
            sub_pk_root,
        ])
    }

    fn verify_stateless_raw_memory(
        &self,
        expected_pk_seed: [u8; HASH_LEN],
        expected_hypertree_root: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        // The stateless verifier has two phases:
        // 1. FORS-C verifies the external message and yields a FORS root.
        // 2. The hypertree verifies that FORS root up to the committed hypertree root.
        if !matches_expected_stateless_key(public_key, expected_pk_seed, expected_hypertree_root) {
            return false;
        }
        if !valid_public_key(public_key) {
            return false;
        }
        if signature.hypertree.is_empty() {
            return false;
        }

        let first_layer = &signature.hypertree[0];
        let Some(fors_root) = verify_fors_c_and_return_root(
            public_key,
            message,
            &signature.fors,
            first_layer.tree_index,
            first_layer.leaf_index,
        ) else {
            return false;
        };
        verify_hypertree(public_key, fors_root, &signature.hypertree)
    }
}
