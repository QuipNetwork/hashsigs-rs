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
//! Performs context binding, rotation-message construction, and high-level parameter
//! checks, then delegates the cryptographic work to the same component modules
//! as the Solidity verifier (`ShrincsStateful`, `ShrincsForsC`, and
//! `ShrincsHypertree`).

#[path = "shrincs_verifier_fors_c.rs"]
mod shrincs_verifier_fors_c;
#[path = "shrincs_verifier_hypertree.rs"]
mod shrincs_verifier_hypertree;
#[path = "shrincs_verifier_stateful.rs"]
mod shrincs_verifier_stateful;
#[path = "shrincs_verifier_types.rs"]
mod shrincs_verifier_types;
#[path = "shrincs_verifier_utils.rs"]
mod shrincs_verifier_utils;

pub use self::shrincs_verifier_types::*;

use self::shrincs_verifier_fors_c::verify_fors_c_and_return_root;
use self::shrincs_verifier_hypertree::verify_hypertree;
use self::shrincs_verifier_stateful::verify_stateful_unsafe_raw as verify_stateful_raw_component;
use self::shrincs_verifier_utils::{
    decode_stateful_public_key, hash_packed, matches_expected_public_key_commitment,
    rotation_target_commitment, stateful_rotation_target_commitment, valid_action_context,
    valid_parameter_set_binding, valid_params, valid_rotation_context, word32,
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

    /// Return the fixed parameter view used by the Solidity verifier.
    ///
    /// Keeping this as an associated function matches the Solidity facade and
    /// makes call sites read as "this verifier's parameters".
    pub fn default_params_view(parameter_set_id: ParameterSetId) -> ParamsView {
        shrincs_verifier_types::default_params_view(parameter_set_id)
    }

    /// Verify a stateful signature over an action context.
    ///
    /// This is the safe account-style path. The caller provides structured
    /// context rather than raw bytes, and the verifier hashes that context into
    /// the exact message that must have been signed. This binds replay-control
    /// fields (`nonce`, `key_version`), domain separation, action type, payload,
    /// parameter set, hash suite, and expected installed public-key commitment.
    pub fn verify_stateful(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatefulSignature,
    ) -> bool {
        if !valid_action_context(context) {
            return false;
        }
        let message = self.stateful_action_message_hash(
            parameter_set_id,
            expected_public_key_commitment,
            context,
        );
        self.verify_stateful_unsafe_raw(
            parameter_set_id,
            expected_public_key_commitment,
            public_key,
            &message,
            signature,
        )
    }

    /// Verify a stateless signature over an action context.
    ///
    /// This follows the same safe-context pattern as `verify_stateful`, but it
    /// verifies the message through FORS-C and the hypertree rather than through
    /// the stateful WOTS-C tree.
    pub fn verify_stateless(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatelessSignature,
    ) -> bool {
        if !valid_action_context(context) {
            return false;
        }
        let message = self.stateless_action_message_hash(
            parameter_set_id,
            expected_public_key_commitment,
            context,
        );
        self.verify_stateless_raw_memory(
            parameter_set_id,
            expected_public_key_commitment,
            public_key,
            &message,
            signature,
        )
    }

    /// Rotate only the stateful key using a stateless recovery signature.
    ///
    /// The stateless key material remains unchanged. The recovery signature must
    /// authorize a message that binds the current installed-key commitment,
    /// rotation context, and the next installed-key commitment. If verification
    /// succeeds, the returned value is the replacement installed-key commitment.
    pub fn rotate_stateful_via_stateless(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        recovery_signature: &StatelessSignature,
        next_stateful_key: &StatefulRotationTarget,
    ) -> Option<[u8; HASH_LEN]> {
        let params = Self::default_params_view(parameter_set_id);
        // First prove that the current public key is the key the caller intended:
        // same requested parameter set, same declared parameter set, and same
        // expected installed-key commitment.
        if !valid_parameter_set_binding(
            &params,
            parameter_set_id,
            current_public_key.parameter_set_id,
        ) {
            return None;
        }
        if !matches_expected_public_key_commitment(
            current_public_key,
            expected_public_key_commitment,
        ) {
            return None;
        }
        if !valid_rotation_context(context) {
            return None;
        }
        if !valid_params(&params, current_public_key) {
            return None;
        }
        // The next stateful key is not trusted just because it was supplied. It
        // must declare the same parameter set and decode into a non-empty usage
        // budget before it can be signed into the rotation message.
        if !valid_parameter_set_binding(
            &params,
            parameter_set_id,
            next_stateful_key.parameter_set_id,
        ) {
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
            next_stateful_key.parameter_set_id,
            &next_stateful_key.stateful_public_key,
            &current_pk_seed,
            &current_hypertree_root,
        );
        if word32(&next_stateful_key.public_key_commitment) != Some(next_public_key_commitment) {
            return None;
        }

        let recovery_message = self.stateful_rotation_message_hash(
            parameter_set_id,
            expected_public_key_commitment,
            current_public_key,
            context,
            next_stateful_key,
        );
        if !self.verify_stateless_raw_memory(
            parameter_set_id,
            expected_public_key_commitment,
            current_public_key,
            &recovery_message,
            recovery_signature,
        ) {
            return None;
        }

        Some(next_public_key_commitment)
    }

    /// Rotate the full SHRINCS key bundle using a stateless recovery signature.
    ///
    /// This is stricter than `rotate_stateful_via_stateless`: every public
    /// component of the next bundle is supplied and signed into the recovery
    /// message before the next installed-key commitment is returned.
    pub fn stateless_rotate(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        recovery_signature: &StatelessSignature,
        next_key: &RotationTarget,
    ) -> Option<[u8; HASH_LEN]> {
        let params = Self::default_params_view(parameter_set_id);
        if !valid_parameter_set_binding(
            &params,
            parameter_set_id,
            current_public_key.parameter_set_id,
        ) {
            return None;
        }
        if !matches_expected_public_key_commitment(
            current_public_key,
            expected_public_key_commitment,
        ) {
            return None;
        }
        if !valid_rotation_context(context) {
            return None;
        }
        if !valid_params(&params, current_public_key) {
            return None;
        }
        if !valid_parameter_set_binding(&params, parameter_set_id, next_key.parameter_set_id) {
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

        // The recovery message signs the replacement bundle fields so callers do
        // not authorize a different stateful/stateless tuple accidentally.
        let recovery_message = self.full_rotation_message_hash(
            parameter_set_id,
            expected_public_key_commitment,
            current_public_key,
            context,
            next_key,
        );
        if !self.verify_stateless_raw_memory(
            parameter_set_id,
            expected_public_key_commitment,
            current_public_key,
            &recovery_message,
            recovery_signature,
        ) {
            return None;
        }
        Some(next_public_key_commitment)
    }

    /// Verify a raw stateful message.
    ///
    /// This is intentionally named "unsafe" to match Solidity: it is
    /// cryptographically valid, but it does not add nonce/domain/payload binding.
    /// Use `verify_stateful` unless the caller has already constructed a safe
    /// signed message externally.
    pub(crate) fn verify_stateful_unsafe_raw(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatefulSignature,
    ) -> bool {
        // Low-level verifier path. The caller supplies the signed message directly,
        // so replay protection and domain separation are entirely caller-managed.
        verify_stateful_raw_component(
            parameter_set_id,
            expected_public_key_commitment,
            public_key,
            message,
            signature,
        )
    }

    /// Verify a raw stateless message.
    ///
    /// Same warning as `verify_stateful_unsafe_raw`: callers own replay
    /// protection and domain separation when they use this path.
    #[cfg(any(test, feature = "wasm-bindings"))]
    pub(crate) fn verify_stateless_unsafe_raw(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        // Low-level verifier path. The caller supplies the signed message directly,
        // so replay protection and domain separation are entirely caller-managed.
        let params = Self::default_params_view(parameter_set_id);
        if !valid_parameter_set_binding(&params, parameter_set_id, public_key.parameter_set_id) {
            return false;
        }
        if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
            return false;
        }
        self.verify_stateless_raw_memory(
            parameter_set_id,
            expected_public_key_commitment,
            public_key,
            message,
            signature,
        )
    }

    /// Build the canonical message hash for a stateful action.
    ///
    /// This mirrors Solidity `abi.encodePacked` exactly: operation tag, parameter
    /// set byte, hash suite, expected installed-key commitment, and action context fields are
    /// concatenated and Keccak-hashed.
    pub fn stateful_action_message_hash(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        let params = Self::default_params_view(parameter_set_id);
        let op = hash_packed(&[b"shrincs-verify-stateful"]);
        hash_packed(&[
            &op,
            &[parameter_set_id.packed_byte()],
            &params.hash_suite_id.to_be_bytes(),
            &expected_public_key_commitment,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &context.action_type,
            &context.payload_hash,
        ])
    }

    /// Build the canonical message hash for a stateless action.
    ///
    /// The only difference from the stateful action hash is the operation tag.
    /// That prevents a valid stateful authorization from being replayed as a
    /// stateless authorization or vice versa.
    pub fn stateless_action_message_hash(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        let params = Self::default_params_view(parameter_set_id);
        let op = hash_packed(&[b"shrincs-verify-stateless"]);
        hash_packed(&[
            &op,
            &[parameter_set_id.packed_byte()],
            &params.hash_suite_id.to_be_bytes(),
            &expected_public_key_commitment,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &context.action_type,
            &context.payload_hash,
        ])
    }

    /// Build the canonical message hash for stateful-only rotation.
    ///
    /// This binds the current installed-key commitment and the replacement
    /// installed-key commitment. A signature over this hash cannot authorize a
    /// different replacement bundle.
    pub fn stateful_rotation_message_hash(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        next_stateful_key: &StatefulRotationTarget,
    ) -> [u8; HASH_LEN] {
        let params = Self::default_params_view(parameter_set_id);
        let op = hash_packed(&[b"shrincs-rotate-stateful"]);
        hash_packed(&[
            &op,
            &[parameter_set_id.packed_byte()],
            &params.hash_suite_id.to_be_bytes(),
            &expected_public_key_commitment,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &current_public_key.public_key_commitment,
            &next_stateful_key.public_key_commitment,
        ])
    }

    /// Build the canonical message hash for full key-bundle rotation.
    ///
    /// The next key bundle is first compressed into `next_key_bundle_hash`, then
    /// that hash is included in the signed rotation message.
    pub fn full_rotation_message_hash(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        current_public_key: &PublicKey,
        context: &RotationContext,
        next_key: &RotationTarget,
    ) -> [u8; HASH_LEN] {
        let params = Self::default_params_view(parameter_set_id);
        let op = hash_packed(&[b"shrincs-rotate-full"]);
        hash_packed(&[
            &op,
            &[parameter_set_id.packed_byte()],
            &params.hash_suite_id.to_be_bytes(),
            &expected_public_key_commitment,
            &context.domain_separator,
            &context.nonce,
            &context.key_version,
            &current_public_key.public_key_commitment,
            &next_key.public_key_commitment,
        ])
    }

    fn verify_stateless_raw_memory(
        &self,
        parameter_set_id: ParameterSetId,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        // The stateless verifier has two phases:
        // 1. FORS-C verifies the external message and yields a FORS root.
        // 2. The hypertree verifies that FORS root up to the committed hypertree root.
        if !matches_expected_public_key_commitment(public_key, expected_public_key_commitment) {
            return false;
        }
        let params = Self::default_params_view(parameter_set_id);
        if !valid_params(&params, public_key) {
            return false;
        }
        if signature.hypertree.is_empty() {
            return false;
        }

        let first_layer = &signature.hypertree[0];
        let Some(fors_root) = verify_fors_c_and_return_root(
            &params,
            public_key,
            message,
            &signature.fors,
            first_layer.tree_index,
            first_layer.leaf_index,
        ) else {
            return false;
        };
        verify_hypertree(&params, public_key, fors_root, &signature.hypertree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::signer::verifier::{
        ParameterSetId as SignerParameterSetId, PublicKey as SignerPublicKey,
        StatelessSignature as SignerStatelessSignature,
    };
    use crate::shrincs::ShrincsSigner;
    use solana_program::keccak::hash as keccak256_hash;

    fn to_public_key(input: &SignerPublicKey) -> PublicKey {
        PublicKey {
            parameter_set_id: match input.parameter_set_id {
                SignerParameterSetId::Sphincs256sKeccakQ20 => ParameterSetId::Sphincs256sKeccakQ20,
                SignerParameterSetId::Unsupported => ParameterSetId::Unsupported,
            },
            stateful_public_key: input.stateful_public_key.clone(),
            public_key_commitment: input.public_key_commitment.clone(),
            pk_seed: input.pk_seed.clone(),
            hypertree_root: input.hypertree_root.clone(),
        }
    }

    fn to_stateless_signature(input: &SignerStatelessSignature) -> StatelessSignature {
        StatelessSignature {
            fors: ForsSignature {
                randomizer: input.fors.randomizer.clone(),
                counter: input.fors.counter,
                entries: input
                    .fors
                    .entries
                    .iter()
                    .map(|entry| ForsEntry {
                        secret_leaf: entry.secret_leaf.clone(),
                        auth_path: entry.auth_path.clone(),
                    })
                    .collect(),
            },
            hypertree: input
                .hypertree
                .iter()
                .map(|layer| HypertreeLayerSignature {
                    tree_index: layer.tree_index,
                    leaf_index: layer.leaf_index,
                    wots_c_pk_hash: layer.wots_c_pk_hash.clone(),
                    wots_c_signature: WotsCSignature {
                        randomizer: layer.wots_c_signature.randomizer.clone(),
                        counter: layer.wots_c_signature.counter,
                        chains: layer.wots_c_signature.chains.clone(),
                    },
                    auth_path: layer.auth_path.clone(),
                })
                .collect(),
        }
    }

    fn public_key_commitment(
        parameter_set_id: ParameterSetId,
        stateful_public_key: &[u8],
        pk_seed: &[u8],
        hypertree_root: &[u8],
    ) -> [u8; HASH_LEN] {
        let mut packed = Vec::with_capacity(
            b"shrincs-public-key".len()
                + 1
                + stateful_public_key.len()
                + pk_seed.len()
                + hypertree_root.len(),
        );
        packed.extend_from_slice(b"shrincs-public-key");
        packed.push(parameter_set_id.packed_byte());
        packed.extend_from_slice(stateful_public_key);
        packed.extend_from_slice(pk_seed);
        packed.extend_from_slice(hypertree_root);
        keccak256_hash(&packed).to_bytes()
    }

    fn expected_key(public_key: &PublicKey) -> [u8; HASH_LEN] {
        public_key.public_key_commitment.clone().try_into().unwrap()
    }

    fn sample_action_context() -> ActionContext {
        ActionContext {
            domain_separator: [7u8; HASH_LEN],
            nonce: [1u8; HASH_LEN],
            key_version: [2u8; HASH_LEN],
            action_type: [3u8; HASH_LEN],
            payload_hash: [4u8; HASH_LEN],
        }
    }

    fn sample_rotation_context() -> RotationContext {
        RotationContext {
            domain_separator: [9u8; HASH_LEN],
            nonce: [5u8; HASH_LEN],
            key_version: [6u8; HASH_LEN],
        }
    }

    #[test]
    fn contexts_reject_zero_domain_values() {
        let zero = [0u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: zero,
            nonce: zero,
            key_version: zero,
            action_type: [1u8; HASH_LEN],
            payload_hash: [2u8; HASH_LEN],
        };
        assert!(!valid_action_context(&context));
    }

    #[test]
    fn verify_stateless_accepts_valid_action_signature() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"verifier stateless action seed",
            4,
        )
        .unwrap();
        let public_key = to_public_key(&public_key);
        let context = sample_action_context();
        let expected = expected_key(&public_key);
        let message = verifier.stateless_action_message_hash(
            ParameterSetId::Sphincs256sKeccakQ20,
            expected,
            &context,
        );
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        assert!(verifier.verify_stateless(
            ParameterSetId::Sphincs256sKeccakQ20,
            expected,
            &public_key,
            &context,
            &signature,
        ));
    }

    #[test]
    fn rotate_stateful_via_stateless_accepts_valid_recovery_signature() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"verifier stateful rotation current seed",
            4,
        )
        .unwrap();
        let (_, next_public_key) = ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"verifier stateful rotation next seed",
            8,
        )
        .unwrap();
        let public_key = to_public_key(&public_key);
        let context = sample_rotation_context();
        let expected = expected_key(&public_key);
        let next_commitment = public_key_commitment(
            ParameterSetId::Sphincs256sKeccakQ20,
            &next_public_key.stateful_public_key,
            &public_key.pk_seed,
            &public_key.hypertree_root,
        );
        let next_target = StatefulRotationTarget {
            parameter_set_id: ParameterSetId::Sphincs256sKeccakQ20,
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_commitment.to_vec(),
        };

        let recovery_message = verifier.stateful_rotation_message_hash(
            ParameterSetId::Sphincs256sKeccakQ20,
            expected,
            &public_key,
            &context,
            &next_target,
        );
        let recovery_signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &recovery_message).unwrap();
        let recovery_signature = to_stateless_signature(&recovery_signature);

        assert_eq!(
            verifier.rotate_stateful_via_stateless(
                ParameterSetId::Sphincs256sKeccakQ20,
                expected,
                &public_key,
                &context,
                &recovery_signature,
                &next_target,
            ),
            Some(next_commitment)
        );
    }

    #[test]
    fn stateless_rotate_accepts_valid_recovery_signature() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"verifier full rotation current seed",
            4,
        )
        .unwrap();
        let (_, next_public_key) = ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"verifier full rotation next seed",
            8,
        )
        .unwrap();
        let public_key = to_public_key(&public_key);
        let next_public_key = to_public_key(&next_public_key);
        let context = sample_rotation_context();
        let expected = expected_key(&public_key);
        let next_commitment = expected_key(&next_public_key);
        let next_target = RotationTarget {
            parameter_set_id: ParameterSetId::Sphincs256sKeccakQ20,
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_public_key.public_key_commitment.clone(),
            pk_seed: next_public_key.pk_seed.clone(),
            hypertree_root: next_public_key.hypertree_root.clone(),
        };

        let recovery_message = verifier.full_rotation_message_hash(
            ParameterSetId::Sphincs256sKeccakQ20,
            expected,
            &public_key,
            &context,
            &next_target,
        );
        let recovery_signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &recovery_message).unwrap();
        let recovery_signature = to_stateless_signature(&recovery_signature);

        assert_eq!(
            verifier.stateless_rotate(
                ParameterSetId::Sphincs256sKeccakQ20,
                expected,
                &public_key,
                &context,
                &recovery_signature,
                &next_target,
            ),
            Some(next_commitment)
        );
    }
}
