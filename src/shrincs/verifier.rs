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

use crate::envelope;
use crate::primitives::hash::keccak_packed;
use crate::sphincs_plus_c::verifier::SphincsPlusCVerifier;
use crate::verifier::VerifyOutcome;
// Wire types/constants live in `crate::types` after the restructure. Re-export
// them here so the historical path `hashsigs_rs::shrincs::verifier::*` still
// resolves (main used `pub use self::shrincs_verifier_types::*`).
pub use crate::types::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, RotationContext,
    RotationTarget, StatefulPublicKey, StatefulRotationTarget, StatefulSignature,
    StatelessSignature, WotsCSignature, ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE,
    ADDRESS_TYPE_WOTS_HASH, HASH_LEN, HASH_SUITE_KECCAK_256, STATEFUL_PUBLIC_KEY_BYTES,
};
// Profile parameter tuple also lived in main's shrincs_verifier_types (via
// `pub use profile::*`); re-export from the current profiles module.
pub use crate::primitives::profiles::{
    FORS_TREE_HEIGHT, HASH_TRUNC_LEN, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
    NUM_WOTS_CHAINS, PROFILE_NAME, STATELESS_SIGNATURE_LIMIT, WOTS_BASE_STATEFUL, WOTS_CHAIN_LEN,
    WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
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

impl ShrincsVerifier {
    /// `keccak256("quip.shrincs-verifier.v1")`. Mirrors
    /// `SHRINCSVerifier.VERSION_TAG`: names this verifier's key/envelope
    /// format family, not the compiled parameter profile.
    pub fn version_tag() -> [u8; HASH_LEN] {
        keccak_packed(&[b"quip.shrincs-verifier.v1"])
    }

    /// Stateless verify through the verifier interface shapes, delegated to the pinned SPHINCS+C sibling.
    /// Mirrors `SHRINCSVerifier.verifyStateless`: decode the commitment key,
    /// run `envelope::prepare_stateless_delegation` (mirroring
    /// `SHRINCS.prepareStatelessDelegation`) to extract the delegate
    /// `(pkSeed, hypertreeRoot)` key and re-encoded signature envelope, then
    /// hand both to `SphincsPlusCVerifier::verify`, exactly like the
    /// Solidity adapter's external call to its pinned sibling.
    pub fn verify_stateless_envelope(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        stateless_envelope: &[u8],
    ) -> VerifyOutcome {
        let Some(commitment) = envelope::decode_public_key_commitment(key) else {
            return VerifyOutcome::Invalid;
        };
        // `prepare_stateless_delegation` folds envelope-decode failure,
        // commitment mismatch, and public-key shape failure into a single
        // `None` (see envelope.rs's doc comment on that function). Decode
        // once more here, purely to split "framing that can't be read at
        // all" (Malformed) from "well-formed but rejected" (Invalid),
        // without duplicating its commitment/shape-check logic.
        if envelope::decode_stateless_envelope(stateless_envelope).is_none() {
            return VerifyOutcome::Malformed;
        }
        let Some((delegate_key, delegate_signature_envelope)) =
            super::prepare_stateless_delegation(commitment, stateless_envelope)
        else {
            return VerifyOutcome::Invalid;
        };
        // `prepare_stateless_delegation` hands back a re-encoded signature
        // envelope, not a typed signature — Solidity's zero-copy calldata
        // pointer aliasing has no Rust equivalent here, so this decodes it
        // straight back into the typed form `SphincsPlusCVerifier::verify`
        // expects (an encode-then-decode round trip the Solidity adapter
        // never pays).
        let Some(delegate_signature) =
            envelope::decode_stateless_signature_envelope(&delegate_signature_envelope)
        else {
            // `prepare_stateless_delegation` only ever emits a canonically
            // re-encoded envelope for a delegation it accepted, so this
            // should be unreachable; fail closed as Malformed rather than
            // silently treating a codec-internal inconsistency as Invalid.
            return VerifyOutcome::Malformed;
        };
        if SphincsPlusCVerifier::new().verify(&delegate_key, hash, &delegate_signature) {
            VerifyOutcome::Valid
        } else {
            VerifyOutcome::Invalid
        }
    }
}

impl crate::verifier::VerifierInterface for ShrincsVerifier {
    /// Stateful verify: `key` is the 32-byte SHRINCS `publicKeyCommitment`; Mirrors `SHRINCSVerifier.verify` /
    /// `SHRINCS.verify`: `key` must be exactly 32 bytes (the SHRINCS
    /// `publicKeyCommitment`); `signature_envelope` is
    /// `abi.encode(PublicKey, SHRINCS.Signature)`.
    fn verify_envelope(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        signature_envelope: &[u8],
    ) -> VerifyOutcome {
        let Some(commitment) = envelope::decode_public_key_commitment(key) else {
            return VerifyOutcome::Invalid;
        };
        let Some((public_key, signature)) =
            envelope::decode_stateful_envelope(signature_envelope)
        else {
            return VerifyOutcome::Malformed;
        };
        // `SHRINCS.verify` packs the bytes32 hash into the signed message as
        // its raw 32 bytes (`SPHINCSPlusC.toMessage`); `hash` IS the message.
        if super::verify_stateful_unsafe_raw(commitment, &public_key, hash, &signature) {
            VerifyOutcome::Valid
        } else {
            VerifyOutcome::Invalid
        }
    }
}

#[cfg(test)]
use crate::verifier::VerifierInterface as _;

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::shrincs::{PublicKey, ShrincsSigner, StatelessSignature};

    fn keypair(seed: &[u8]) -> (crate::shrincs::ShrincsSigningKey, PublicKey) {
        ShrincsSigner::keygen(seed, 4).expect("keygen must succeed for a valid seed/budget")
    }

    fn commitment_of(public_key: &PublicKey) -> Vec<u8> {
        public_key.public_key_commitment.clone()
    }

    // --- version tag -------------------------------------------------------

    #[test]
    fn version_tag_matches_pinned_solidity_constant() {
        // keccak256("quip.shrincs-verifier.v1"), computed independently and
        // pinned here so drift in either the literal string or the hash
        // routine fails loud instead of silently matching itself.
        const EXPECTED: [u8; HASH_LEN] = [
            0x06, 0x4b, 0x5b, 0x1b, 0x1f, 0x5d, 0x6d, 0xc3, 0xd3, 0x8c, 0x8e, 0xd9, 0xf3, 0x8f,
            0xd2, 0x4f, 0x68, 0x62, 0x83, 0x29, 0xf9, 0x32, 0x9a, 0x54, 0xb8, 0xe8, 0xc5, 0x3e,
            0x3b, 0x06, 0xda, 0x58,
        ];
        assert_eq!(ShrincsVerifier::version_tag(), EXPECTED);
    }

    // --- stateful verify -----------------------------------------------------

    #[test]
    fn verify_accepts_a_valid_stateful_signature_over_the_raw_hash() {
        let (mut signing_key, public_key) = keypair(b"verifier stateful accept seed");
        let hash = [0x42u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let outcome =
            ShrincsVerifier::new().verify_envelope(&commitment_of(&public_key), &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[test]
    fn verify_rejects_a_signature_over_a_different_hash() {
        let (mut signing_key, public_key) = keypair(b"verifier stateful reject seed");
        let hash = [0x11u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let wrong_hash = [0x22u8; HASH_LEN];
        let outcome = ShrincsVerifier::new().verify_envelope(
            &commitment_of(&public_key),
            &wrong_hash,
            &envelope,
        );
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn verify_rejects_a_wrong_length_key() {
        let (mut signing_key, public_key) = keypair(b"verifier stateful wrong key seed");
        let hash = [0x33u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let mut short_key = commitment_of(&public_key);
        short_key.pop();
        let outcome = ShrincsVerifier::new().verify_envelope(&short_key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn verify_reports_a_truncated_envelope_as_malformed() {
        let (mut signing_key, public_key) = keypair(b"verifier stateful malformed seed");
        let hash = [0x44u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let outcome = ShrincsVerifier::new().verify_envelope(
            &commitment_of(&public_key),
            &hash,
            &envelope[..envelope.len() - 1],
        );
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }

    #[test]
    fn verify_reports_an_empty_envelope_as_malformed() {
        let (_signing_key, public_key) = keypair(b"verifier stateful empty seed");
        let hash = [0x55u8; HASH_LEN];
        let outcome =
            ShrincsVerifier::new().verify_envelope(&commitment_of(&public_key), &hash, &[]);
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }

    // --- stateless verify ------------------------------------------------

    #[test]
    fn verify_stateless_accepts_a_valid_stateless_signature_over_the_raw_hash() {
        let (signing_key, public_key) = keypair(b"verifier stateless accept seed");
        let hash = [0x66u8; HASH_LEN];
        let signature: StatelessSignature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let outcome = ShrincsVerifier::new().verify_stateless_envelope(
            &commitment_of(&public_key),
            &hash,
            &envelope,
        );
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[test]
    fn verify_stateless_rejects_a_signature_over_a_different_hash() {
        let (signing_key, public_key) = keypair(b"verifier stateless reject seed");
        let hash = [0x77u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let wrong_hash = [0x88u8; HASH_LEN];
        let outcome = ShrincsVerifier::new().verify_stateless_envelope(
            &commitment_of(&public_key),
            &wrong_hash,
            &envelope,
        );
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn verify_stateless_rejects_a_wrong_length_key() {
        let (signing_key, public_key) = keypair(b"verifier stateless wrong key seed");
        let hash = [0x99u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let mut short_key = commitment_of(&public_key);
        short_key.pop();
        let outcome =
            ShrincsVerifier::new().verify_stateless_envelope(&short_key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn verify_stateless_reports_a_mismatched_commitment_as_invalid_not_malformed() {
        let (signing_key, public_key) = keypair(b"verifier stateless wrong commitment seed");
        let hash = [0xaau8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let mut wrong_commitment = commitment_of(&public_key);
        wrong_commitment[0] ^= 0x01;
        let outcome = ShrincsVerifier::new().verify_stateless_envelope(
            &wrong_commitment,
            &hash,
            &envelope,
        );
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[test]
    fn verify_stateless_reports_a_truncated_envelope_as_malformed() {
        let (signing_key, public_key) = keypair(b"verifier stateless malformed seed");
        let hash = [0xbbu8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let outcome = ShrincsVerifier::new().verify_stateless_envelope(
            &commitment_of(&public_key),
            &hash,
            &envelope[..envelope.len() - 1],
        );
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }

    #[test]
    fn verify_stateless_reports_an_empty_envelope_as_malformed() {
        let (_signing_key, public_key) = keypair(b"verifier stateless empty seed");
        let hash = [0xccu8; HASH_LEN];
        let outcome = ShrincsVerifier::new().verify_stateless_envelope(
            &commitment_of(&public_key),
            &hash,
            &[],
        );
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }
}
