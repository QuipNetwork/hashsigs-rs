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

//! Public SHRINCS key generation and signing facade.
//!
//! - `shrincs_signer_stateful` builds stateful WOTS-C signatures.
//! - `shrincs_signer_fors_c` opens the fixed FORS forest for a message digest.
//! - `shrincs_signer_hypertree` carries the FORS root to the hypertree root.

#[cfg(test)]
#[path = "verifier.rs"]
pub(crate) mod verifier;

#[cfg(not(test))]
pub(crate) use super::verifier;

#[path = "shrincs_signer_fors_c.rs"]
mod shrincs_signer_fors_c;
#[path = "shrincs_signer_hypertree.rs"]
mod shrincs_signer_hypertree;
#[path = "shrincs_signer_stateful.rs"]
mod shrincs_signer_stateful;
#[path = "shrincs_signer_types.rs"]
mod shrincs_signer_types;
#[path = "shrincs_signer_utils.rs"]
mod shrincs_signer_utils;

pub use self::shrincs_signer_types::{ShrincsSignerResult, ShrincsSigningKey};

use self::shrincs_signer_fors_c::sign_fors_c;
use self::shrincs_signer_hypertree::{hypertree_public_root, sign_hypertree};
#[cfg(test)]
use self::shrincs_signer_stateful::sign_stateful_raw_at_leaf as sign_stateful_raw_at_leaf_inner;
use self::shrincs_signer_stateful::{
    sign_stateful_raw as sign_stateful_raw_inner, stateful_subtree_root,
};
use self::shrincs_signer_utils::{
    derive32, encode_stateful_public_key, public_key_from_components, word32,
};
use self::verifier::{
    ActionContext, PublicKey, ShrincsVerifier, StatefulSignature, StatelessSignature,
};

pub struct ShrincsSigner;

const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;
const MAX_STATEFUL_SIGNATURES_LIMIT: u32 = 4096;

impl ShrincsSigner {
    /// Deterministically derive signing material and a public key from seed material.
    ///
    /// The public key contains one stateful tree plus one stateless `PK.seed`
    /// and hypertree `PK.root`. The message-specific FORS root is derived
    /// during signing and authenticated by the hypertree.
    pub fn keygen(
        seed_material: &[u8],
        max_stateful_signatures: u32,
    ) -> ShrincsSignerResult<(ShrincsSigningKey, PublicKey)> {
        if max_stateful_signatures == 0 {
            return None;
        }
        if max_stateful_signatures > MAX_STATEFUL_SIGNATURES_LIMIT {
            return None;
        }

        let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed_material, &[]);
        let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed_material, &[]);
        let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed_material, &[]);
        let stateful_root = stateful_subtree_root(
            &stateful_sk_seed,
            &stateful_pk_seed,
            INITIAL_STATEFUL_LEAF_INDEX,
            max_stateful_signatures,
        );
        let stateless_sk_seed = derive32(b"shrincs-stateless-sk-seed", seed_material, &[]);
        let stateless_prf_seed = derive32(b"shrincs-stateless-prf-seed", seed_material, &[]);
        let pk_seed = derive32(b"shrincs-pk-seed", seed_material, &[]);
        let hypertree_root = hypertree_public_root(&stateless_sk_seed, &pk_seed);

        let signing_key = ShrincsSigningKey {
            stateful_sk_seed,
            stateful_prf_seed,
            stateful_pk_seed,
            stateful_root,
            max_stateful_signatures,
            next_stateful_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
            stateless_sk_seed,
            stateless_prf_seed,
            pk_seed,
            hypertree_root,
        };
        let public_key = public_key_from_components(
            encode_stateful_public_key(stateful_pk_seed, stateful_root, max_stateful_signatures),
            pk_seed,
            hypertree_root,
        );

        Some((signing_key, public_key))
    }

    /// Sign the verifier's canonical stateful action hash and advance the leaf counter.
    pub fn sign_stateful_action(
        signing_key: &mut ShrincsSigningKey,
        public_key: &PublicKey,
        context: &ActionContext,
    ) -> ShrincsSignerResult<StatefulSignature> {
        let expected = word32(&public_key.public_key_commitment)?;
        let verifier = ShrincsVerifier::new();
        let message = verifier.stateful_action_message_hash(expected, context);
        sign_stateful_raw_inner(signing_key, &message)
    }

    /// Sign raw bytes with the next unused stateful leaf.
    pub fn sign_stateful_raw(
        signing_key: &mut ShrincsSigningKey,
        message: &[u8],
    ) -> ShrincsSignerResult<StatefulSignature> {
        sign_stateful_raw_inner(signing_key, message)
    }

    /// Sign raw bytes with a specific stateful leaf for deterministic tests.
    #[cfg(test)]
    pub(crate) fn sign_stateful_raw_at_leaf(
        signing_key: &ShrincsSigningKey,
        leaf_index: u32,
        message: &[u8],
    ) -> ShrincsSignerResult<StatefulSignature> {
        sign_stateful_raw_at_leaf_inner(signing_key, leaf_index, message)
    }

    /// Sign raw bytes with FORS-C plus the hypertree.
    ///
    /// The signature verifies under the long-lived public key returned by
    /// `keygen`; the message-specific FORS root is carried only inside the
    /// signature/hypertree flow.
    pub fn sign_stateless_raw(
        signing_key: &ShrincsSigningKey,
        message: &[u8],
    ) -> ShrincsSignerResult<StatelessSignature> {
        let signed_fors = sign_fors_c(signing_key, message)?;
        let hypertree = sign_hypertree(
            signing_key,
            signed_fors.root,
            signed_fors.tree_index,
            signed_fors.leaf_index,
        )?;
        Some(StatelessSignature {
            fors: signed_fors.signature,
            hypertree,
        })
    }
}

#[cfg(test)]
mod tests {
    use self::verifier::HASH_LEN;
    use super::shrincs_signer_utils::hash_packed;
    use super::*;

    fn action_context() -> ActionContext {
        ActionContext {
            domain_separator: [7u8; HASH_LEN],
            nonce: [1u8; HASH_LEN],
            key_version: [2u8; HASH_LEN],
            action_type: [3u8; HASH_LEN],
            payload_hash: [4u8; HASH_LEN],
        }
    }

    fn expected_key(public_key: &PublicKey) -> [u8; HASH_LEN] {
        word32(&public_key.public_key_commitment).unwrap()
    }

    // The 256s profile pins these exact counts; the 128s profiles use a
    // different tuple (h=18, d=1, len=32), so this constant-identity check is
    // scoped to the default build. 256s behaviour is unchanged.
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn signer_constants_match_verifier_constants() {
        use self::verifier::{
            HYPERTREE_HEIGHT, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, WOTS_CHAIN_LEN,
        };
        assert_eq!(HASH_LEN, 32);
        assert_eq!(HYPERTREE_HEIGHT, 64);
        assert_eq!(NUM_HYPERTREE_LAYERS, 8);
        assert_eq!(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS, 8);
        assert_eq!(NUM_WOTS_CHAINS, 64);
        assert_eq!(WOTS_CHAIN_LEN, 16);
    }

    // 128s stateless keygen/signing (a 2^18-leaf hypertree and 2^24-leaf FORS
    // trees) is computationally infeasible in-process, so the 128s truncation
    // path is proven through the feasible stateful subsystem. The stateful
    // verifier never rebuilds the hypertree, so a signing key with a placeholder
    // hypertree root exercises the real stateful WOTS-C and unbalanced-tree
    // hashing at n=16. This also confirms `mask_hash` actually truncates: every
    // masked node value must have a zero low half.
    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    #[test]
    fn stateful_round_trip_verifies_under_128s_truncation() {
        let seed = b"128s stateful truncation seed";
        let max = 4u32;
        let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed, &[]);
        let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed, &[]);
        let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed, &[]);
        let stateful_root = stateful_subtree_root(
            &stateful_sk_seed,
            &stateful_pk_seed,
            INITIAL_STATEFUL_LEAF_INDEX,
            max,
        );
        let pk_seed = derive32(b"shrincs-pk-seed", seed, &[]);
        // Placeholder: a real hypertree root is infeasible here and irrelevant to
        // the stateful path, but it is still committed by the public key.
        let hypertree_root = derive32(b"placeholder-hypertree-root", seed, &[]);

        let signing_key = ShrincsSigningKey {
            stateful_sk_seed,
            stateful_prf_seed,
            stateful_pk_seed,
            stateful_root,
            max_stateful_signatures: max,
            next_stateful_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
            stateless_sk_seed: derive32(b"shrincs-stateless-sk-seed", seed, &[]),
            stateless_prf_seed: derive32(b"shrincs-stateless-prf-seed", seed, &[]),
            pk_seed,
            hypertree_root,
        };
        let public_key = public_key_from_components(
            encode_stateful_public_key(stateful_pk_seed, stateful_root, max),
            pk_seed,
            hypertree_root,
        );
        let expected = word32(&public_key.public_key_commitment).unwrap();
        let message = hash_packed(&[b"128s stateful message"]);

        let signature =
            ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 2, &message).unwrap();
        assert_eq!(signature.auth_path.len(), 2);
        assert!(ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));

        // Truncation actually happened: the second auth-path node is a masked
        // `uxmss-wots-pk` leaf, so its low (HASH_LEN - HASH_TRUNC_LEN) bytes are
        // zero while its high half is not. At 256s this assertion would fail.
        assert_eq!(&signature.auth_path[1][16..], &[0u8; 16]);
        assert_ne!(&signature.auth_path[1][..16], &[0u8; 16]);
    }

    #[test]
    fn keygen_is_deterministic_for_same_seed_material() {
        let (signing_key_a, public_key_a) =
            ShrincsSigner::keygen(b"deterministic keygen seed", 4).unwrap();
        let (signing_key_b, public_key_b) =
            ShrincsSigner::keygen(b"deterministic keygen seed", 4).unwrap();

        assert_eq!(signing_key_a, signing_key_b);
        assert_eq!(public_key_a, public_key_b);
    }

    #[test]
    fn keygen_public_key_uses_single_stateless_seed_and_root() {
        let (_, public_key) = ShrincsSigner::keygen(b"public key structure seed", 8).unwrap();

        assert_eq!(
            public_key.stateful_public_key.len(),
            verifier::STATEFUL_PUBLIC_KEY_BYTES
        );
        assert_eq!(public_key.public_key_commitment.len(), HASH_LEN);
        assert_eq!(public_key.pk_seed.len(), HASH_LEN);
        assert_eq!(public_key.hypertree_root.len(), HASH_LEN);
    }

    #[test]
    fn keygen_starts_stateful_signer_at_leaf_one() {
        let (signing_key, _) = ShrincsSigner::keygen(b"initial stateful leaf seed", 8).unwrap();

        assert_eq!(
            signing_key.next_stateful_leaf_index,
            INITIAL_STATEFUL_LEAF_INDEX
        );
    }

    #[test]
    fn generated_stateful_signature_verifies() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"stateful signer seed", 4).unwrap();
        let expected = expected_key(&public_key);
        let message = hash_packed(&[b"stateful test message"]);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        // Positive example matching `lib.rs`: a signer-generated signature must
        // verify against the public key returned by the same key generation.
        assert!(ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));
    }

    #[test]
    fn generated_stateful_action_signature_verifies() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"action signer seed", 4).unwrap();
        let context = action_context();
        let expected = expected_key(&public_key);
        let signature =
            ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context).unwrap();

        // The safe action path signs the verifier's canonical action hash, not
        // caller-supplied raw bytes.
        assert!(ShrincsVerifier::new().verify_stateful(
            expected,
            &public_key,
            &context,
            &signature,
        ));
    }

    #[test]
    fn explicit_leaf_test_helper_verifies_for_requested_leaf() {
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"explicit leaf helper seed", 4).unwrap();
        let expected = expected_key(&public_key);
        let message = hash_packed(&[b"explicit leaf test message"]);
        let signature =
            ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 2, &message).unwrap();

        assert_eq!(signature.auth_path.len(), 2);
        assert!(ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));
    }

    #[test]
    fn generated_stateless_raw_signature_verifies() {
        let (signing_key, public_key) = ShrincsSigner::keygen(b"stateless signer seed", 2).unwrap();
        let message = hash_packed(&[b"stateless test"]);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let expected = expected_key(&public_key);

        // Stateless signatures should verify through the FORS-C opening and all
        // hypertree layers up to the generated hypertree public root.
        assert!(ShrincsVerifier::new().verify_stateless_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));
    }

    #[test]
    fn keygen_rejects_empty_or_excessive_stateful_budget() {
        assert!(ShrincsSigner::keygen(b"seed", 0).is_none());
        assert!(ShrincsSigner::keygen(b"seed", MAX_STATEFUL_SIGNATURES_LIMIT + 1).is_none());
    }

    #[test]
    fn stateful_signing_advances_leaf_and_rejects_exhaustion() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"stateful exhaustion seed", 1).unwrap();
        let expected = expected_key(&public_key);
        let message = hash_packed(&[b"first and only stateful signature"]);

        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        assert_eq!(
            signing_key.next_stateful_leaf_index,
            INITIAL_STATEFUL_LEAF_INDEX + 1
        );
        assert!(ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));

        // The stateful signer is one-time per leaf. With a budget of one, the
        // next signing attempt must fail instead of reusing the previous leaf.
        assert!(ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).is_none());
    }

    #[test]
    fn stateful_signature_rejects_wrong_message_and_tampered_chain() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"stateful negative seed", 4).unwrap();
        let expected = expected_key(&public_key);
        let message = hash_packed(&[b"stateful valid message"]);
        let wrong_message = hash_packed(&[b"stateful wrong message"]);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let verifier = ShrincsVerifier::new();

        // Equivalent to the invalid-message test in `lib.rs`: the signature is
        // bound to the exact message hash that was signed.
        assert!(!verifier.verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &wrong_message,
            &signature,
        ));

        let mut tampered = signature.clone();
        tampered.chains[0][0] ^= 1;
        // Equivalent to the invalid-signature test in `lib.rs`: mutating a WOTS
        // chain value prevents reconstruction of the committed public key hash.
        assert!(!verifier.verify_stateful_unsafe_raw(expected, &public_key, &message, &tampered,));
    }

    #[test]
    fn stateful_action_rejects_tampered_context() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"action negative seed", 4).unwrap();
        let expected = expected_key(&public_key);
        let context = action_context();
        let signature =
            ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context).unwrap();

        let mut tampered_context = context;
        tampered_context.nonce[31] ^= 1;

        // Safe action verification hashes the structured context, so changing a
        // replay-control field invalidates the same signature.
        assert!(!ShrincsVerifier::new().verify_stateful(
            expected,
            &public_key,
            &tampered_context,
            &signature,
        ));
    }

    #[test]
    fn stateless_signature_rejects_wrong_message_and_tampered_hypertree_path() {
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"stateless negative seed", 2).unwrap();
        let message = hash_packed(&[b"stateless valid message"]);
        let wrong_message = hash_packed(&[b"stateless wrong message"]);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let expected = expected_key(&public_key);
        let verifier = ShrincsVerifier::new();

        // The FORS-C digest binds the stateless signature to the signed raw
        // message, so a different message must not verify.
        assert!(!verifier.verify_stateless_unsafe_raw(
            expected,
            &public_key,
            &wrong_message,
            &signature,
        ));

        let mut tampered = signature.clone();
        tampered.hypertree[0].auth_path[0][0] ^= 1;
        // A changed auth-path sibling should stop the verifier from climbing to
        // the committed hypertree root.
        assert!(!verifier.verify_stateless_unsafe_raw(expected, &public_key, &message, &tampered,));
    }

    #[test]
    fn stateless_signature_rejects_malformed_lengths() {
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"stateless malformed seed", 2).unwrap();
        let message = hash_packed(&[b"stateless malformed message"]);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let expected = expected_key(&public_key);
        let verifier = ShrincsVerifier::new();

        let mut missing_layer = signature.clone();
        missing_layer.hypertree.pop();
        // Similar to the invalid-signature-length test in `lib.rs`: the
        // hypertree must carry exactly one proof per configured layer.
        assert!(!verifier.verify_stateless_unsafe_raw(
            expected,
            &public_key,
            &message,
            &missing_layer,
        ));

        let mut missing_chain = signature;
        missing_chain.hypertree[0].wots_c_signature.chains.pop();
        // Each WOTS-C signature must include one chain value for every configured
        // WOTS chain.
        assert!(!verifier.verify_stateless_unsafe_raw(
            expected,
            &public_key,
            &message,
            &missing_chain,
        ));
    }

    #[test]
    fn public_key_commitment_rejects_tampered_component() {
        let (mut signing_key, mut public_key) =
            ShrincsSigner::keygen(b"public key negative seed", 4).unwrap();
        let expected = expected_key(&public_key);
        let message = hash_packed(&[b"public key commitment message"]);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        public_key.stateful_public_key[0] ^= 1;

        // Like a serialization/round-trip check in spirit: the composite key is
        // a commitment to every public-key component, so changing one component
        // while keeping the old expected commitment must be rejected.
        assert!(!ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &public_key,
            &message,
            &signature,
        ));
    }
}
