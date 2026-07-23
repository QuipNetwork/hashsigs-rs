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
//! `ShrincsSigner` derives seed material into a `ShrincsSigningKey` +
//! `PublicKey` pair and drives both signing paths: `uxmss` for the stateful
//! fast path, `sphincs_plus_c` for stateless recovery. Consumed by `account`
//! and `wasm` as the only place that advances signer-side state
//! (`next_stateful_leaf_index`).

use crate::primitives::hash::word32;
use crate::sphincs_plus_c::hypertree::hypertree_public_root;
use crate::sphincs_plus_c::{self, SphincsPlusCSigningKey};
use crate::types::{ActionContext, PublicKey, StatefulSignature, StatelessSignature, HASH_LEN};
use crate::shrincs::uxmss::{self, StatefulSecret};

pub use super::signer_types::{ShrincsSignerResult, ShrincsSigningKey};
use super::messages::stateful_action_message_hash;
use super::public_key::encode_stateful_public_key;
use super::signer_utils::{derive32, public_key_from_components};

/// Stateful SHRINCS signer implementing [`crate::signer::SignerInterface`].
///
/// Each [`sign_envelope`](crate::signer::SignerInterface::sign_envelope)
/// consumes a one-time UXMSS leaf and advances the key; it returns `None`
/// once the leaf budget is exhausted. Built via
/// [`ShrincsSigner::into_stateful_signer`].
pub struct ShrincsStatefulSigner {
    signing_key: ShrincsSigningKey,
    public_key: PublicKey,
}

impl ShrincsStatefulSigner {
    /// The hybrid public-key bundle.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The signing key (leaf state advances as signatures are produced).
    pub fn signing_key(&self) -> &ShrincsSigningKey {
        &self.signing_key
    }

    /// Leaves remaining before the stateful budget is exhausted.
    pub fn remaining_stateful_signatures(&self) -> u32 {
        self.signing_key
            .max_stateful_signatures
            .saturating_sub(self.signing_key.next_stateful_leaf_index.saturating_sub(1))
    }
}

impl crate::signer::SignerInterface for ShrincsStatefulSigner {
    fn sign_envelope(&mut self, hash: &[u8; HASH_LEN]) -> Option<alloc::vec::Vec<u8>> {
        // The verifier signs the raw 32-byte hash as the message (matching
        // `ShrincsVerifier::verify_envelope`'s unchecked stateful path).
        let signature = ShrincsSigner::sign_stateful_raw(&mut self.signing_key, hash)?;
        Some(crate::envelope::encode_stateful_envelope(
            &self.public_key,
            &signature,
        ))
    }

    fn verifying_key(&self) -> alloc::vec::Vec<u8> {
        self.public_key.public_key_commitment.clone()
    }
}

#[cfg(test)]
use crate::shrincs::ShrincsVerifier;

pub struct ShrincsSigner;

const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;
const MAX_STATEFUL_SIGNATURES_LIMIT: u32 = 4096;

fn stateless_trace_enabled() -> bool {
    #[cfg(feature = "std")]
    {
        matches!(
            std::env::var("SHRINCS_TRACE_STATELESS").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        )
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

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
        let stateful_root = uxmss::stateful_subtree_root(
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

    /// Reconstruct a signing key from previously exported fields (the inverse
    /// of the wasm `shrincsKeygen`'s `secretKey` output, consumed by
    /// `shrincsImportSigningKey`). Enforces the same bounds as `keygen`,
    /// accepts the exhausted state (`next == max + 1`, which
    /// `sign_stateful_raw` legitimately produces), and recomputes both roots
    /// from the seeds — returns `None` if the candidate's stored roots don't
    /// match (corrupted or field-spliced input). The rebuilt `PublicKey`
    /// (including the commitment) is derived, never taken from the caller.
    pub fn import_signing_key(
        candidate: ShrincsSigningKey,
    ) -> ShrincsSignerResult<(ShrincsSigningKey, PublicKey)> {
        let max = candidate.max_stateful_signatures;
        if max == 0 || max > MAX_STATEFUL_SIGNATURES_LIMIT {
            return None;
        }
        let next = candidate.next_stateful_leaf_index;
        if next < INITIAL_STATEFUL_LEAF_INDEX || next > max.saturating_add(1) {
            return None;
        }
        // Recompute, never trust: the roots are consensus-critical inputs to
        // every signature this key will produce. The stateful root always
        // covers the full tree from leaf 1 — independent of `next`.
        let stateful_root = uxmss::stateful_subtree_root(
            &candidate.stateful_sk_seed,
            &candidate.stateful_pk_seed,
            INITIAL_STATEFUL_LEAF_INDEX,
            max,
        );
        let hypertree_root =
            hypertree_public_root(&candidate.stateless_sk_seed, &candidate.pk_seed);
        if stateful_root != candidate.stateful_root
            || hypertree_root != candidate.hypertree_root
        {
            return None;
        }
        let public_key = public_key_from_components(
            encode_stateful_public_key(candidate.stateful_pk_seed, stateful_root, max),
            candidate.pk_seed,
            hypertree_root,
        );
        Some((candidate, public_key))
    }

    /// Sign the verifier's canonical stateful action hash and advance the leaf counter.
    pub fn sign_stateful_action(
        signing_key: &mut ShrincsSigningKey,
        public_key: &PublicKey,
        context: &ActionContext,
    ) -> ShrincsSignerResult<StatefulSignature> {
        let expected = word32(&public_key.public_key_commitment)?;
        let message = stateful_action_message_hash(expected, context);
        sign_stateful_via_uxmss(signing_key, &message)
    }

    /// Sign raw bytes with the next unused stateful leaf.
    pub fn sign_stateful_raw(
        signing_key: &mut ShrincsSigningKey,
        message: &[u8],
    ) -> ShrincsSignerResult<StatefulSignature> {
        sign_stateful_via_uxmss(signing_key, message)
    }

    /// Bundle a signing key with its public key into a stateful signer that
    /// implements [`crate::signer::SignerInterface`].
    pub fn into_stateful_signer(
        signing_key: ShrincsSigningKey,
        public_key: PublicKey,
    ) -> ShrincsStatefulSigner {
        ShrincsStatefulSigner {
            signing_key,
            public_key,
        }
    }

    /// Sign raw bytes with a caller-supplied stateful leaf; does NOT advance the
    /// counter. Test-only: the wasm surface dropped its `signStatefulRawAt`
    /// binding (see the wasm-noble delivery report) in favor of the
    /// noble-style `shrincsSign`/`shrincsSignStateless` free functions.
    #[cfg(test)]
    pub(crate) fn sign_stateful_raw_at_leaf(
        signing_key: &ShrincsSigningKey,
        leaf_index: u32,
        message: &[u8],
    ) -> ShrincsSignerResult<StatefulSignature> {
        sign_stateful_at_leaf_via_uxmss(signing_key, leaf_index, message)
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
        if stateless_trace_enabled() {
            hashsigs_println!(
                "stateless trace: signer start message_len={}",
                message.len()
            );
        }
        let spk = SphincsPlusCSigningKey {
            stateless_sk_seed: signing_key.stateless_sk_seed,
            stateless_prf_seed: signing_key.stateless_prf_seed,
            pk_seed: signing_key.pk_seed,
            hypertree_root: signing_key.hypertree_root,
        };
        let sig = sphincs_plus_c::sign(&spk, message)?;
        if stateless_trace_enabled() {
            hashsigs_println!("stateless trace: signer done");
        }
        Some(sig)
    }
}

fn sign_stateful_via_uxmss(
    signing_key: &mut ShrincsSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    let mut secret = StatefulSecret {
        sk_seed: signing_key.stateful_sk_seed,
        prf_seed: signing_key.stateful_prf_seed,
        pk_seed: signing_key.stateful_pk_seed,
        max_signatures: signing_key.max_stateful_signatures,
        next_leaf_index: signing_key.next_stateful_leaf_index,
    };
    let sig = uxmss::sign_stateful_raw(&mut secret, message)?;
    signing_key.next_stateful_leaf_index = secret.next_leaf_index;
    Some(sig)
}

#[cfg(test)]
fn sign_stateful_at_leaf_via_uxmss(
    signing_key: &ShrincsSigningKey,
    leaf_index: u32,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    let secret = StatefulSecret {
        sk_seed: signing_key.stateful_sk_seed,
        prf_seed: signing_key.stateful_prf_seed,
        pk_seed: signing_key.stateful_pk_seed,
        max_signatures: signing_key.max_stateful_signatures,
        next_leaf_index: signing_key.next_stateful_leaf_index,
    };
    uxmss::sign_stateful_raw_at_leaf(&secret, leaf_index, message)
}


#[cfg(test)]
mod tests {
    use crate::types::HASH_LEN;
    use crate::shrincs::test_fixtures::{
        fixture_entry_opt, fixture_pair, fixture_path, load_fixture_file,
        stateful_signer_fixture_path, TestKeyMode,
    };
    use crate::primitives::hash::hash_packed;
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    use crate::test_support::stateful_only_key;


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

    fn fixture_or_fresh_full_key(
        seed_label: &'static str,
        max_stateful_signatures: u32,
    ) -> (ShrincsSigningKey, PublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => ShrincsSigner::keygen(
                seed_label.as_bytes(),
                max_stateful_signatures,
            )
            .unwrap_or_else(|| {
                panic!("fresh keygen failed for seed label {seed_label:?}")
            }),
            TestKeyMode::Fixture => {
                let path = fixture_path();
                if path.is_file() {
                    let fixture_file = load_fixture_file(&path);
                    assert_eq!(
                        fixture_file.profile_name,
                        crate::primitives::profiles::PROFILE_NAME,
                        "fixture profile mismatch",
                    );
                    if let Some(entry) = fixture_entry_opt(&fixture_file, seed_label) {
                        return fixture_pair(entry);
                    }
                }
                ShrincsSigner::keygen(seed_label.as_bytes(), max_stateful_signatures)
                    .unwrap_or_else(|| {
                        panic!("fresh keygen failed for seed label {seed_label:?}")
                    })
            }
        }
    }

    fn fixture_or_stateful_only_key(
        seed_label: &'static str,
        max_stateful_signatures: u32,
    ) -> (ShrincsSigningKey, PublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => stateful_only_key(seed_label.as_bytes(), max_stateful_signatures),
            TestKeyMode::Fixture => {
                let path = stateful_signer_fixture_path();
                if path.is_file() {
                    let fixture_file = load_fixture_file(&path);
                    assert_eq!(
                        fixture_file.profile_name,
                        crate::primitives::profiles::PROFILE_NAME,
                        "fixture profile mismatch",
                    );
                    if let Some(entry) = fixture_entry_opt(&fixture_file, seed_label) {
                        return fixture_pair(entry);
                    }
                }
                stateful_only_key(seed_label.as_bytes(), max_stateful_signatures)
            }
        }
    }

    // The 256s profile pins these exact counts; the 128s profiles use a
    // different tuple (h=18, d=1, len=32), so this constant-identity check is
    // scoped to the default build. 256s behaviour is unchanged.
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn signer_constants_match_verifier_constants() {
        use crate::primitives::profiles::{
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
        use crate::primitives::profiles::HASH_TRUNC_LEN;
        let seed = b"128s stateful truncation seed";
        let max = 4u32;
        let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed, &[]);
        let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed, &[]);
        let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed, &[]);
        let stateful_root = uxmss::stateful_subtree_root(
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
        assert_eq!(
            &signature.auth_path[1][HASH_TRUNC_LEN..],
            &[0u8; HASH_LEN - HASH_TRUNC_LEN]
        );
        assert_ne!(
            &signature.auth_path[1][..HASH_TRUNC_LEN],
            &[0u8; HASH_TRUNC_LEN]
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s full keygen remains manual; stateful signer behavior is covered by stateful fixtures"
    )]
    #[test]
    fn keygen_is_deterministic_for_same_seed_material() {
        let (signing_key_a, public_key_a) =
            fixture_or_fresh_full_key("deterministic keygen seed", 4);
        let (signing_key_b, public_key_b) =
            fixture_or_fresh_full_key("deterministic keygen seed", 4);

        assert_eq!(signing_key_a, signing_key_b);
        assert_eq!(public_key_a, public_key_b);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s full keygen remains manual; stateful signer behavior is covered by stateful fixtures"
    )]
    #[test]
    fn keygen_public_key_uses_single_stateless_seed_and_root() {
        let (_, public_key) = fixture_or_fresh_full_key("deterministic keygen seed", 4);

        assert_eq!(
            public_key.stateful_public_key.len(),
            crate::types::STATEFUL_PUBLIC_KEY_BYTES
        );
        assert_eq!(public_key.public_key_commitment.len(), HASH_LEN);
        assert_eq!(public_key.pk_seed.len(), HASH_LEN);
        assert_eq!(public_key.hypertree_root.len(), HASH_LEN);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s full keygen remains manual; stateful signer behavior is covered by stateful fixtures"
    )]
    #[test]
    fn keygen_starts_stateful_signer_at_leaf_one() {
        let (signing_key, _) = fixture_or_fresh_full_key("deterministic keygen seed", 4);

        assert_eq!(
            signing_key.next_stateful_leaf_index,
            INITIAL_STATEFUL_LEAF_INDEX
        );
    }

    #[test]
    fn generated_stateful_signature_verifies() {
        let (mut signing_key, public_key) = fixture_or_stateful_only_key("stateful signer seed", 4);
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
        let (mut signing_key, public_key) = fixture_or_stateful_only_key("action signer seed", 4);
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
            fixture_or_stateful_only_key("explicit leaf helper seed", 4);
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

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn stateless_sign_via_sphincs_plus_c_verifies_hybrid_and_independent() {
        use crate::sphincs_plus_c::{self, SphincsPlusCPublicKey, SphincsPlusCSigningKey};
        let (signing_key, public_key) =
            fixture_or_fresh_full_key("sphincs-plus-c hybrid cross-check", 4);
        let message = hash_packed(&[b"sphincs-plus-c-hybrid-cross"]);
        let spk = SphincsPlusCSigningKey {
            stateless_sk_seed: signing_key.stateless_sk_seed,
            stateless_prf_seed: signing_key.stateless_prf_seed,
            pk_seed: signing_key.pk_seed,
            hypertree_root: signing_key.hypertree_root,
        };
        let sig = sphincs_plus_c::sign(&spk, &message).expect("independent sign");
        let pk = SphincsPlusCPublicKey {
            pk_seed: signing_key.pk_seed,
            hypertree_root: signing_key.hypertree_root,
        };
        assert!(sphincs_plus_c::verify(&pk, &message, &sig));
        let expected = expected_key(&public_key);
        assert!(ShrincsVerifier::new().verify_stateless_unsafe_raw(
            expected,
            &public_key,
            &message,
            &sig,
        ));
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
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
            fixture_or_stateful_only_key("stateful exhaustion seed", 1);
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
            fixture_or_stateful_only_key("stateful negative seed", 4);
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
        let (mut signing_key, public_key) = fixture_or_stateful_only_key("action negative seed", 4);
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

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn stateless_signature_rejects_wrong_message_and_tampered_hypertree_path() {
        let (signing_key, public_key) =
            fixture_or_fresh_full_key("stateless negative seed", 2);
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

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn stateless_signature_rejects_malformed_lengths() {
        let (signing_key, public_key) =
            fixture_or_fresh_full_key("stateless malformed seed", 2);
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
            fixture_or_stateful_only_key("public key negative seed", 4);
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

    #[test]
    fn import_round_trips_a_keygen_key() {
        let (key, pk) = ShrincsSigner::keygen(b"import round trip seed", 4).unwrap();
        let (imported_key, imported_pk) = ShrincsSigner::import_signing_key(key).unwrap();
        let (key_again, _) = ShrincsSigner::keygen(b"import round trip seed", 4).unwrap();
        assert_eq!(imported_key, key_again);
        assert_eq!(imported_pk, pk);
    }

    #[test]
    fn import_accepts_advanced_and_exhausted_counters() {
        let (mut key, _) = ShrincsSigner::keygen(b"import counter seed", 4).unwrap();
        key.next_stateful_leaf_index = 3;
        let (imported, _) = ShrincsSigner::import_signing_key(key).unwrap();
        assert_eq!(imported.next_stateful_leaf_index, 3);

        let (mut key, _) = ShrincsSigner::keygen(b"import counter seed", 4).unwrap();
        key.next_stateful_leaf_index = 5; // max + 1: exhausted, still valid
        let (imported, _) = ShrincsSigner::import_signing_key(key).unwrap();
        assert!(ShrincsSigner::sign_stateful_raw(
            &mut { imported },
            b"no leaves left"
        )
        .is_none());
    }

    #[test]
    fn import_rejects_out_of_range_counters_and_budgets() {
        let (mut key, _) = ShrincsSigner::keygen(b"import bounds seed", 4).unwrap();
        key.next_stateful_leaf_index = 0;
        assert!(ShrincsSigner::import_signing_key(key).is_none());

        let (mut key, _) = ShrincsSigner::keygen(b"import bounds seed", 4).unwrap();
        key.next_stateful_leaf_index = 6; // max + 2
        assert!(ShrincsSigner::import_signing_key(key).is_none());

        let (mut key, _) = ShrincsSigner::keygen(b"import bounds seed", 4).unwrap();
        key.max_stateful_signatures = 0;
        assert!(ShrincsSigner::import_signing_key(key).is_none());

        let (mut key, _) = ShrincsSigner::keygen(b"import bounds seed", 4).unwrap();
        key.max_stateful_signatures = 4097; // > MAX_STATEFUL_SIGNATURES_LIMIT
        assert!(ShrincsSigner::import_signing_key(key).is_none());
    }

    #[test]
    fn import_rejects_tampered_roots() {
        let (mut key, _) = ShrincsSigner::keygen(b"import tamper seed", 4).unwrap();
        key.stateful_root[0] ^= 0x01;
        assert!(ShrincsSigner::import_signing_key(key).is_none());

        let (mut key, _) = ShrincsSigner::keygen(b"import tamper seed", 4).unwrap();
        key.hypertree_root[0] ^= 0x01;
        assert!(ShrincsSigner::import_signing_key(key).is_none());

        // Field splice: seeds from one key, roots from another.
        let (key_a, _) = ShrincsSigner::keygen(b"import splice seed A", 4).unwrap();
        let (mut key_b, _) = ShrincsSigner::keygen(b"import splice seed B", 4).unwrap();
        key_b.stateful_root = key_a.stateful_root;
        assert!(ShrincsSigner::import_signing_key(key_b).is_none());
    }

    #[test]
    fn imported_key_signs_and_verifies() {
        let (mut key, _) = ShrincsSigner::keygen(b"import sign seed", 4).unwrap();
        key.next_stateful_leaf_index = 2;
        let (mut imported, pk) = ShrincsSigner::import_signing_key(key).unwrap();
        let message = b"signed after import".to_vec();
        let signature = ShrincsSigner::sign_stateful_raw(&mut imported, &message).unwrap();
        assert_eq!(signature.auth_path.len(), 2);
        let expected = word32(&pk.public_key_commitment).unwrap();
        assert!(ShrincsVerifier::new().verify_stateful_unsafe_raw(
            expected,
            &pk,
            &message,
            &signature
        ));
    }

    // Boundary coverage for the stateful tree: the lowest live leaf (1) and the
    // budget leaf (leaf == max_signatures) must both round-trip, and an empty
    // message must round-trip while a signature over `&[]` must not verify a
    // one-byte message. Uses the placeholder-hypertree key so it runs on every
    // profile. (Bead 0lh.)
    #[test]
    fn stateful_boundary_leaves_and_empty_message_round_trip() {
        let budget = 4u32;
        let (signing_key, public_key) = stateful_only_key(b"stateful boundary seed", budget);
        let expected = expected_key(&public_key);
        let verifier = ShrincsVerifier::new();
        let message = hash_packed(&[b"stateful boundary message"]);

        // Leaf 1: the first live leaf.
        let leaf_one = ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 1, &message).unwrap();
        assert_eq!(leaf_one.auth_path.len(), 1);
        assert!(verifier.verify_stateful_unsafe_raw(expected, &public_key, &message, &leaf_one));

        // Leaf == budget: the last usable leaf.
        let leaf_budget =
            ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, budget, &message).unwrap();
        assert_eq!(leaf_budget.auth_path.len(), budget as usize);
        assert!(verifier.verify_stateful_unsafe_raw(expected, &public_key, &message, &leaf_budget));

        // Empty message round-trips; the same signature must reject a 1-byte message.
        let empty = ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 1, &[]).unwrap();
        assert!(verifier.verify_stateful_unsafe_raw(expected, &public_key, &[], &empty));
        assert!(!verifier.verify_stateful_unsafe_raw(expected, &public_key, &[0u8], &empty));
    }

    // Stateless boundary: an empty message signs and verifies through FORS-C plus
    // the full hypertree, and the FORS-C opening carries exactly `num_fors_trees
    // - 1` entries (the omitted final tree is forced to leaf index 0). The
    // empty-message signature must not verify a one-byte message. (Bead 0lh.)
    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn stateless_empty_message_round_trip_and_fors_boundary() {
        use crate::primitives::profiles::NUM_FORS_TREES;
        let (signing_key, public_key) =
            fixture_or_fresh_full_key("stateless empty message seed", 2);
        let expected = expected_key(&public_key);
        let verifier = ShrincsVerifier::new();

        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &[]).unwrap();
        // FORS-C forces the omitted final tree's leaf to 0: only k - 1 entries.
        assert_eq!(signature.fors.entries.len(), NUM_FORS_TREES as usize - 1);
        assert!(verifier.verify_stateless_unsafe_raw(expected, &public_key, &[], &signature));

        // A signature over `&[]` must not verify a different (1-byte) message.
        assert!(!verifier.verify_stateless_unsafe_raw(expected, &public_key, &[0u8], &signature));
    }

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        // Modest case count: each case builds a placeholder-hypertree stateful
        // key and grinds one WOTS-C signature. (Bead aur.)
        #![proptest_config(ProptestConfig::with_cases(24))]

        // Sign->verify round-trip plus the universal single-byte-tamper-rejects
        // property over the stateful WOTS-C path, across random messages
        // (including empty), leaves, and tamper positions.
        #[test]
        fn stateful_sign_verify_round_trip_and_single_byte_tamper_rejects(
            message in proptest::collection::vec(any::<u8>(), 0..48usize),
            leaf in 1u32..=4,
            tamper_chain in 0usize..crate::primitives::profiles::WOTS_CHAINS_STATEFUL,
            tamper_byte in 0usize..HASH_LEN,
        ) {
            let (signing_key, public_key) = stateful_only_key(b"proptest stateful seed", 4);
            let expected = word32(&public_key.public_key_commitment).unwrap();
            let verifier = ShrincsVerifier::new();
            let signature =
                ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, leaf, &message).unwrap();

            // Round-trip: a freshly produced signature verifies.
            prop_assert!(verifier.verify_stateful_unsafe_raw(
                expected,
                &public_key,
                &message,
                &signature
            ));

            // Flipping any single byte of any revealed WOTS chain value breaks the
            // reconstruction to the committed public-key hash, so verification
            // must reject.
            let mut tampered = signature;
            tampered.chains[tamper_chain][tamper_byte] ^= 1;
            prop_assert!(!verifier.verify_stateful_unsafe_raw(
                expected,
                &public_key,
                &message,
                &tampered
            ));
        }
    }
}
