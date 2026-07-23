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


//! Independent SPHINCS+C stateless layer.
//!
//! Mirrors Solidity `SPHINCSPlusC.sol`: key = (pk_seed, hypertree_root), message
//! is arbitrary bytes (or raw 32-byte hash via `to_message` / `verify_hash`).
//! No SHRINCS public-key-bundle commitment and no action envelope.

use crate::primitives::hash::word32;
use crate::types::{StatelessSignature, HASH_LEN};

/// Stateless SPHINCS+C public key: public seed + hypertree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SphincsPlusCPublicKey {
    pub pk_seed: [u8; HASH_LEN],
    pub hypertree_root: [u8; HASH_LEN],
}

impl SphincsPlusCPublicKey {
    pub fn from_slices(pk_seed: &[u8], hypertree_root: &[u8]) -> Option<Self> {
        Some(Self {
            pk_seed: word32(pk_seed)?,
            hypertree_root: word32(hypertree_root)?,
        })
    }
}

/// Convert a 32-byte hash into the signed message bytes.
/// The hash IS the message: exactly its 32 bytes.
pub fn to_message(hash: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    *hash
}

/// Verify a SPHINCS+C signature over an arbitrary message.
pub fn verify(pk: &SphincsPlusCPublicKey, message: &[u8], sig: &StatelessSignature) -> bool {
    verify_raw(&pk.pk_seed, &pk.hypertree_root, message, sig)
}

/// Verify a SPHINCS+C signature over a 32-byte hash.
pub fn verify_hash(
    pk: &SphincsPlusCPublicKey,
    hash: &[u8; HASH_LEN],
    sig: &StatelessSignature,
) -> bool {
    verify(pk, &to_message(hash), sig)
}

/// Core verify: FORS-C then hypertree (byte-identical to prior `verify_stateless_raw`).
pub(crate) fn verify_raw(
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
    message: &[u8],
    signature: &StatelessSignature,
) -> bool {
    if signature.hypertree.is_empty() {
        return false;
    }
    let Some((fors_root, seed_tree_index, seed_leaf_index)) =
        fors_c::verify_fors_c_and_return_root(pk_seed, hypertree_root, message, &signature.fors)
    else {
        return false;
    };
    hypertree::verify_hypertree(
        pk_seed,
        hypertree_root,
        fors_root,
        hypertree::HypertreeSeed {
            tree_index: seed_tree_index,
            leaf_index: seed_leaf_index,
        },
        &signature.hypertree,
    )
}

// Canonical definition lives in `types` (the leaf module) so `fors_c` and
// `hypertree` accept it without importing upward; re-exported here because
// this layer is its public home.
pub use crate::types::SphincsPlusCSigningKey;

pub(crate) mod fors_c;
pub(crate) mod hypertree;

/// Verifier-interface facade (opaque key/signature bytes, tri-state verdict).
pub mod verifier;
pub use verifier::SphincsPlusCVerifier;

/// Stateless SPHINCS+C signer implementing [`crate::signer::SignerInterface`].
///
/// Holds the signing key plus its 64-byte verifying key (`pkSeed‖hypertreeRoot`).
/// Signing never mutates observable state; the `&mut self` in the trait is
/// only there for the stateful sibling.
#[derive(Clone)]
pub struct SphincsPlusCSigner {
    signing_key: SphincsPlusCSigningKey,
    public_key: SphincsPlusCPublicKey,
}

impl SphincsPlusCSigner {
    /// Build a signer from seed material (the [`keygen`] inputs).
    pub fn from_seeds(
        stateless_sk_seed: [u8; HASH_LEN],
        stateless_prf_seed: [u8; HASH_LEN],
        pk_seed: [u8; HASH_LEN],
    ) -> Self {
        let (signing_key, public_key) = keygen(stateless_sk_seed, stateless_prf_seed, pk_seed);
        Self {
            signing_key,
            public_key,
        }
    }

    /// The independent public key (`pkSeed`, `hypertreeRoot`).
    pub fn public_key(&self) -> &SphincsPlusCPublicKey {
        &self.public_key
    }

    /// The signing key material.
    pub fn signing_key(&self) -> &SphincsPlusCSigningKey {
        &self.signing_key
    }
}

impl crate::signer::SignerInterface for SphincsPlusCSigner {
    fn sign_envelope(&mut self, hash: &[u8; HASH_LEN]) -> Option<alloc::vec::Vec<u8>> {
        let signature = sign(&self.signing_key, &to_message(hash))?;
        Some(crate::envelope::encode_stateless_signature_envelope(
            &signature,
        ))
    }

    fn verifying_key(&self) -> alloc::vec::Vec<u8> {
        let mut key = alloc::vec::Vec::with_capacity(64);
        key.extend_from_slice(&self.public_key.pk_seed);
        key.extend_from_slice(&self.public_key.hypertree_root);
        key
    }
}

/// Sign an arbitrary message at the SPHINCS+C layer.
pub fn sign(
    signing_key: &SphincsPlusCSigningKey,
    message: &[u8],
) -> Option<StatelessSignature> {
    let signed_fors = fors_c::sign_fors_c(signing_key, message)?;
    let hypertree_layers = hypertree::sign_hypertree(
        signing_key,
        signed_fors.root,
        signed_fors.tree_index,
        signed_fors.leaf_index,
    )?;
    Some(StatelessSignature {
        fors: signed_fors.signature,
        hypertree: hypertree_layers,
    })
}

/// Derive the SPHINCS+C signing key and public key from raw seed material.
///
/// `hypertree_root` is computed here (the SPHINCS+C "keygen" step); this is
/// the only public entry point that produces a real (non-placeholder) root,
/// so downstream consumers (tests, on-chain fixtures) do not need crate-
/// internal access to build a fully independent SPHINCS+C keypair.
/// `stateless_prf_seed` only affects signing randomness, not the public key.
pub fn keygen(
    stateless_sk_seed: [u8; HASH_LEN],
    stateless_prf_seed: [u8; HASH_LEN],
    pk_seed: [u8; HASH_LEN],
) -> (SphincsPlusCSigningKey, SphincsPlusCPublicKey) {
    let hypertree_root = hypertree::hypertree_public_root(&stateless_sk_seed, &pk_seed);
    let signing_key = SphincsPlusCSigningKey {
        stateless_sk_seed,
        stateless_prf_seed,
        pk_seed,
        hypertree_root,
    };
    let public_key = SphincsPlusCPublicKey {
        pk_seed,
        hypertree_root,
    };
    (signing_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    use crate::primitives::hash::hash_packed;

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    fn derive32(domain: &[u8], seed: &[u8]) -> [u8; HASH_LEN] {
        hash_packed(&[domain, seed, &[]])
    }

    /// Independent keygen at the SPHINCS+C layer (no SHRINCS hybrid fields).
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    fn independent_keygen(seed: &[u8]) -> (SphincsPlusCSigningKey, SphincsPlusCPublicKey) {
        keygen(
            derive32(b"shrincs-stateless-sk-seed", seed),
            derive32(b"shrincs-stateless-prf-seed", seed),
            derive32(b"shrincs-pk-seed", seed),
        )
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn sphincs_plus_c_sign_verify_round_trip() {
        let (sk, pk) = independent_keygen(b"sphincs-plus-c independent rt");
        let message = hash_packed(&[b"sphincs-plus-c-rt-message"]);
        let sig = sign(&sk, &message).expect("sign");
        assert!(verify(&pk, &message, &sig));
        assert!(verify_hash(&pk, &message, &sig));
        // verifier key shape: pk_seed || hypertree_root
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&pk.pk_seed);
        key[32..].copy_from_slice(&pk.hypertree_root);
        assert!(crate::sphincs_plus_c::verifier::SphincsPlusCVerifier::new().verify(
            &key,
            &message,
            &sig,
        ));
    }

    #[test]
    fn to_message_is_identity() {
        let h = [0xabu8; 32];
        assert_eq!(to_message(&h), h);
    }

    /// Solana compute-unit estimator for one stateless verify.
    ///
    /// The verify-path hash count is a per-profile structural constant: WOTS-C's
    /// target-sum check fixes total chain-walk steps at
    /// `chains * (w-1) - target_sum` regardless of message, and the FORS /
    /// auth-path counts are structural. This asserts the exact count against
    /// the analytic model, then prints the agave syscall charge
    /// `calls * 85 + Σ_slices max(10, len/2)` (agave `SyscallHash`) — a floor:
    /// SBF instruction execution and instruction deserialization come on top.
    ///
    /// Excluded under `parallel` (rayon workers would record into their own
    /// thread-local counters) and under the 128s profiles (signing there is
    /// too slow for the default-profile test lanes; the structural model
    /// covers them analytically).
    #[cfg(all(
        feature = "std",
        not(feature = "parallel"),
        not(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))
    ))]
    #[test]
    fn stateless_verify_hash_count_matches_model_and_reports_cu_floor() {
        use crate::primitives::hash_backend::metrics;
        use crate::primitives::profiles::{
            FORS_TREE_HEIGHT, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
            NUM_WOTS_CHAINS, WOTS_CHAIN_LEN, WOTS_TARGET_SUM_STATELESS,
        };

        let (sk, pk) = independent_keygen(b"sphincs-plus-c cu estimator");
        let message = hash_packed(&[b"sphincs-plus-c-cu-message"]);
        let sig = sign(&sk, &message).expect("sign");

        metrics::reset();
        assert!(verify(&pk, &message, &sig));
        let (calls, bytes, slice_cost) = metrics::snapshot();

        let signed_trees = u64::from(NUM_FORS_TREES) - 1;
        let digest_bytes = (u64::from(NUM_FORS_TREES) * u64::from(FORS_TREE_HEIGHT)
            + u64::from(HYPERTREE_HEIGHT))
        .div_ceil(8);
        let fors_digest_blocks = if digest_bytes <= 32 {
            1
        } else {
            digest_bytes.div_ceil(32)
        };
        // Per signed FORS tree: one leaf hash + one node hash per level; plus
        // the aggregate fors-pk hash.
        let fors_calls =
            fors_digest_blocks + signed_trees * (1 + u64::from(FORS_TREE_HEIGHT)) + 1;
        // Per hypertree layer: WOTS message digest + fixed chain-walk total +
        // wots-c-pk hash + one node hash per subtree auth-path level.
        let subtree_height = u64::from(HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS);
        let chain_steps = u64::from(NUM_WOTS_CHAINS) * u64::from(WOTS_CHAIN_LEN - 1)
            - u64::from(WOTS_TARGET_SUM_STATELESS);
        let per_layer = 1 + chain_steps + 1 + subtree_height;
        let expected_calls = fors_calls + u64::from(NUM_HYPERTREE_LAYERS) * per_layer;
        assert_eq!(calls, expected_calls, "verify hash-count model drifted");

        let cu_floor = metrics::estimated_syscall_cu(calls, slice_cost);
        hashsigs_println!(
            "CU estimate profile={}: stateless verify = {calls} hash syscalls, \
             {bytes} bytes hashed, syscall floor ≈ {cu_floor} CU \
             (excludes SBF instruction execution and borsh deserialization)",
            crate::primitives::profiles::PROFILE_NAME
        );
    }
}
