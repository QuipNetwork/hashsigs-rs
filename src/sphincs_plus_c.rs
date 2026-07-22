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

use crate::fors_c;
use crate::hash::word32;
use crate::hypertree;
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

/// Convert an ERC-7913 32-byte hash into the signed message bytes.
/// The hash IS the message: exactly its 32 bytes.
pub fn to_message(hash: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    *hash
}

/// Verify a SPHINCS+C signature over an arbitrary message.
pub fn verify(pk: &SphincsPlusCPublicKey, message: &[u8], sig: &StatelessSignature) -> bool {
    verify_raw(&pk.pk_seed, &pk.hypertree_root, message, sig)
}

/// Verify a SPHINCS+C signature over a 32-byte hash (ERC-7913 shape).
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
        seed_tree_index,
        seed_leaf_index,
        &signature.hypertree,
    )
}

/// Secret material required to sign at the SPHINCS+C layer alone.
#[derive(Debug, Clone, Copy)]
pub struct SphincsPlusCSigningKey {
    pub stateless_sk_seed: [u8; HASH_LEN],
    pub stateless_prf_seed: [u8; HASH_LEN],
    pub pk_seed: [u8; HASH_LEN],
    pub hypertree_root: [u8; HASH_LEN],
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
    use crate::hash::hash_packed;

    fn derive32(domain: &[u8], seed: &[u8]) -> [u8; HASH_LEN] {
        hash_packed(&[domain, seed, &[]])
    }

    /// Independent keygen at the SPHINCS+C layer (no SHRINCS hybrid fields).
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
        // ERC-7913 key shape: pk_seed || hypertree_root
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&pk.pk_seed);
        key[32..].copy_from_slice(&pk.hypertree_root);
        assert!(crate::sphincs_plus_c_verifier::SphincsPlusCVerifier::new().verify(
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
}
