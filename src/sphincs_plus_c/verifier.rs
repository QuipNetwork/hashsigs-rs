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


//! Verifier-interface facade for the independent SPHINCS+C scheme.
//!
//! Key = (pk_seed || hypertree_root) as two 32-byte words. Input is an arbitrary
//! 32-byte hash. No SHRINCS commitment or action envelope.

use crate::sphincs_plus_c::{self, PublicKey};
use crate::types::{StatelessSignature, HASH_LEN};

/// Independent stateless-only verifier (Solidity `SPHINCSPlusCVerifier` shape).
pub struct SphincsPlusCVerifier;

impl Default for SphincsPlusCVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SphincsPlusCVerifier {
    pub fn new() -> Self {
        Self
    }

    /// `keccak256("quip.sphincsplusc-verifier.v1")`. Mirrors
    /// `SPHINCSPlusCVerifier.VERSION_TAG`: names this verifier's key/envelope
    /// format family, not the compiled parameter profile.
    pub fn version_tag() -> [u8; HASH_LEN] {
        crate::primitives::hash::keccak_packed(&[b"quip.sphincsplusc-verifier.v1"])
    }

    /// Verify a SPHINCS+C signature over a 32-byte hash.
    ///
    /// `key` is `pk_seed || hypertree_root` (exactly 64 bytes).
    pub fn verify(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        if key.len() != 64 {
            return false;
        }
        let Some(pk) = PublicKey::from_slices(&key[..32], &key[32..64]) else {
            return false;
        };
        sphincs_plus_c::verify_hash(&pk, hash, signature)
    }

    /// Verify with an already-decoded public key.
    pub fn verify_with_pk(
        &self,
        pk: &PublicKey,
        hash: &[u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        sphincs_plus_c::verify_hash(pk, hash, signature)
    }

    /// Verify over arbitrary message bytes (non-verifier-interface helper).
    pub fn verify_message(
        &self,
        pk: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        sphincs_plus_c::verify(pk, message, signature)
    }
}

impl crate::verifier::VerifierInterface for SphincsPlusCVerifier {
    /// `key` is the 64-byte `pkSeed || hypertreeRoot`; `signature` is the
    /// stateless signature envelope (`abi.encode(SPHINCSPlusC.Signature)`).
    fn verify_envelope(
        &self,
        key: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> crate::verifier::VerifyOutcome {
        use crate::verifier::VerifyOutcome;
        if key.len() != 64 {
            return VerifyOutcome::Invalid;
        }
        let Some(decoded) = crate::envelope::decode_stateless_signature_envelope(signature)
        else {
            return VerifyOutcome::Malformed;
        };
        let mut hash32 = [0u8; 32];
        hash32.copy_from_slice(hash);
        if self.verify(key, &hash32, &decoded) {
            VerifyOutcome::Valid
        } else {
            VerifyOutcome::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    use crate::envelope;
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    use crate::verifier::{VerifierInterface, VerifyOutcome};

    #[test]
    fn version_tag_matches_pinned_solidity_constant() {
        // keccak256("quip.sphincsplusc-verifier.v1"), computed independently
        // and pinned here so drift in either the literal string or the hash
        // routine fails loud instead of silently matching itself.
        const EXPECTED: [u8; HASH_LEN] = [
            0xb3, 0xee, 0x3b, 0x4a, 0x95, 0x9f, 0xcc, 0xaf, 0x76, 0xdc, 0xbb, 0x8f, 0x88, 0x7c,
            0x05, 0xff, 0xe4, 0xbd, 0x73, 0xd8, 0x80, 0x32, 0xd7, 0xe2, 0xe5, 0xfd, 0xc8, 0x3a,
            0x67, 0x17, 0x29, 0xa8,
        ];
        assert_eq!(SphincsPlusCVerifier::version_tag(), EXPECTED);
    }

    /// Build a 64-byte `pk_seed || hypertree_root` key and a signed hash +
    /// stateless envelope for `VerifierInterface` tests. Gated off the 128s
    /// profiles because independent SPHINCS+C keygen/sign grinds too hard.
    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    fn signed_stateless_envelope(
        seed_label: &[u8],
        hash: [u8; HASH_LEN],
    ) -> ([u8; 64], Vec<u8>) {
        use crate::primitives::hash::hash_packed;
        use crate::sphincs_plus_c;

        let sk_seed = hash_packed(&[b"sphincs-plus-c-verifier-sk", seed_label]);
        let prf_seed = hash_packed(&[b"sphincs-plus-c-verifier-prf", seed_label]);
        let pk_seed = hash_packed(&[b"sphincs-plus-c-verifier-pk", seed_label]);
        let sk = sphincs_plus_c::keygen(sk_seed, prf_seed, pk_seed);
        let signature = sphincs_plus_c::sign(&sk, &hash).expect("stateless sign");
        let envelope = envelope::encode_stateless_signature_envelope(&signature);
        let key = key64(&sk.public_key);
        (key, envelope)
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    fn key64(pk: &crate::sphincs_plus_c::PublicKey) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(pk.pk_seed.as_bytes());
        key[32..].copy_from_slice(pk.root.as_bytes());
        key
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn verify_envelope_accepts_valid_64_byte_key_and_stateless_envelope() {
        let hash = [0x42u8; HASH_LEN];
        let (key, envelope) = signed_stateless_envelope(b"verify-envelope valid", hash);

        let outcome = SphincsPlusCVerifier::new().verify_envelope(&key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn verify_envelope_rejects_wrong_length_key() {
        let hash = [0x43u8; HASH_LEN];
        let (key, envelope) = signed_stateless_envelope(b"verify-envelope wrong key", hash);

        let short_key = &key[..63];
        let outcome = SphincsPlusCVerifier::new().verify_envelope(short_key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);

        let long_key = [&key[..], &[0u8]].concat();
        let outcome = SphincsPlusCVerifier::new().verify_envelope(&long_key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn verify_envelope_reports_malformed_envelope() {
        let hash = [0x44u8; HASH_LEN];
        let (key, envelope) = signed_stateless_envelope(b"verify-envelope malformed", hash);

        let outcome = SphincsPlusCVerifier::new().verify_envelope(
            &key,
            &hash,
            &envelope[..envelope.len().saturating_sub(1)],
        );
        assert_eq!(outcome, VerifyOutcome::Malformed);

        let outcome = SphincsPlusCVerifier::new().verify_envelope(&key, &hash, &[]);
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }
}

