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

use crate::profiles::selected::{SelectedProfile, NUM_CHAINS};
use crate::sphincs_plus_c::{self, PublicKey, Signature};
use crate::HASH_LEN;

/// Independent stateless-only verifier (Solidity `SPHINCSPlusCVerifier` shape).
///
/// Bound to `SelectedProfile`: this facade names one profile, unlike the
/// algorithms it calls, which are generic over `P: Profile`. It gains its own
/// profile parameter when `build.rs` stops pinning one profile per build.
#[derive(Debug, Clone, Copy)]
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

    /// `keccak256("quip.sphincsplusc-verifier.v3")`. Mirrors
    /// `SPHINCSPlusCVerifier.VERSION_TAG`: names this verifier's key/envelope
    /// format family, not the compiled parameter profile.
    pub fn version_tag() -> [u8; HASH_LEN] {
        crate::hash::keccak_packed(&[b"quip.sphincsplusc-verifier.v3"])
    }

    /// Verify a decoded SPHINCS+C signature over a 32-byte hash.
    ///
    /// `key` is `pk_seed || hypertree_root` (exactly 64 bytes). Named
    /// `verify_signature` (not `verify`) so it does not shadow the opaque-bytes
    /// [`VerifierInterface::verify`](crate::verifier::VerifierInterface::verify).
    pub fn verify_signature(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        signature: &Signature,
    ) -> bool {
        if key.len() != 64 {
            return false;
        }
        let Some(pk) = PublicKey::from_slices(&key[..32], &key[32..64]) else {
            return false;
        };
        sphincs_plus_c::verify_hash::<SelectedProfile, NUM_CHAINS>(&pk, hash, signature)
    }

    /// Verify with an already-decoded public key.
    pub fn verify_with_pk(
        &self,
        pk: &PublicKey,
        hash: &[u8; HASH_LEN],
        signature: &Signature,
    ) -> bool {
        sphincs_plus_c::verify_hash::<SelectedProfile, NUM_CHAINS>(pk, hash, signature)
    }

    /// Verify over arbitrary message bytes (non-verifier-interface helper).
    pub fn verify_message(&self, pk: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        sphincs_plus_c::verify::<SelectedProfile, NUM_CHAINS>(pk, message, signature)
    }
}

impl crate::verifier::VerifierInterface for SphincsPlusCVerifier {
    /// `key` is the 64-byte `pkSeed || hypertreeRoot`; `signature` is the
    /// stateless signature envelope (`abi.encode(SPHINCSPlusC.Signature)`).
    fn verify(
        &self,
        key: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> crate::verifier::VerifyOutcome {
        use crate::verifier::VerifyOutcome;
        if key.len() != 64 {
            return VerifyOutcome::Invalid;
        }
        let Some(decoded) = Signature::from_bytes::<SelectedProfile>(signature) else {
            return VerifyOutcome::Malformed;
        };
        if self.verify_signature(key, hash, &decoded) {
            VerifyOutcome::Valid
        } else {
            VerifyOutcome::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    use crate::verifier::{VerifierInterface, VerifyOutcome};

    #[test]
    fn version_tag_matches_pinned_solidity_constant() {
        // keccak256("quip.sphincsplusc-verifier.v3"), computed independently
        // and pinned here so drift in either the literal string or the hash
        // routine fails loud instead of silently matching itself.
        const EXPECTED: [u8; HASH_LEN] = [
            0x62, 0xcf, 0xe9, 0x36, 0xd3, 0x54, 0x4b, 0x0b, 0x08, 0xdc, 0x32, 0xed, 0x9b, 0x4e,
            0x33, 0xe8, 0xb5, 0x81, 0x33, 0x9e, 0x5f, 0xa0, 0x61, 0x68, 0xb3, 0xd9, 0xca, 0x6b,
            0x9c, 0x55, 0x4e, 0xa3,
        ];
        assert_eq!(SphincsPlusCVerifier::version_tag(), EXPECTED);
    }

    /// One 64-byte `pk_seed || hypertree_root` key plus a signed hash and
    /// stateless envelope for `VerifierInterface` tests, ground once per
    /// process: SPHINCS+C signing grinds FORS-C/WOTS-C counters, so tests
    /// that only need a valid envelope share this artifact. Gated off the
    /// 128s profiles because independent SPHINCS+C keygen/sign grinds too
    /// hard.
    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    fn signed_stateless_envelope() -> &'static ([u8; 64], [u8; HASH_LEN], Vec<u8>) {
        use crate::hash::hash_packed;
        use crate::profile::Profile;
        use crate::profiles::selected::NUM_LAYERS;
        use crate::sphincs_plus_c;
        use std::sync::OnceLock;
        type Suite = <SelectedProfile as Profile>::Suite;

        static CELL: OnceLock<([u8; 64], [u8; HASH_LEN], Vec<u8>)> = OnceLock::new();
        CELL.get_or_init(|| {
            let seed_label: &[u8] = b"verify-envelope shared";
            let hash = [0x42u8; HASH_LEN];
            let sk_seed = hash_packed::<Suite>(&[b"sphincs-plus-c-verifier-sk", seed_label]);
            let prf_seed = hash_packed::<Suite>(&[b"sphincs-plus-c-verifier-prf", seed_label]);
            let pk_seed = hash_packed::<Suite>(&[b"sphincs-plus-c-verifier-pk", seed_label]);
            let sk =
                sphincs_plus_c::keygen::<SelectedProfile, NUM_LAYERS>(sk_seed, prf_seed, pk_seed);
            let signature = sphincs_plus_c::sign::<SelectedProfile, NUM_LAYERS>(&sk, &hash)
                .expect("stateless sign");
            let envelope = signature.to_bytes();
            let key = key64(&sk.public_key);
            (key, hash, envelope)
        })
    }

    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    fn key64(pk: &crate::sphincs_plus_c::PublicKey) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(pk.pk_seed.as_bytes());
        key[32..].copy_from_slice(pk.root.as_bytes());
        key
    }

    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    #[test]
    fn verify_accepts_valid_64_byte_key_and_stateless_envelope() {
        let (key, hash, envelope) = signed_stateless_envelope();

        let outcome = SphincsPlusCVerifier::new().verify(key, hash, envelope);
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    #[test]
    fn verify_rejects_wrong_length_key() {
        let (key, hash, envelope) = signed_stateless_envelope();

        let short_key = &key[..63];
        let outcome = SphincsPlusCVerifier::new().verify(short_key, hash, envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);

        let long_key = [&key[..], &[0u8]].concat();
        let outcome = SphincsPlusCVerifier::new().verify(&long_key, hash, envelope);
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[cfg(not(any(
        shrincs_default_profile_128s_q18,
        shrincs_default_profile_128s_q20,
        shrincs_default_profile_128s_q18_sha2,
        shrincs_default_profile_128s_q20_sha2
    )))]
    #[test]
    fn verify_reports_malformed_envelope() {
        let (key, hash, envelope) = signed_stateless_envelope();

        let outcome = SphincsPlusCVerifier::new().verify(
            key,
            hash,
            &envelope[..envelope.len().saturating_sub(1)],
        );
        assert_eq!(outcome, VerifyOutcome::Malformed);

        let outcome = SphincsPlusCVerifier::new().verify(key, hash, &[]);
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }
}
