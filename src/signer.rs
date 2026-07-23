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

//! The signer interface: the mirror of [`crate::verifier::VerifierInterface`].
//!
//! A signer produces the opaque signature envelope that the matching verifier
//! accepts, over a 32-byte message hash, and exposes the verifying key the
//! verifier needs. Both schemes implement it:
//! [`crate::sphincs_plus_c::SphincsPlusCSigner`] (stateless: `sign_envelope`
//! never mutates observable state and never fails) and
//! [`crate::shrincs::ShrincsStatefulSigner`] (stateful: each `sign_envelope`
//! consumes a one-time leaf, advances the key, and returns `None` once the
//! leaf budget is exhausted).
//!
//! The round-trip
//! `verifier.verify_envelope(signer.verifying_key(), h, signer.sign_envelope(h))`
//! holds for both schemes; a conformance test pins it.

use alloc::vec::Vec;

use crate::types::HASH_LEN;

/// Produces a signature envelope over a 32-byte hash and the verifying key
/// that checks it. The mirror of [`crate::verifier::VerifierInterface`].
pub trait SignerInterface {
    /// Sign a 32-byte message hash, returning the opaque signature envelope
    /// the matching verifier accepts. `&mut self` because a stateful signer
    /// consumes a one-time leaf and advances its key; a stateless signer
    /// ignores the mutability. Returns `None` on failure (e.g. stateful leaf
    /// exhaustion or grind-budget exhaustion).
    fn sign_envelope(&mut self, hash: &[u8; HASH_LEN]) -> Option<Vec<u8>>;

    /// The verifying key bytes the matching [`VerifierInterface`] expects for
    /// signatures from this signer (64-byte `pkSeed‖hypertreeRoot` for
    /// SPHINCS+C, the 32-byte public-key commitment for SHRINCS).
    ///
    /// [`VerifierInterface`]: crate::verifier::VerifierInterface
    fn verifying_key(&self) -> Vec<u8>;
}

#[cfg(all(
    test,
    not(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))
))]
mod tests {
    use super::SignerInterface;
    use crate::verifier::{VerifierInterface, VerifyOutcome};

    fn message() -> [u8; 32] {
        crate::primitives::hash::hash_packed(&[b"signer-interface-round-trip"])
    }

    #[test]
    fn sphincs_plus_c_signer_round_trips_through_the_verifier() {
        fn d(domain: &[u8]) -> [u8; 32] {
            crate::primitives::hash::hash_packed(&[domain, b"seed"])
        }
        let mut signer = crate::sphincs_plus_c::SphincsPlusCSigner::from_seeds(
            d(b"sk"),
            d(b"prf"),
            d(b"pk"),
        );
        let hash = message();
        let key = signer.verifying_key();
        let envelope = signer.sign_envelope(&hash).expect("sign");
        let outcome = crate::sphincs_plus_c::SphincsPlusCVerifier::new()
            .verify_envelope(&key, &hash, &envelope);
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[test]
    fn shrincs_stateful_signer_round_trips_and_advances() {
        let (signing_key, public_key) =
            crate::shrincs::ShrincsSigner::keygen(b"signer iface shrincs seed", 4).expect("keygen");
        let mut signer =
            crate::shrincs::ShrincsSigner::into_stateful_signer(signing_key, public_key);
        assert_eq!(signer.remaining_stateful_signatures(), 4);

        let hash = message();
        let key = signer.verifying_key();
        let envelope = signer.sign_envelope(&hash).expect("first sign");
        assert_eq!(
            crate::shrincs::ShrincsVerifier::new().verify_envelope(&key, &hash, &envelope),
            VerifyOutcome::Valid
        );
        // The leaf advanced: a second signature consumes the next leaf.
        assert_eq!(signer.remaining_stateful_signatures(), 3);
        let envelope2 = signer.sign_envelope(&hash).expect("second sign");
        assert_ne!(envelope, envelope2, "distinct leaves yield distinct envelopes");
        assert_eq!(
            crate::shrincs::ShrincsVerifier::new().verify_envelope(&key, &hash, &envelope2),
            VerifyOutcome::Valid
        );
    }
}
