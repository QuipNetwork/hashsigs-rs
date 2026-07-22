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

//! ERC-7913 SHRINCS verifier adapter.
//!
//! Rust mirror of `hashsigs-solidity-shrincs`'s `SHRINCSVerifier`
//! (`contracts/SHRINCSVerifier.sol`): a stateless, storage-free facade over
//! the hybrid SHRINCS scheme's two ERC-7913-shaped verify entrypoints. `key`
//! is always the 32-byte SHRINCS `publicKeyCommitment`; `signature` is the
//! plain (non-mode-prefixed) envelope `abi.encode(PublicKey,
//! SHRINCS.Signature)` for [`ShrincsVerifierErc7913::verify`], or
//! `abi.encode(PublicKey, SPHINCSPlusC.Signature)` for
//! [`ShrincsVerifierErc7913::verify_stateless`] — see
//! `super::envelope::encode_stateful_envelope` /
//! `super::envelope::encode_stateless_envelope`. This is a different wire
//! shape from the mode-prefixed ERC-1271 action envelope the account wrapper
//! consumes (`crate::account::ShrincsAccountVerifierExample::isValidSignature`).
//!
//! # Tri-state outcome
//!
//! Solidity's `IERC7913SignatureVerifier.verify` returns a `bytes4`: the
//! magic `verify.selector` on success, `0xffffffff` for a well-formed but
//! cryptographically invalid signature (or a malformed/wrong-length key), or
//! it reverts when the calldata re-tag cannot even read the envelope's
//! framing. Rust has no revert channel, so [`Erc7913Outcome`] makes that
//! third state an explicit variant instead of folding it into `Invalid`:
//! callers that need Solidity's return-or-revert split can match
//! `Erc7913Outcome::Malformed` onto their own hard-reject path.
//!
//! # Intentional divergences from `SHRINCSVerifier.sol`
//!
//! - No `verifyAndAttest` / `wasVerified`. Both exist only to write/read
//!   EIP-1153 transient storage, which has no meaning off-chain; skipped
//!   entirely rather than stubbed out.

use super::envelope;
use crate::hash::keccak_packed;
use crate::sphincs_plus_c_verifier::SphincsPlusCVerifier;
use crate::types::HASH_LEN;

/// Outcome of an ERC-7913 verify call. See the module docs for the mapping
/// onto Solidity's magic-value / `0xffffffff` / revert tri-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erc7913Outcome {
    /// The signature verified. Mirrors returning
    /// `IERC7913SignatureVerifier.verify.selector`.
    Valid,
    /// A well-formed envelope carrying a cryptographically invalid
    /// signature, or a key that is not exactly 32 bytes. Mirrors returning
    /// `0xffffffff`.
    Invalid,
    /// The envelope's ABI framing could not be decoded at all. Mirrors a
    /// Solidity revert (the calldata re-tag's member-access failure) — there
    /// is no revert here, so callers must treat this as a hard reject, the
    /// same way they would an unexpected revert.
    Malformed,
}

/// ERC-7913 signature verifier for the hybrid SHRINCS scheme. Rust mirror of
/// `hashsigs-solidity-shrincs`'s `SHRINCSVerifier`; see the module docs.
pub struct ShrincsVerifierErc7913;

impl Default for ShrincsVerifierErc7913 {
    fn default() -> Self {
        Self::new()
    }
}

impl ShrincsVerifierErc7913 {
    pub fn new() -> Self {
        Self
    }

    /// `keccak256("quip.shrincs-verifier.v1")`. Mirrors
    /// `SHRINCSVerifier.VERSION_TAG`: names this verifier's key/envelope
    /// format family, not the compiled parameter profile.
    pub fn version_tag() -> [u8; HASH_LEN] {
        keccak_packed(&[b"quip.shrincs-verifier.v1"])
    }

    /// ERC-7913 stateful verify. Mirrors `SHRINCSVerifier.verify` /
    /// `SHRINCS.verify`: `key` must be exactly 32 bytes (the SHRINCS
    /// `publicKeyCommitment`); `signature_envelope` is
    /// `abi.encode(PublicKey, SHRINCS.Signature)`.
    pub fn verify(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        signature_envelope: &[u8],
    ) -> Erc7913Outcome {
        let Some(commitment) = envelope::decode_public_key_commitment(key) else {
            return Erc7913Outcome::Invalid;
        };
        let Some((public_key, signature)) =
            envelope::decode_stateful_envelope(signature_envelope)
        else {
            return Erc7913Outcome::Malformed;
        };
        // `SHRINCS.verify` packs the bytes32 hash into the signed message as
        // its raw 32 bytes (`SPHINCSPlusC.toMessage`); `hash` IS the message.
        if super::verify_stateful_unsafe_raw(commitment, &public_key, hash, &signature) {
            Erc7913Outcome::Valid
        } else {
            Erc7913Outcome::Invalid
        }
    }

    /// ERC-7913 stateless verify, delegated to the pinned SPHINCS+C sibling.
    /// Mirrors `SHRINCSVerifier.verifyStateless`: decode the commitment key,
    /// run `envelope::prepare_stateless_delegation` (mirroring
    /// `SHRINCS.prepareStatelessDelegation`) to extract the delegate
    /// `(pkSeed, hypertreeRoot)` key and re-encoded signature envelope, then
    /// hand both to `SphincsPlusCVerifier::verify`, exactly like the
    /// Solidity adapter's external call to its pinned sibling.
    pub fn verify_stateless(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        stateless_envelope: &[u8],
    ) -> Erc7913Outcome {
        let Some(commitment) = envelope::decode_public_key_commitment(key) else {
            return Erc7913Outcome::Invalid;
        };
        // `prepare_stateless_delegation` folds envelope-decode failure,
        // commitment mismatch, and public-key shape failure into a single
        // `None` (see envelope.rs's doc comment on that function). Decode
        // once more here, purely to split "framing that can't be read at
        // all" (Malformed) from "well-formed but rejected" (Invalid),
        // without duplicating its commitment/shape-check logic.
        if envelope::decode_stateless_envelope(stateless_envelope).is_none() {
            return Erc7913Outcome::Malformed;
        }
        let Some((delegate_key, delegate_signature_envelope)) =
            envelope::prepare_stateless_delegation(commitment, stateless_envelope)
        else {
            return Erc7913Outcome::Invalid;
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
            return Erc7913Outcome::Malformed;
        };
        if SphincsPlusCVerifier::new().verify(&delegate_key, hash, &delegate_signature) {
            Erc7913Outcome::Valid
        } else {
            Erc7913Outcome::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(ShrincsVerifierErc7913::version_tag(), EXPECTED);
    }

    // --- stateful verify -----------------------------------------------------

    #[test]
    fn verify_accepts_a_valid_stateful_signature_over_the_raw_hash() {
        let (mut signing_key, public_key) = keypair(b"erc7913 stateful accept seed");
        let hash = [0x42u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let outcome =
            ShrincsVerifierErc7913::new().verify(&commitment_of(&public_key), &hash, &envelope);
        assert_eq!(outcome, Erc7913Outcome::Valid);
    }

    #[test]
    fn verify_rejects_a_signature_over_a_different_hash() {
        let (mut signing_key, public_key) = keypair(b"erc7913 stateful reject seed");
        let hash = [0x11u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let wrong_hash = [0x22u8; HASH_LEN];
        let outcome = ShrincsVerifierErc7913::new().verify(
            &commitment_of(&public_key),
            &wrong_hash,
            &envelope,
        );
        assert_eq!(outcome, Erc7913Outcome::Invalid);
    }

    #[test]
    fn verify_rejects_a_wrong_length_key() {
        let (mut signing_key, public_key) = keypair(b"erc7913 stateful wrong key seed");
        let hash = [0x33u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let mut short_key = commitment_of(&public_key);
        short_key.pop();
        let outcome = ShrincsVerifierErc7913::new().verify(&short_key, &hash, &envelope);
        assert_eq!(outcome, Erc7913Outcome::Invalid);
    }

    #[test]
    fn verify_reports_a_truncated_envelope_as_malformed() {
        let (mut signing_key, public_key) = keypair(b"erc7913 stateful malformed seed");
        let hash = [0x44u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash)
            .expect("signing must succeed for a fresh key");
        let envelope = envelope::encode_stateful_envelope(&public_key, &signature);

        let outcome = ShrincsVerifierErc7913::new().verify(
            &commitment_of(&public_key),
            &hash,
            &envelope[..envelope.len() - 1],
        );
        assert_eq!(outcome, Erc7913Outcome::Malformed);
    }

    #[test]
    fn verify_reports_an_empty_envelope_as_malformed() {
        let (_signing_key, public_key) = keypair(b"erc7913 stateful empty seed");
        let hash = [0x55u8; HASH_LEN];
        let outcome =
            ShrincsVerifierErc7913::new().verify(&commitment_of(&public_key), &hash, &[]);
        assert_eq!(outcome, Erc7913Outcome::Malformed);
    }

    // --- stateless verify ------------------------------------------------

    #[test]
    fn verify_stateless_accepts_a_valid_stateless_signature_over_the_raw_hash() {
        let (signing_key, public_key) = keypair(b"erc7913 stateless accept seed");
        let hash = [0x66u8; HASH_LEN];
        let signature: StatelessSignature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let outcome = ShrincsVerifierErc7913::new().verify_stateless(
            &commitment_of(&public_key),
            &hash,
            &envelope,
        );
        assert_eq!(outcome, Erc7913Outcome::Valid);
    }

    #[test]
    fn verify_stateless_rejects_a_signature_over_a_different_hash() {
        let (signing_key, public_key) = keypair(b"erc7913 stateless reject seed");
        let hash = [0x77u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let wrong_hash = [0x88u8; HASH_LEN];
        let outcome = ShrincsVerifierErc7913::new().verify_stateless(
            &commitment_of(&public_key),
            &wrong_hash,
            &envelope,
        );
        assert_eq!(outcome, Erc7913Outcome::Invalid);
    }

    #[test]
    fn verify_stateless_rejects_a_wrong_length_key() {
        let (signing_key, public_key) = keypair(b"erc7913 stateless wrong key seed");
        let hash = [0x99u8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let mut short_key = commitment_of(&public_key);
        short_key.pop();
        let outcome =
            ShrincsVerifierErc7913::new().verify_stateless(&short_key, &hash, &envelope);
        assert_eq!(outcome, Erc7913Outcome::Invalid);
    }

    #[test]
    fn verify_stateless_reports_a_mismatched_commitment_as_invalid_not_malformed() {
        let (signing_key, public_key) = keypair(b"erc7913 stateless wrong commitment seed");
        let hash = [0xaau8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let mut wrong_commitment = commitment_of(&public_key);
        wrong_commitment[0] ^= 0x01;
        let outcome = ShrincsVerifierErc7913::new().verify_stateless(
            &wrong_commitment,
            &hash,
            &envelope,
        );
        assert_eq!(outcome, Erc7913Outcome::Invalid);
    }

    #[test]
    fn verify_stateless_reports_a_truncated_envelope_as_malformed() {
        let (signing_key, public_key) = keypair(b"erc7913 stateless malformed seed");
        let hash = [0xbbu8; HASH_LEN];
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash)
            .expect("stateless signing must succeed for a fresh key");
        let envelope = envelope::encode_stateless_envelope(&public_key, &signature);

        let outcome = ShrincsVerifierErc7913::new().verify_stateless(
            &commitment_of(&public_key),
            &hash,
            &envelope[..envelope.len() - 1],
        );
        assert_eq!(outcome, Erc7913Outcome::Malformed);
    }

    #[test]
    fn verify_stateless_reports_an_empty_envelope_as_malformed() {
        let (_signing_key, public_key) = keypair(b"erc7913 stateless empty seed");
        let hash = [0xccu8; HASH_LEN];
        let outcome = ShrincsVerifierErc7913::new().verify_stateless(
            &commitment_of(&public_key),
            &hash,
            &[],
        );
        assert_eq!(outcome, Erc7913Outcome::Malformed);
    }
}
