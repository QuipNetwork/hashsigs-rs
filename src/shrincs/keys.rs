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

//! The composed SHRINCS key.
//!
//! A SHRINCS key is a [`sphincs_plus_c::Key`] (the stateless recovery
//! identity), a [`uxmss::Key`] (the stateful fast-path chain), and the
//! [`Commitment`] that binds both public keys into one on-chain identity —
//! composition, not a flat concatenation of seeds.
//!
//! The commitment is derivable from the two public keys, so it is never part
//! of the 264-byte secret serialization; [`Keys::from_bytes`] recomputes it.
//! Flat layout: `stateful(136) ‖ stateless(128)` = 264 bytes, byte-identical
//! to the legacy `ShrincsSigningKey` order.

use crate::shrincs::uxmss;
use crate::sphincs_plus_c;
use crate::types::HASH_LEN;

use super::public_key_commitment;

/// Number of bytes in the flat secret serialization of a [`Keys`].
pub const KEYS_BYTES: usize = 264;

/// keccak256 commitment binding the stateful and stateless public keys into a
/// single 32-byte on-chain identity. Not a verification key: a fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment([u8; HASH_LEN]);

impl Commitment {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

/// A SHRINCS key: a SPHINCS+C recovery key, a UXMSS fast-path key, and the
/// commitment that binds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    /// Durable stateless recovery identity (a SPHINCS+C keypair).
    pub stateless: sphincs_plus_c::Key,
    /// Rotatable stateful fast-path chain (a UXMSS key); its counter advances
    /// on each stateful signature.
    pub stateful: uxmss::Key,
    /// Fingerprint binding both public keys; fixed until the stateful chain is
    /// reset.
    pub public_key_commitment: Commitment,
}

impl Keys {
    /// Recompute the commitment from the two public keys. Deterministic; the
    /// authoritative definition of a SHRINCS identity.
    pub fn compute_commitment(
        stateful: &uxmss::Key,
        stateless: &sphincs_plus_c::Key,
    ) -> Commitment {
        let stateful_public_key = stateful.public_key.to_bytes();
        Commitment::new(public_key_commitment(
            &stateful_public_key,
            stateless.public_key.pk_seed.as_bytes(),
            stateless.public_key.root.as_bytes(),
        ))
    }

    /// Flat secret layout `stateful(136) ‖ stateless(128)`, 264 bytes. The
    /// commitment is derivable and is not serialized.
    pub fn to_bytes(&self) -> [u8; KEYS_BYTES] {
        let mut out = [0u8; KEYS_BYTES];
        out[..136].copy_from_slice(&self.stateful.to_bytes());
        out[136..].copy_from_slice(&self.stateless.to_bytes());
        out
    }

    /// Parse the 264-byte secret layout and recompute the commitment from the
    /// parsed public keys. Returns `None` on wrong length or malformed fields.
    ///
    /// This is a structural parse: it does not recompute the tree roots from
    /// the seeds, so a caller reloading persisted bytes trusts that those
    /// bytes came from a prior `to_bytes`. Root re-derivation belongs to the
    /// signer's validating import.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEYS_BYTES {
            return None;
        }
        let stateful = uxmss::Key::from_bytes(bytes.get(..136)?)?;
        let stateless = sphincs_plus_c::Key::from_bytes(bytes.get(136..)?)?;
        let public_key_commitment = Self::compute_commitment(&stateful, &stateless);
        Some(Self {
            stateless,
            stateful,
            public_key_commitment,
        })
    }
}

// `Keys` intentionally does not derive `Zeroize`: its secret halves
// (`sphincs_plus_c::Secret`, `uxmss::Secret`) are `ZeroizeOnDrop`, so their
// seeds are wiped when a `Keys` drops, and its derived `Debug` delegates to
// those redacting component impls. A blanket derive would also require the
// public `Commitment` to be zeroizable for no benefit.

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Keys {
        // Structural sample: any 264 bytes parse; roots/commitment are not
        // validated against seeds here (that is the signer's job).
        Keys::from_bytes(&[7u8; KEYS_BYTES]).expect("264 bytes parse")
    }

    #[test]
    fn bytes_round_trip() {
        let keys = sample();
        assert_eq!(Keys::from_bytes(&keys.to_bytes()), Some(keys));
    }

    #[test]
    fn from_bytes_reproduces_input_bytes() {
        let input = [9u8; KEYS_BYTES];
        let keys = Keys::from_bytes(&input).expect("parse");
        assert_eq!(keys.to_bytes(), input);
    }

    #[test]
    fn commitment_recomputed_on_parse() {
        let keys = sample();
        assert_eq!(
            keys.public_key_commitment,
            Keys::compute_commitment(&keys.stateful, &keys.stateless)
        );
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Keys::from_bytes(&[0u8; KEYS_BYTES - 1]).is_none());
        assert!(Keys::from_bytes(&[0u8; KEYS_BYTES + 1]).is_none());
    }

    /// `compute_commitment` must match the commitment production `keygen`
    /// installs in the public key — same preimage, same keccak.
    #[test]
    fn commitment_matches_production_keygen() {
        use crate::shrincs::signer::ShrincsSigner;
        let (sk, pk) =
            ShrincsSigner::keygen(b"keys commitment cross-check", 4).expect("keygen");
        let stateful = uxmss::Key {
            secret: uxmss::Secret {
                sk_seed: uxmss::SkSeed::new(sk.stateful_sk_seed),
                prf_seed: uxmss::PrfSeed::new(sk.stateful_prf_seed),
            },
            public_key: uxmss::PublicKey {
                pk_seed: uxmss::PkSeed::new(sk.stateful_pk_seed),
                root: uxmss::Root::new(sk.stateful_root),
                max_signatures: sk.max_stateful_signatures,
            },
            next_leaf_index: sk.next_stateful_leaf_index,
        };
        let stateless = sphincs_plus_c::Key {
            secret: sphincs_plus_c::Secret {
                sk_seed: sphincs_plus_c::SkSeed::new(sk.stateless_sk_seed),
                prf_seed: sphincs_plus_c::PrfSeed::new(sk.stateless_prf_seed),
            },
            public_key: sphincs_plus_c::PublicKey {
                pk_seed: sphincs_plus_c::PkSeed::new(sk.pk_seed),
                root: sphincs_plus_c::Root::new(sk.hypertree_root),
            },
        };
        let commitment = Keys::compute_commitment(&stateful, &stateless);
        assert_eq!(
            commitment.as_bytes().as_slice(),
            pk.public_key_commitment.as_slice()
        );
    }

    #[test]
    fn debug_redacts_secret_seeds() {
        // Distinct secret marker (0xAA -> "170") vs everything else (0x07), so a
        // leak of the secret seeds would be visible. Public pk_seed/root (0x07)
        // are shown in the clear, which is fine; the secret halves must not be.
        let mut bytes = [0x07u8; KEYS_BYTES];
        bytes[..64].fill(0xAA); // stateful sk_seed ‖ prf_seed
        bytes[136..200].fill(0xAA); // stateless sk_seed ‖ prf_seed
        let keys = Keys::from_bytes(&bytes).expect("parse");
        let shown = alloc::format!("{keys:?}");
        // Four secret seeds, each redacted.
        assert_eq!(shown.matches("redacted").count(), 4);
        assert!(!shown.contains("170"));
    }
}
