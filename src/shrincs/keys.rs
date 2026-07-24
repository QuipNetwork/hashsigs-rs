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
//! Flat layout: `stateful(136) ‖ stateless(128)` = 264 bytes.

use crate::primitives::hash::word32;
use crate::shrincs::signer::{INITIAL_STATEFUL_LEAF_INDEX, MAX_STATEFUL_SIGNATURES_LIMIT};
use crate::shrincs::uxmss::{self, stateful_subtree_root};
use crate::sphincs_plus_c;
use crate::sphincs_plus_c::hypertree::hypertree_public_root;
use crate::types::HASH_LEN;

use super::{derive32, public_key_commitment};

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

    /// Parse and validate a persisted 264-byte secret.
    ///
    /// Unlike [`Keys::from_bytes`], this recomputes both tree roots from the
    /// seeds and rejects any mismatch (corrupted or field-spliced input) — the
    /// roots are consensus-critical inputs to every signature. The stateful
    /// counter may sit at the exhausted position (`next == max + 1`), which
    /// stateful signing legitimately produces. On success the commitment is
    /// recomputed, never trusted from the input.
    pub fn import(bytes: &[u8]) -> Option<Self> {
        let keys = Self::from_bytes(bytes)?;
        let max = keys.stateful.public_key.max_signatures;
        if max == 0 || max > MAX_STATEFUL_SIGNATURES_LIMIT {
            return None;
        }
        let next = keys.stateful.next_leaf_index;
        if next < INITIAL_STATEFUL_LEAF_INDEX || next > max.saturating_add(1) {
            return None;
        }
        // The stateful root always covers the whole tree from leaf 1,
        // independent of `next`.
        let stateful_root = stateful_subtree_root(
            keys.stateful.secret.sk_seed.as_bytes(),
            keys.stateful.public_key.pk_seed.as_bytes(),
            INITIAL_STATEFUL_LEAF_INDEX,
            max,
        );
        let hypertree_root = hypertree_public_root(
            keys.stateless.secret.sk_seed.as_bytes(),
            keys.stateless.public_key.pk_seed.as_bytes(),
        );
        if &stateful_root != keys.stateful.public_key.root.as_bytes()
            || &hypertree_root != keys.stateless.public_key.root.as_bytes()
        {
            return None;
        }
        Some(keys)
    }

    /// Regenerate a fresh stateful chain from `new_seed`, discarding any
    /// relationship to prior stateful signatures — that is the point of a
    /// reset. The stateless recovery half and the `max_signatures` budget
    /// are untouched; the commitment is recomputed. Same derivation as
    /// [`ShrincsSigner::keygen`](crate::shrincs::signer::ShrincsSigner::keygen)'s
    /// stateful half. `new_seed` is arbitrary-length seed material hashed by
    /// [`derive32`]; this library has no RNG, so the caller must supply
    /// fresh entropy.
    pub fn reset(&mut self, new_seed: &[u8]) {
        let max = self.stateful.public_key.max_signatures;
        let sk = derive32(b"shrincs-stateful-sk-seed", new_seed, &[]);
        let prf = derive32(b"shrincs-stateful-prf-seed", new_seed, &[]);
        let pk = derive32(b"shrincs-stateful-pk-seed", new_seed, &[]);
        let root = stateful_subtree_root(&sk, &pk, INITIAL_STATEFUL_LEAF_INDEX, max);
        self.stateful = uxmss::Key {
            secret: uxmss::Secret {
                sk_seed: uxmss::SkSeed::new(sk),
                prf_seed: uxmss::PrfSeed::new(prf),
            },
            public_key: uxmss::PublicKey {
                pk_seed: uxmss::PkSeed::new(pk),
                root: uxmss::Root::new(root),
                max_signatures: max,
            },
            next_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
        };
        self.public_key_commitment = Self::compute_commitment(&self.stateful, &self.stateless);
    }

    /// Recompute the commitment from this key's current public halves.
    /// Convenience wrapper around [`Keys::compute_commitment`].
    pub fn recompute_commitment(&self) -> Commitment {
        Self::compute_commitment(&self.stateful, &self.stateless)
    }

    /// Decode a stateful envelope and recompute the commitment its carried
    /// public key implies, ecrecover-style. The envelope's own
    /// `public_key_commitment` field is never trusted: an attacker controls
    /// the envelope bytes, so the recovered value is only a claim, to be
    /// checked by the caller against a stored commitment. Returns `None` on
    /// a malformed envelope or wrong-length fields.
    pub fn recover_commitment(stateful_envelope: &[u8]) -> Option<Commitment> {
        let (pk, _sig) = crate::envelope::decode_stateful_envelope(stateful_envelope)?;
        let pk_seed = word32(&pk.pk_seed)?;
        let hypertree_root = word32(&pk.hypertree_root)?;
        Some(Commitment::new(public_key_commitment(
            &pk.stateful_public_key,
            &pk_seed,
            &hypertree_root,
        )))
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

    /// A `Keys` with real, seed-derived roots, plus the `PublicKey` production
    /// `keygen` installs — for cross-checking commitment and import.
    fn production_keys() -> (Keys, crate::types::PublicKey) {
        use crate::shrincs::signer::ShrincsSigner;
        ShrincsSigner::keygen(b"keys import cross-check", 4).expect("keygen")
    }

    /// `compute_commitment` must match the commitment production `keygen`
    /// installs in the public key — same preimage, same keccak.
    #[test]
    fn commitment_matches_production_keygen() {
        let (keys, pk) = production_keys();
        assert_eq!(
            keys.public_key_commitment.as_bytes().as_slice(),
            pk.public_key_commitment.as_slice()
        );
    }

    #[test]
    fn import_accepts_valid_seed_derived_key() {
        let (keys, _) = production_keys();
        assert_eq!(Keys::import(&keys.to_bytes()), Some(keys));
    }

    #[test]
    fn import_rejects_tampered_stateful_root() {
        let (keys, _) = production_keys();
        let mut bytes = keys.to_bytes();
        bytes[96] ^= 0x01; // stateful root occupies bytes 96..128
        assert!(Keys::import(&bytes).is_none());
    }

    #[test]
    fn import_rejects_tampered_hypertree_root() {
        let (keys, _) = production_keys();
        let mut bytes = keys.to_bytes();
        bytes[232] ^= 0x01; // stateless hypertree root occupies bytes 232..264
        assert!(Keys::import(&bytes).is_none());
    }

    #[test]
    fn import_rejects_out_of_bounds_max() {
        let (keys, _) = production_keys();
        let mut bytes = keys.to_bytes();
        bytes[128..132].copy_from_slice(&0u32.to_be_bytes()); // max_signatures = 0
        assert!(Keys::import(&bytes).is_none());
    }

    #[test]
    fn import_accepts_exhausted_counter() {
        let (keys, _) = production_keys();
        let mut bytes = keys.to_bytes();
        // next_leaf_index (bytes 132..136) = max + 1 (exhausted but legal).
        let exhausted = keys.stateful.public_key.max_signatures + 1;
        bytes[132..136].copy_from_slice(&exhausted.to_be_bytes());
        assert!(Keys::import(&bytes).is_some());
    }

    #[test]
    fn reset_generates_fresh_stateful_chain() {
        let (mut keys, _pk) = production_keys();
        let original_stateless = keys.stateless.clone();
        let original_commitment = keys.public_key_commitment;
        let original_max = keys.stateful.public_key.max_signatures;

        keys.reset(b"a completely different reset seed");

        assert_ne!(keys.public_key_commitment, original_commitment);
        assert_eq!(keys.stateless, original_stateless);
        assert_eq!(keys.stateful.next_leaf_index, INITIAL_STATEFUL_LEAF_INDEX);
        assert_eq!(keys.stateful.public_key.max_signatures, original_max);
        assert!(Keys::import(&keys.to_bytes()).is_some());
    }

    #[test]
    fn reset_is_deterministic() {
        let (mut keys_a, _) = production_keys();
        let (mut keys_b, _) = production_keys();

        keys_a.reset(b"same reset seed");
        keys_b.reset(b"same reset seed");

        assert_eq!(keys_a.stateful, keys_b.stateful);
        assert_eq!(keys_a.public_key_commitment, keys_b.public_key_commitment);
    }

    #[test]
    fn recompute_commitment_matches_current_commitment() {
        let (keys, _pk) = production_keys();
        assert_eq!(keys.recompute_commitment(), keys.public_key_commitment);
    }

    #[test]
    fn recover_commitment_from_envelope_matches_keygen_commitment() {
        let (mut keys, pk) = production_keys();
        let pre_sign_commitment = keys.public_key_commitment;
        let sig =
            crate::shrincs::signer::ShrincsSigner::sign_stateful_raw(&mut keys, &[0x11; 32])
                .expect("sign");
        let env = crate::envelope::encode_stateful_envelope(&pk, &sig);

        let recovered = Keys::recover_commitment(&env).expect("recover");

        assert_eq!(recovered, pre_sign_commitment);
        assert_eq!(recovered, production_keys().0.public_key_commitment);
    }

    #[test]
    fn recover_commitment_rejects_garbage_envelope() {
        assert!(Keys::recover_commitment(&[0u8; 4]).is_none());
    }

    /// `recover_commitment` must recompute the commitment from the envelope's
    /// carried `stateful_public_key ‖ pk_seed ‖ hypertree_root`, not trust the
    /// envelope's own `public_key_commitment` field: an attacker controls the
    /// envelope bytes and could claim any commitment there.
    #[test]
    fn recover_commitment_ignores_tampered_commitment_field() {
        let (mut keys, pk) = production_keys();
        let real = keys.public_key_commitment;
        let sig =
            crate::shrincs::signer::ShrincsSigner::sign_stateful_raw(&mut keys, &[0x11u8; 32])
                .expect("sign");

        let mut bad_pk = pk.clone();
        bad_pk.public_key_commitment = alloc::vec![0xFFu8; 32];
        let env = crate::envelope::encode_stateful_envelope(&bad_pk, &sig);

        assert_eq!(Keys::recover_commitment(&env), Some(real));
        assert_ne!(
            Keys::recover_commitment(&env).unwrap().as_bytes(),
            &[0xFFu8; 32]
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
