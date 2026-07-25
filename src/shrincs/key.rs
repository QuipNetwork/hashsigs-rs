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
//! A SHRINCS key is a [`crate::sphincs_plus_c::Key`] (the stateless recovery
//! identity), a `uxmss::Key` (the stateful fast-path chain), and the
//! [`Commitment`] that binds both public keys into one on-chain identity —
//! composition, not a flat concatenation of seeds.
//!
//! The commitment is derivable from the two public keys, so it is never part
//! of the 264-byte secret serialization; [`Keys::from_bytes`] recomputes it.
//! Flat layout: `stateful(136) ‖ stateless(128)` = 264 bytes.

use alloc::vec::Vec;

use crate::abi::{encode_bytes, encode_tuple, AbiReader, Field};
use crate::hash::{derive32, keccak_packed, word32};
use crate::profiles::PROFILE_NAME;
use crate::shrincs::uxmss::{
    self, stateful_subtree_root, PublicKey as StatefulPublicKey, INITIAL_STATEFUL_LEAF_INDEX,
    MAX_STATEFUL_SIGNATURES_LIMIT, STATEFUL_PUBLIC_KEY_BYTES,
};
use crate::sphincs_plus_c;
use crate::HASH_LEN;

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

    /// Derive the commitment binding an encoded stateful public key with a
    /// stateless `pk_seed`/`hypertree_root`:
    /// `keccak256("shrincs-public-key/" || profile || stateful_public_key ||
    /// pk_seed || hypertree_root)`. Mirrors
    /// `SHRINCS.publicKeyCommitmentFromParts`.
    pub fn of(
        stateful_public_key: &[u8],
        pk_seed: &[u8; HASH_LEN],
        hypertree_root: &[u8; HASH_LEN],
    ) -> Self {
        Self(keccak_packed(&[
            b"shrincs-public-key/",
            PROFILE_NAME.as_bytes(),
            stateful_public_key,
            pk_seed,
            hypertree_root,
        ]))
    }

    /// Parse the verifier `key` bytes, which are exactly one 32-byte
    /// commitment word. Mirrors `SHRINCS.decodePublicKeyCommitment`; `None`
    /// for any length other than 32.
    pub fn from_bytes(key: &[u8]) -> Option<Self> {
        Some(Self(word32(key)?))
    }
}

impl TryFrom<&[u8]> for Commitment {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

/// A SHRINCS key: a SPHINCS+C recovery key, a UXMSS fast-path key, and the
/// commitment that binds them.
///
/// Fields are private so callers cannot desynchronize the commitment from the
/// two public halves or tamper with the one-time leaf counter. Construct via
/// keygen / [`Self::from_bytes`] / [`Self::import`] / [`Self::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    /// Durable stateless recovery identity (a SPHINCS+C keypair).
    stateless: sphincs_plus_c::Key,
    /// Rotatable stateful fast-path chain (a UXMSS key); its counter advances
    /// on each stateful signature.
    stateful: uxmss::Key,
    /// Fingerprint binding both public keys; fixed until the stateful chain is
    /// reset.
    public_key_commitment: Commitment,
}

impl Keys {
    /// Assemble from the two scheme keys and recompute the commitment.
    pub fn new(stateless: sphincs_plus_c::Key, stateful: uxmss::Key) -> Self {
        let public_key_commitment = Self::compute_commitment(&stateful, &stateless);
        Self {
            stateless,
            stateful,
            public_key_commitment,
        }
    }

    /// Borrow the durable SPHINCS+C recovery half.
    pub fn stateless(&self) -> &sphincs_plus_c::Key {
        &self.stateless
    }

    /// Borrow the UXMSS fast-path half (including the leaf counter).
    pub fn stateful(&self) -> &uxmss::Key {
        &self.stateful
    }

    /// Mutable access to the stateful half for the in-crate sign/advance path.
    pub(crate) fn stateful_mut(&mut self) -> &mut uxmss::Key {
        &mut self.stateful
    }

    /// Borrow the commitment fingerprint binding both public keys.
    pub fn public_key_commitment(&self) -> &Commitment {
        &self.public_key_commitment
    }

    /// Recompute the commitment from the two public keys. Deterministic; the
    /// authoritative definition of a SHRINCS identity.
    pub fn compute_commitment(
        stateful: &uxmss::Key,
        stateless: &sphincs_plus_c::Key,
    ) -> Commitment {
        let stateful_public_key = stateful.public_key().to_bytes();
        Commitment::of(
            &stateful_public_key,
            stateless.public_key.pk_seed.as_bytes(),
            stateless.public_key.root.as_bytes(),
        )
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
        Some(Self::new(stateless, stateful))
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
        let max = keys.stateful.public_key().max_signatures;
        if max == 0 || max > MAX_STATEFUL_SIGNATURES_LIMIT {
            return None;
        }
        let next = keys.stateful.next_leaf_index();
        if next < INITIAL_STATEFUL_LEAF_INDEX || next > max.saturating_add(1) {
            return None;
        }
        // The stateful root always covers the whole tree from leaf 1,
        // independent of `next`.
        let stateful_root = stateful_subtree_root(
            keys.stateful.secret().as_sk_seed().as_bytes(),
            keys.stateful.public_key().pk_seed.as_bytes(),
            INITIAL_STATEFUL_LEAF_INDEX,
            max,
        );
        let hypertree_root = *sphincs_plus_c::keygen(
            *keys.stateless.secret().as_sk_seed().as_bytes(),
            *keys.stateless.secret().as_prf_seed().as_bytes(),
            *keys.stateless.public_key.pk_seed.as_bytes(),
        )
        .public_key
        .root
        .as_bytes();
        if &stateful_root != keys.stateful.public_key().root.as_bytes()
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
    /// `derive32`; this library has no RNG, so the caller must supply
    /// fresh entropy.
    pub fn reset(&mut self, new_seed: &[u8]) {
        let max = self.stateful.public_key().max_signatures;
        let sk = derive32(b"shrincs-stateful-sk-seed", new_seed, &[]);
        let prf = derive32(b"shrincs-stateful-prf-seed", new_seed, &[]);
        let pk = derive32(b"shrincs-stateful-pk-seed", new_seed, &[]);
        let root = stateful_subtree_root(&sk, &pk, INITIAL_STATEFUL_LEAF_INDEX, max);
        self.stateful = uxmss::Key::new(
            uxmss::PrivateKey::new(uxmss::SkSeed::new(sk), uxmss::PrfSeed::new(prf)),
            uxmss::StructuredPublicKey {
                pk_seed: uxmss::PkSeed::new(pk),
                root: uxmss::Root::new(root),
                max_signatures: max,
            },
            INITIAL_STATEFUL_LEAF_INDEX,
        );
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
        let (pk, _sig) = crate::shrincs::signature::decode_stateful_envelope(stateful_envelope)?;
        pk.commitment()
    }
}

impl TryFrom<&[u8]> for Keys {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

// `Keys` intentionally does not derive `Zeroize`: its secret halves
// (`sphincs_plus_c::PrivateKey`, `uxmss::PrivateKey`) are `ZeroizeOnDrop`, so their
// seeds are wiped when a `Keys` drops, and its derived `Debug` delegates to
// those redacting component impls. A blanket derive would also require the
// public `Commitment` to be zeroizable for no benefit.

// ---------------------------------------------------------------------
// SHRINCS public-key wire type and commitment helpers
// (consolidated from the former `public_key` module to mirror
// `sphincs_plus_c::key`, which holds its scheme's key types in one file).
// ---------------------------------------------------------------------

/// The SHRINCS hybrid public-key bundle: the encoded stateful sub-key, the
/// commitment binding it to the stateless half, and the stateless
/// `pk_seed`/`hypertree_root` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Encoded stateful key: `pk_seed || root || max_signatures`.
    pub stateful_public_key: Vec<u8>,
    /// Commitment to the installed hybrid public-key bundle.
    pub public_key_commitment: Vec<u8>,
    /// Global stateless public seed used for FORS-C, hypertree, and WOTS-C hashing.
    pub pk_seed: Vec<u8>,
    /// Expected final hypertree root.
    pub hypertree_root: Vec<u8>,
}

impl PublicKey {
    /// ABI-encode the public-key body (four `bytes` fields), without a
    /// further outer offset. Used both by `to_bytes` (wrapped one level
    /// further, below) and directly by the composite
    /// `signature::encode_stateful_envelope`/`encode_stateless_envelope`.
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![
            Field::Dynamic(encode_bytes(&self.stateful_public_key)),
            Field::Dynamic(encode_bytes(&self.public_key_commitment)),
            Field::Dynamic(encode_bytes(&self.pk_seed)),
            Field::Dynamic(encode_bytes(&self.hypertree_root)),
        ])
    }

    /// ABI-encode the public-key envelope: `abi.encode(SHRINCS.PublicKey)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![Field::Dynamic(self.encode_body())])
    }

    /// Decode a public-key body already located at `base` within a shared
    /// `AbiReader`. No trailing-bytes check here: `base` commonly sits inside
    /// a larger encoded envelope, so exhaustion is the calling top-level
    /// decoder's responsibility.
    pub(crate) fn decode(reader: &AbiReader, base: usize) -> Option<Self> {
        Some(Self {
            stateful_public_key: reader.decode_bytes(base, base)?,
            public_key_commitment: reader.decode_bytes(base, base.checked_add(32)?)?,
            pk_seed: reader.decode_bytes(base, base.checked_add(64)?)?,
            hypertree_root: reader.decode_bytes(base, base.checked_add(96)?)?,
        })
    }

    /// Decode a standalone byte blob produced by `to_bytes`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let reader = AbiReader::new(data);
        let public_key_start = reader.decode_offset(0, 0)?;
        let decoded = Self::decode(&reader, public_key_start)?;
        reader.finish()?;
        Some(decoded)
    }

    /// Recompute the [`Commitment`] binding this bundle's parts. The stored
    /// `public_key_commitment` field is only a claim (an attacker controls
    /// decoded bytes); this recomputation is authoritative. `None` if any
    /// part is not exactly 32 bytes.
    pub fn commitment(&self) -> Option<Commitment> {
        Some(Commitment::of(
            &self.stateful_public_key,
            &word32(&self.pk_seed)?,
            &word32(&self.hypertree_root)?,
        ))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

pub(crate) fn encode_stateful_public_key(
    pk_seed: [u8; HASH_LEN],
    root: [u8; HASH_LEN],
    max_signatures: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATEFUL_PUBLIC_KEY_BYTES);
    out.extend_from_slice(&pk_seed);
    out.extend_from_slice(&root);
    out.extend_from_slice(&max_signatures.to_be_bytes());
    out
}

pub(crate) fn decode_stateful_public_key(encoded: &[u8]) -> Option<StatefulPublicKey> {
    if encoded.len() != STATEFUL_PUBLIC_KEY_BYTES {
        return None;
    }
    let pk_seed = word32(&encoded[..32])?;
    let root = word32(&encoded[32..64])?;
    let max_signatures = u32::from_be_bytes(encoded[64..68].try_into().ok()?);
    Some(StatefulPublicKey {
        pk_seed,
        root,
        max_signatures,
    })
}

#[cfg(test)]
mod public_key_tests {
    use super::*;
    use alloc::vec;

    fn sample_public_key() -> PublicKey {
        let mut stateful_public_key = vec![0u8; 68];
        for (index, byte) in stateful_public_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        PublicKey {
            stateful_public_key,
            public_key_commitment: vec![0xAA; 32],
            pk_seed: vec![0xBB; 32],
            hypertree_root: vec![0xCC; 32],
        }
    }

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let public_key = sample_public_key();
        let encoded = public_key.to_bytes();
        let decoded = PublicKey::from_bytes(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, public_key);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut encoded = sample_public_key().to_bytes();
        encoded.extend_from_slice(&[0xAA, 0xBB]);
        assert!(
            PublicKey::from_bytes(&encoded).is_none(),
            "trailing junk on the public-key envelope must be rejected"
        );
    }

    #[test]
    fn try_from_delegates_to_from_bytes() {
        let public_key = sample_public_key();
        let encoded = public_key.to_bytes();
        let decoded = PublicKey::try_from(encoded.as_slice()).expect("valid encoding must decode");
        assert_eq!(decoded, public_key);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(PublicKey::try_from(truncated).is_err());
    }

    #[test]
    fn commitment_from_bytes_round_trips() {
        let commitment = Commitment::new([0x42; HASH_LEN]);
        assert_eq!(
            Commitment::from_bytes(commitment.as_bytes()),
            Some(commitment)
        );
    }

    #[test]
    fn commitment_from_bytes_wrong_length_is_rejected() {
        assert!(Commitment::from_bytes(&[0u8; 31]).is_none());
        assert!(Commitment::from_bytes(&[0u8; 33]).is_none());
    }
}

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
            *keys.public_key_commitment(),
            Keys::compute_commitment(keys.stateful(), keys.stateless())
        );
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Keys::from_bytes(&[0u8; KEYS_BYTES - 1]).is_none());
        assert!(Keys::from_bytes(&[0u8; KEYS_BYTES + 1]).is_none());
    }

    /// A `Keys` with real, seed-derived roots, plus the `PublicKey` production
    /// `keygen` installs — for cross-checking commitment and import.
    fn production_keys() -> (Keys, crate::shrincs::key::PublicKey) {
        use crate::shrincs::signer::ShrincsSigner;
        ShrincsSigner::keygen(b"keys import cross-check", 4).expect("keygen")
    }

    /// `compute_commitment` must match the commitment production `keygen`
    /// installs in the public key — same preimage, same keccak.
    #[test]
    fn commitment_matches_production_keygen() {
        let (keys, pk) = production_keys();
        assert_eq!(
            keys.public_key_commitment().as_bytes().as_slice(),
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
        let exhausted = keys.stateful().public_key().max_signatures + 1;
        bytes[132..136].copy_from_slice(&exhausted.to_be_bytes());
        assert!(Keys::import(&bytes).is_some());
    }

    #[test]
    fn reset_generates_fresh_stateful_chain() {
        let (mut keys, _pk) = production_keys();
        let original_stateless = keys.stateless().clone();
        let original_commitment = *keys.public_key_commitment();
        let original_max = keys.stateful().public_key().max_signatures;

        keys.reset(b"a completely different reset seed");

        assert_ne!(*keys.public_key_commitment(), original_commitment);
        assert_eq!(keys.stateless(), &original_stateless);
        assert_eq!(
            keys.stateful().next_leaf_index(),
            INITIAL_STATEFUL_LEAF_INDEX
        );
        assert_eq!(keys.stateful().public_key().max_signatures, original_max);
        assert!(Keys::import(&keys.to_bytes()).is_some());
    }

    #[test]
    fn reset_is_deterministic() {
        let (mut keys_a, _) = production_keys();
        let (mut keys_b, _) = production_keys();

        keys_a.reset(b"same reset seed");
        keys_b.reset(b"same reset seed");

        assert_eq!(keys_a.stateful(), keys_b.stateful());
        assert_eq!(
            keys_a.public_key_commitment(),
            keys_b.public_key_commitment()
        );
    }

    /// A signature produced under a reset key must verify against the NEW
    /// commitment `reset` installs, and be rejected against the stale
    /// pre-reset commitment -- the property that makes `reset` a real key
    /// rotation rather than a no-op relabeling.
    #[test]
    fn reset_then_sign_verifies_against_new_commitment_and_rejects_old() {
        use crate::shrincs::signer::ShrincsSigner;
        use crate::shrincs::verifier::{ActionContext, ShrincsVerifier};

        let (mut keys, old_pk) = production_keys();
        let old_commitment: [u8; HASH_LEN] = old_pk
            .public_key_commitment
            .try_into()
            .expect("commitment is 32 bytes");

        keys.reset(b"reset then sign test seed");

        // `reset` only mutates the stateful half in place; round-trip through
        // `import_signing_key` to get the `PublicKey` bundle matching the
        // freshly reset key (and confirm the reset roots still import clean).
        let (mut keys, new_pk) =
            ShrincsSigner::import_signing_key(keys).expect("reset key must still import");
        let new_commitment: [u8; HASH_LEN] = new_pk
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        assert_ne!(new_commitment, old_commitment);

        let context = ActionContext {
            domain_separator: [1u8; HASH_LEN],
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
            action_type: [2u8; HASH_LEN],
            payload_hash: [3u8; HASH_LEN],
        };
        let signature = ShrincsSigner::sign_stateful_action(&mut keys, &new_pk, &context)
            .expect("sign under the reset key");

        let verifier = ShrincsVerifier::new();
        assert!(
            verifier.verify_stateful(new_commitment, &new_pk, &context, &signature),
            "signature under the reset key must verify against the new commitment"
        );
        assert!(
            !verifier.verify_stateful(old_commitment, &new_pk, &context, &signature),
            "the same signature must be rejected against the stale pre-reset commitment"
        );
    }

    #[test]
    fn recompute_commitment_matches_current_commitment() {
        let (keys, _pk) = production_keys();
        assert_eq!(keys.recompute_commitment(), *keys.public_key_commitment());
    }

    #[test]
    fn recover_commitment_from_envelope_matches_keygen_commitment() {
        let (mut keys, pk) = production_keys();
        let pre_sign_commitment = *keys.public_key_commitment();
        let sig = crate::shrincs::signer::ShrincsSigner::sign_stateful_raw(&mut keys, &[0x11; 32])
            .expect("sign");
        let env = crate::shrincs::signature::encode_stateful_envelope(&pk, &sig);

        let recovered = Keys::recover_commitment(&env).expect("recover");

        assert_eq!(recovered, pre_sign_commitment);
        assert_eq!(recovered, *production_keys().0.public_key_commitment());
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
        let real = *keys.public_key_commitment();
        let sig =
            crate::shrincs::signer::ShrincsSigner::sign_stateful_raw(&mut keys, &[0x11u8; 32])
                .expect("sign");

        let mut bad_pk = pk.clone();
        bad_pk.public_key_commitment = alloc::vec![0xFFu8; 32];
        let env = crate::shrincs::signature::encode_stateful_envelope(&bad_pk, &sig);

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
