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

//! The primary SHRINCS signature (the stateful UXMSS fast-path signature),
//! its ABI codec, and the composite envelope codecs that pair a
//! [`super::key::PublicKey`] with a signature.
//!
//! `Signature::to_bytes`/`from_bytes` are byte-identical to the historical
//! `envelope::encode_stateful_signature_body`/`decode_stateful_signature`,
//! wrapped one more offset level (mirroring
//! `sphincs_plus_c::Signature::to_bytes`) for a standalone
//! `abi.encode(SHRINCS.Signature)` form. The composite
//! `encode_stateful_envelope`/`decode_stateful_envelope` and
//! `encode_stateless_envelope`/`decode_stateless_envelope` are byte-identical
//! to the historical `envelope::encode_stateful_envelope` /
//! `decode_stateful_envelope` / `encode_stateless_envelope` /
//! `decode_stateless_envelope`, and use `encode_body`/`decode` directly,
//! without that extra layer.

use alloc::vec::Vec;

use super::key::PublicKey;
use crate::abi::{encode_bytes32_array, encode_tuple, word_from_u32, AbiReader, Field};
use crate::sphincs_plus_c::Signature as StatelessSignature;
use crate::HASH_LEN;

/// Upper bound on a stateful auth-path length (equals the leaf index).
/// Matches the signer / wasm host cap (`MAX_STATEFUL_SIGNATURES_LIMIT`).
const MAX_STATEFUL_AUTH_PATH_LEN: usize = 4096;

/// The primary SHRINCS signature: the stateful UXMSS fast-path signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Per-signature randomizer mixed into WOTS digit derivation.
    pub randomizer: [u8; HASH_LEN],
    /// Counter mixed into WOTS digit derivation.
    pub counter: u32,
    /// One WOTS-C chain value per reconstructed digit.
    pub chains: Vec<[u8; HASH_LEN]>,
    /// Unbalanced authentication path. Its length is also the leaf index.
    pub auth_path: Vec<[u8; HASH_LEN]>,
}

impl Signature {
    /// ABI-encode the signature body (two static words plus two `bytes32[]`
    /// fields), without a further outer offset. Byte-identical to the
    /// historical `envelope::encode_stateful_signature_body`. Used both by
    /// `to_bytes` (wrapped one level further, below) and directly by the
    /// composite `encode_stateful_envelope`.
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![
            Field::Static(self.randomizer),
            Field::Static(word_from_u32(self.counter)),
            Field::Dynamic(encode_bytes32_array(&self.chains)),
            Field::Dynamic(encode_bytes32_array(&self.auth_path)),
        ])
    }

    /// ABI-encode the signature envelope: `abi.encode(SHRINCS.Signature)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![Field::Dynamic(self.encode_body())])
    }

    /// Decode a signature body already located at `base` within a shared
    /// `AbiReader`. No trailing-bytes check here: `base` commonly sits inside
    /// a larger encoded envelope (the composite `encode_stateful_envelope` or
    /// this type's own `from_bytes`), so exhaustion is the calling top-level
    /// decoder's responsibility. Byte-identical to the historical
    /// `envelope::decode_stateful_signature`.
    pub(crate) fn decode(reader: &AbiReader, base: usize) -> Option<Self> {
        Some(Self {
            randomizer: reader.read_bytes32(base)?,
            counter: reader.read_u32(base.checked_add(32)?)?,
            chains: reader.decode_array_bytes32(
                base,
                base.checked_add(64)?,
                crate::wots_c::NUM_CHAINS,
            )?,
            auth_path: reader.decode_array_bytes32(
                base,
                base.checked_add(96)?,
                MAX_STATEFUL_AUTH_PATH_LEN,
            )?,
        })
    }

    /// Decode a standalone byte blob produced by `to_bytes`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let reader = AbiReader::new(data);
        let signature_start = reader.decode_offset(0, 0)?;
        let decoded = Self::decode(&reader, signature_start)?;
        reader.finish()?;
        Some(decoded)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

// ---------------------------------------------------------------------
// Composite envelope codecs (`PublicKey` ‖ a signature)
// ---------------------------------------------------------------------

/// Inverse of `SHRINCS.statefulEnvelope` / mirrors `encodeStatefulEnvelope`.
/// Layout: `abi.encode(PublicKey, SHRINCS.Signature)`.
pub fn encode_stateful_envelope(public_key: &PublicKey, signature: &Signature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(public_key.encode_body()),
        Field::Dynamic(signature.encode_body()),
    ])
}

/// Strict decoder for the layout `encode_stateful_envelope` produces. See
/// `crate::shrincs`'s module-level strictness note for how this differs from
/// the Solidity `statefulEnvelope` calldata re-tag.
pub fn decode_stateful_envelope(data: &[u8]) -> Option<(PublicKey, Signature)> {
    let reader = AbiReader::new(data);
    let public_key_start = reader.decode_offset(0, 0)?;
    let signature_start = reader.decode_offset(0, 32)?;
    let decoded = (
        PublicKey::decode(&reader, public_key_start)?,
        Signature::decode(&reader, signature_start)?,
    );
    reader.finish()?;
    Some(decoded)
}

/// Inverse of `SHRINCS.statelessEnvelope` / mirrors `encodeStatelessEnvelope`.
/// Layout: `abi.encode(PublicKey, SPHINCSPlusC.Signature)`.
pub fn encode_stateless_envelope(
    public_key: &PublicKey,
    signature: &StatelessSignature,
) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(public_key.encode_body()),
        Field::Dynamic(signature.encode_body()),
    ])
}

/// Strict decoder for the layout `encode_stateless_envelope` produces.
pub fn decode_stateless_envelope(data: &[u8]) -> Option<(PublicKey, StatelessSignature)> {
    let reader = AbiReader::new(data);
    let public_key_start = reader.decode_offset(0, 0)?;
    let signature_start = reader.decode_offset(0, 32)?;
    let decoded = (
        PublicKey::decode(&reader, public_key_start)?,
        StatelessSignature::decode(&reader, signature_start)?,
    );
    reader.finish()?;
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::NUM_HYPERTREE_LAYERS;
    use crate::sphincs_plus_c::{ForsEntry as Entry, ForsSignature, LayerSignature};
    use crate::wots_c::Signature as WotsCSignature;
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

    fn sample_stateful_signature() -> Signature {
        Signature {
            randomizer: [0x11; HASH_LEN],
            counter: 0x0102_0304,
            chains: vec![[0x22; HASH_LEN], [0x33; HASH_LEN], [0x44; HASH_LEN]],
            auth_path: vec![[0x55; HASH_LEN], [0x66; HASH_LEN]],
        }
    }

    fn sample_stateless_signature() -> StatelessSignature {
        StatelessSignature {
            fors: ForsSignature {
                randomizer: [0x77; HASH_LEN],
                counter: 7,
                entries: vec![
                    Entry {
                        secret_leaf: [0x88; HASH_LEN],
                        auth_path: vec![[0x99; HASH_LEN], [0xA0; HASH_LEN]],
                    },
                    Entry {
                        secret_leaf: [0xA1; HASH_LEN],
                        auth_path: vec![[0xA2; HASH_LEN]],
                    },
                ],
            },
            // One layer per profile layer: 8 at 256s, 1 at 128s. A fixed count
            // would exceed the decoder's `<= NUM_HYPERTREE_LAYERS` cap on the
            // single-layer 128s profiles.
            hypertree: (0..NUM_HYPERTREE_LAYERS)
                .map(|layer| LayerSignature {
                    wots_c_pk_hash: [0xB1 ^ layer; HASH_LEN],
                    wots_c_signature: WotsCSignature {
                        randomizer: [0xB2 ^ layer; HASH_LEN],
                        counter: 9 + layer as u32,
                        chains: vec![[0xB3 ^ layer; HASH_LEN], [0xB4 ^ layer; HASH_LEN]],
                    },
                    auth_path: vec![[0xB5 ^ layer; HASH_LEN]],
                })
                .collect(),
        }
    }

    // --- (b) standalone Signature codec tests -----------------------------

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let signature = sample_stateful_signature();
        let encoded = signature.to_bytes();
        let decoded = Signature::from_bytes(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, signature);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut encoded = sample_stateful_signature().to_bytes();
        encoded.extend_from_slice(&[0xAA, 0xBB]);
        assert!(
            Signature::from_bytes(&encoded).is_none(),
            "trailing junk on the signature envelope must be rejected"
        );
    }

    #[test]
    fn try_from_delegates_to_from_bytes() {
        let signature = sample_stateful_signature();
        let encoded = signature.to_bytes();
        let decoded = Signature::try_from(encoded.as_slice()).expect("valid encoding must decode");
        assert_eq!(decoded, signature);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(Signature::try_from(truncated).is_err());
    }

    // --- (a) round-trip tests -------------------------------------------

    #[test]
    fn stateful_envelope_round_trips() {
        let public_key = sample_public_key();
        let signature = sample_stateful_signature();
        let encoded = encode_stateful_envelope(&public_key, &signature);
        let (decoded_key, decoded_sig) =
            decode_stateful_envelope(&encoded).expect("valid envelope must decode");
        assert_eq!(decoded_key, public_key);
        assert_eq!(decoded_sig, signature);
        // Canonical framing must re-encode byte-identical.
        assert_eq!(
            encode_stateful_envelope(&decoded_key, &decoded_sig),
            encoded
        );
    }

    #[test]
    fn stateless_envelope_round_trips() {
        let public_key = sample_public_key();
        let signature = sample_stateless_signature();
        let encoded = encode_stateless_envelope(&public_key, &signature);
        let (decoded_key, decoded_sig) =
            decode_stateless_envelope(&encoded).expect("valid envelope must decode");
        assert_eq!(decoded_key, public_key);
        assert_eq!(decoded_sig, signature);
        assert_eq!(
            encode_stateless_envelope(&decoded_key, &decoded_sig),
            encoded
        );
    }

    #[test]
    fn prepare_stateless_delegation_extracts_pinned_sibling_shapes() {
        let mut public_key = sample_public_key();
        // Build a self-consistent commitment via the `Commitment::of` helper
        // instead of hand-rolling the keccak call.
        let commitment = *crate::shrincs::key::Commitment::of(
            &public_key.stateful_public_key,
            &public_key.pk_seed.clone().try_into().unwrap(),
            &public_key.hypertree_root.clone().try_into().unwrap(),
        )
        .as_bytes();
        public_key.public_key_commitment = commitment.to_vec();
        let signature = sample_stateless_signature();
        let envelope = encode_stateless_envelope(&public_key, &signature);

        let (delegate_key, delegate_signature) =
            crate::shrincs::prepare_stateless_delegation(commitment, &envelope)
                .expect("matching commitment must delegate");
        let mut expected_key = [0u8; 64];
        expected_key[..32].copy_from_slice(&public_key.pk_seed);
        expected_key[32..].copy_from_slice(&public_key.hypertree_root);
        assert_eq!(delegate_key, expected_key);
        assert_eq!(delegate_signature, signature.to_bytes());

        // A wrong expected commitment must fail closed.
        let mut wrong_commitment = commitment;
        wrong_commitment[0] ^= 0x01;
        assert!(
            crate::shrincs::prepare_stateless_delegation(wrong_commitment, &envelope).is_none()
        );
    }

    // --- (c) malformed-input rejection tests ------------------------------

    #[test]
    fn truncated_stateful_envelope_is_rejected() {
        let encoded = encode_stateful_envelope(&sample_public_key(), &sample_stateful_signature());
        for cut in [0usize, 1, 32, 63, encoded.len() - 1] {
            assert!(
                decode_stateful_envelope(&encoded[..cut]).is_none(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn stateful_envelope_with_out_of_bounds_offset_is_rejected() {
        let mut encoded =
            encode_stateful_envelope(&sample_public_key(), &sample_stateful_signature());
        // Blow the PublicKey offset word's value bytes out to a huge offset
        // that is guaranteed to fall past the end of the buffer.
        for byte in &mut encoded[24..32] {
            *byte = 0xFF;
        }
        assert!(decode_stateful_envelope(&encoded).is_none());
    }

    #[test]
    fn stateful_envelope_with_dirty_offset_high_bits_is_rejected() {
        let mut encoded =
            encode_stateful_envelope(&sample_public_key(), &sample_stateful_signature());
        // Dirty high bits above the 8 bytes read_usize actually consumes.
        encoded[0] = 0x01;
        assert!(decode_stateful_envelope(&encoded).is_none());
    }

    #[test]
    fn stateful_signature_with_dirty_counter_high_bits_is_rejected() {
        let public_key = sample_public_key();
        let signature = sample_stateful_signature();
        let mut encoded = encode_stateful_envelope(&public_key, &signature);
        let signature_offset = 32usize;
        let signature_start = usize::try_from(u32::from_be_bytes(
            encoded[signature_offset + 28..signature_offset + 32]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        // counter word sits at signature_start + 32; dirty one high byte.
        encoded[signature_start + 32] = 0x01;
        assert!(decode_stateful_envelope(&encoded).is_none());
    }

    #[test]
    fn stateful_envelope_with_dirty_bytes_padding_is_rejected() {
        let public_key = sample_public_key();
        let signature = sample_stateful_signature();
        let mut encoded = encode_stateful_envelope(&public_key, &signature);
        // The 68-byte statefulPublicKey field pads 28 zero bytes up to the
        // next word; dirty the last one.
        let last = encoded.len();
        // Locate the pad region by re-deriving offsets: public key body
        // starts right after the 2-word top head (64 bytes); within it, the
        // stateful_public_key bytes begin after its own 4-word head (128
        // bytes) plus the 32-byte length word.
        let public_key_body_start = 64usize;
        let field_data_start = public_key_body_start + 128 + 32;
        let pad_byte_pos = field_data_start + 68 + 27; // last of the 28 pad bytes
        assert!(pad_byte_pos < last);
        encoded[pad_byte_pos] = 0x01;
        assert!(decode_stateful_envelope(&encoded).is_none());
    }

    /// Read a clean ABI length/offset word at `pos` (big-endian u64 in the
    /// low 8 bytes of a 32-byte word).
    fn read_abi_usize(buf: &[u8], pos: usize) -> usize {
        usize::try_from(u64::from_be_bytes(
            buf[pos + 24..pos + 32].try_into().unwrap(),
        ))
        .unwrap()
    }

    fn write_abi_usize(buf: &mut [u8], pos: usize, value: usize) {
        buf[pos..pos + 24].fill(0);
        buf[pos + 24..pos + 32].copy_from_slice(&(value as u64).to_be_bytes());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded =
            encode_stateful_envelope(&sample_public_key(), &sample_stateful_signature());
        encoded.push(0x00);
        assert!(
            decode_stateful_envelope(&encoded).is_none(),
            "single trailing byte must be rejected"
        );
    }

    #[test]
    fn oversized_array_length_is_rejected() {
        // Stateful chains are `bytes32[]` capped at `wots_c::NUM_CHAINS`.
        // Overwrite the chains length word to max+1 without growing the buffer
        // so a naive decoder would either OOM-prep or walk off the end; with
        // the cap it must fail closed before element allocation.
        let public_key = sample_public_key();
        let signature = sample_stateful_signature();
        let mut encoded = encode_stateful_envelope(&public_key, &signature);

        // Top head: pk_off@0, sig_off@32.
        let signature_start = read_abi_usize(&encoded, 32);
        // Signature body head: randomizer@0, counter@32, chains_off@64, auth_off@96.
        let chains_start = signature_start + read_abi_usize(&encoded, signature_start + 64);
        write_abi_usize(&mut encoded, chains_start, crate::wots_c::NUM_CHAINS + 1);
        assert!(
            decode_stateful_envelope(&encoded).is_none(),
            "WOTS-C chain count + 1 must be rejected"
        );
    }
}
