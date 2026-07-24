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

//! SPHINCS+C stateless signature (a `fors_c::Signature` plus the hypertree
//! layers that carry its root to the pinned hypertree root), its ABI codec,
//! and the SPHINCS+C key-spec byte helper.
//!
//! `Signature::to_bytes`/`from_bytes` are byte-identical to the historical
//! `envelope::encode_stateless_signature_envelope`/
//! `decode_stateless_signature_envelope` — the `abi.encode(SPHINCSPlusC.Signature)`
//! envelope form that `wasm` and `SphincsPlusCVerifier` consume. `Signature::decode`
//! (embedded, no further offset) is byte-identical to the historical
//! `envelope::decode_stateless_signature`; `Signature::encode_body` is its
//! encode-side counterpart, byte-identical to the historical
//! `envelope::encode_stateless_signature_body`. The composite
//! `envelope::encode_stateless_envelope`/`decode_stateless_envelope`
//! (`PublicKey ‖ Signature`) still delegates to `encode_body`/`decode` directly,
//! without the extra envelope-offset layer.
//!
//! `encode_stateless_key` is byte-identical to the historical
//! `envelope::encode_stateless_key` (mirrors `SHRINCS.encodeStatelessKey`).

use alloc::vec::Vec;

use super::fors_c;
use super::hypertree::LayerSignature;
use crate::primitives::abi::{encode_dynamic_array, encode_tuple, AbiReader, Field};
use crate::primitives::profiles::NUM_HYPERTREE_LAYERS;
use crate::primitives::HASH_LEN;

/// SPHINCS+C stateless signature: a FORS-C signature over the message,
/// carried up through the hypertree layers to the pinned hypertree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// FORS-C signature that signs the external message and returns the first root.
    pub fors: fors_c::Signature,
    /// Hypertree layers that carry the FORS root up to the pinned hypertree root.
    pub hypertree: Vec<LayerSignature>,
}

impl Signature {
    /// ABI-encode the signature body (`fors_offset || hypertree_offset ||
    /// data`), without a further outer offset. Byte-identical to the
    /// historical `envelope::encode_stateless_signature_body`. Used both by
    /// `to_bytes` (wrapped one level further, below) and directly by the
    /// composite `envelope::encode_stateless_envelope`.
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![
            Field::Dynamic(self.fors.to_bytes()),
            Field::Dynamic(encode_dynamic_array(
                self.hypertree.iter().map(LayerSignature::to_bytes).collect(),
            )),
        ])
    }

    /// ABI-encode the signature envelope: `abi.encode(SPHINCSPlusC.Signature)`.
    /// Byte-identical to the historical
    /// `envelope::encode_stateless_signature_envelope`. This is the form
    /// `wasm` and `SphincsPlusCVerifier` consume.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tuple(alloc::vec![Field::Dynamic(self.encode_body())])
    }

    /// Decode a signature body already located at `base` within a shared
    /// `AbiReader`. No trailing-bytes check here: `base` commonly sits inside
    /// a larger encoded envelope (the composite
    /// `envelope::decode_stateless_envelope` or this type's own
    /// `from_bytes`), so exhaustion is the calling top-level decoder's
    /// responsibility. Byte-identical to the historical
    /// `envelope::decode_stateless_signature`.
    pub(crate) fn decode(reader: &AbiReader, base: usize) -> Option<Self> {
        let fors_start = reader.decode_offset(base, base)?;
        Some(Self {
            fors: fors_c::Signature::decode(reader, fors_start)?,
            hypertree: reader.decode_dynamic_array(
                base,
                base.checked_add(32)?,
                NUM_HYPERTREE_LAYERS as usize,
                LayerSignature::decode,
            )?,
        })
    }

    /// Decode a standalone byte blob produced by `to_bytes`. Byte-identical
    /// to the historical `envelope::decode_stateless_signature_envelope`,
    /// built as a top-level entrypoint: reads the outer offset, decodes the
    /// body at that offset, then rejects trailing bytes.
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

/// Mirrors `SHRINCS.encodeStatelessKey`. Layout:
/// `abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot)`, which for two static
/// words is exactly the 64-byte concatenation with no offsets. Byte-identical
/// to the historical `envelope::encode_stateless_key`.
pub fn encode_stateless_key(pk_seed: [u8; HASH_LEN], hypertree_root: [u8; HASH_LEN]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&pk_seed);
    out[32..].copy_from_slice(&hypertree_root);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphincs_plus_c::fors_c::Entry;
    use crate::wots_c::Signature as WotsCSignature;
    use alloc::vec;

    fn sample_signature() -> Signature {
        Signature {
            fors: fors_c::Signature {
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

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let signature = sample_signature();
        let encoded = signature.to_bytes();
        let decoded = Signature::from_bytes(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, signature);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn empty_hypertree_round_trips_as_empty() {
        // Unlike the Solidity slice-copy re-tag (which panics on an empty
        // hypertree/authPath because it indexes the last element), this
        // strict abi.decode-style path has no such precondition and simply
        // decodes the zero-length array.
        let signature = Signature {
            fors: fors_c::Signature {
                randomizer: [0x01; HASH_LEN],
                counter: 0,
                entries: vec![],
            },
            hypertree: vec![],
        };
        let encoded = signature.to_bytes();
        assert_eq!(Signature::from_bytes(&encoded), Some(signature));
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut encoded = sample_signature().to_bytes();
        encoded.extend_from_slice(&[0xAA, 0xBB]);
        assert!(
            Signature::from_bytes(&encoded).is_none(),
            "trailing junk on the signature envelope must be rejected"
        );
    }

    #[test]
    fn try_from_delegates_to_from_bytes() {
        let signature = sample_signature();
        let encoded = signature.to_bytes();
        let decoded =
            Signature::try_from(encoded.as_slice()).expect("valid encoding must decode");
        assert_eq!(decoded, signature);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(Signature::try_from(truncated).is_err());
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
    fn oversized_fors_entries_length_is_rejected() {
        // FORS entries are a dynamic struct array capped at NUM_FORS_TREES.
        use crate::primitives::profiles::NUM_FORS_TREES;
        let mut encoded = sample_signature().to_bytes();
        // Outer head: one offset to the signature body.
        let sig_start = read_abi_usize(&encoded, 0);
        // Signature body head: fors_off@0, hypertree_off@32.
        let fors_start = sig_start + read_abi_usize(&encoded, sig_start);
        // ForsSignature head: randomizer_off@0, counter@32, entries_off@64.
        let entries_start = fors_start + read_abi_usize(&encoded, fors_start + 64);
        write_abi_usize(&mut encoded, entries_start, NUM_FORS_TREES as usize + 1);
        assert!(
            Signature::from_bytes(&encoded).is_none(),
            "FORS entries length NUM_FORS_TREES+1 must be rejected"
        );
    }

    #[test]
    fn aliased_dynamic_array_offsets_are_rejected() {
        // Build a valid `bytes[]` auth_path of two elements inside a FORS
        // entry, then rewrite both element offsets to the first payload so a
        // lenient decoder would double-read one blob (alias). Sequential
        // offset checks must reject.
        let mut encoded = sample_signature().to_bytes();
        let sig_start = read_abi_usize(&encoded, 0);
        let fors_start = sig_start + read_abi_usize(&encoded, sig_start);
        let entries_start = fors_start + read_abi_usize(&encoded, fors_start + 64);
        // entries: length word, then one offset per entry (sample has 2).
        // Offsets are relative to the start of the offset table (entries_start+32).
        let entry0_start = entries_start + 32 + read_abi_usize(&encoded, entries_start + 32);
        // ForsEntry head: secret_leaf_off@0, auth_path_off@32.
        let auth_start = entry0_start + read_abi_usize(&encoded, entry0_start + 32);
        // auth_path is bytes[] with length 2; force the second element offset
        // equal to the first (relative to the offset table at auth_start+32).
        let first_elem_rel = read_abi_usize(&encoded, auth_start + 32);
        write_abi_usize(&mut encoded, auth_start + 64, first_elem_rel);
        assert!(
            Signature::from_bytes(&encoded).is_none(),
            "aliased bytes[] element offsets must be rejected"
        );
    }

    #[test]
    fn stateless_key_encodes_to_64_byte_layout() {
        let pk_seed = [0x12; HASH_LEN];
        let hypertree_root = [0x34; HASH_LEN];
        let encoded = encode_stateless_key(pk_seed, hypertree_root);
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[..HASH_LEN], &pk_seed); // pkSeed occupies the first word
        assert_eq!(&encoded[HASH_LEN..], &hypertree_root); // hypertreeRoot the second
    }
}
