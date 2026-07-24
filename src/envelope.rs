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

//! EVM envelope codec: byte-exact Solidity `abi.encode` framing for the
//! SHRINCS wire shapes, matching the codec surface folded into
//! `hashsigs-solidity`'s `SHRINCS.sol` / `SPHINCSPlusC.sol` (encoders
//! `encodeStatefulEnvelope`, `encodeStatelessEnvelope`, `encodeStatelessKey`,
//! `sliceStatelessSignatureEnvelope` / `encodeStatelessSignatureEnvelope`;
//! decoders `decodePublicKeyCommitment`, `decodeStatefulEnvelope`,
//! `prepareStatelessDelegation`).
//!
//! # Strictness divergence from the Solidity re-tag functions
//!
//! `SHRINCS.statefulEnvelope`, `statelessEnvelope`, and
//! `SPHINCSPlusC.statelessSignatureEnvelope` are zero-copy calldata re-tags:
//! they read offset words without bounds- or
//! canonicity-checking them, so malformed or truncated framing is rejected
//! only downstream (by a Solidity member-access revert or a verify-time
//! shape/commitment check), and some non-canonical framings that read past
//! the envelope into adjacent calldata are accepted (documented on
//! `SHRINCS.sol` as encoding malleability, never a wrong-accept). The
//! decoders in this module are **not** that re-tag; they are the
//! `decodeStatefulEnvelope`-style oracle path (plain `abi.decode` semantics)
//! made fail-closed end to end:
//!
//! - every offset and length is bounds-checked against the input slice
//!   (`Option`/`?`, never a panic or an out-of-bounds read);
//! - `uint32` word fields (WOTS-C/FORS-C counters) and offset/length words
//!   reject dirty high bits instead of silently truncating them;
//! - dynamic `bytes` padding (the zero fill up to the next 32-byte word) must
//!   be all-zero or the decode fails;
//! - each dynamic array's declared element count is capped by the matching
//!   per-profile structural constant (FORS trees, hypertree layers, WOTS
//!   chains, auth-path heights) before any element allocation, so aliased
//!   nested arrays cannot force super-linear work;
//! - dynamic-array element offsets must be sequential (no aliasing or gaps
//!   inside a `T[]` / `bytes[]` payload);
//! - top-level entry points require the high-water mark of every successfully
//!   read byte range to equal the input length (trailing bytes rejected).
//!
//! This is strictly narrower than the Solidity re-tag's acceptance set: a
//! framing the on-chain re-tag would accept via calldata-slack (offset
//! aliasing, tail truncation into adjacent calldata) is rejected here. That
//! is the intended divergence — this module targets off-chain/embedded
//! encode+decode call sites, which have no adjacent "calldata" to alias into
//! and want a canonical round-trip, not the on-chain gas-optimized re-tag's
//! wider acceptance.

use alloc::vec::Vec;

use crate::primitives::abi::{
    collect_hash_words, encode_bytes, encode_bytes32_array, encode_dynamic_array, encode_tuple,
    word_from_u32, AbiReader, Field,
};
use crate::primitives::profiles::{
    FORS_TREE_HEIGHT, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
    WOTS_CHAINS_STATEFUL,
};
use crate::primitives::HASH_LEN;
use crate::types::{
    ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, StatefulSignature,
    StatelessSignature,
};
use crate::wots_c::Signature as WotsCSignature;

/// Upper bound on a stateful auth-path length (equals the leaf index).
/// Matches the signer / wasm host cap (`MAX_STATEFUL_SIGNATURES_LIMIT`).
const MAX_STATEFUL_AUTH_PATH_LEN: usize = 4096;

/// Hypertree subtree height: one auth-path node per level per layer.
const HYPERTREE_SUBTREE_HEIGHT: usize =
    (HYPERTREE_HEIGHT as usize) / (NUM_HYPERTREE_LAYERS as usize);

fn encode_public_key_body(public_key: &PublicKey) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_bytes(&public_key.stateful_public_key)),
        Field::Dynamic(encode_bytes(&public_key.public_key_commitment)),
        Field::Dynamic(encode_bytes(&public_key.pk_seed)),
        Field::Dynamic(encode_bytes(&public_key.hypertree_root)),
    ])
}

fn encode_stateful_signature_body(signature: &StatefulSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Static(signature.randomizer),
        Field::Static(word_from_u32(signature.counter)),
        Field::Dynamic(encode_bytes32_array(&signature.chains)),
        Field::Dynamic(encode_bytes32_array(&signature.auth_path)),
    ])
}

fn encode_fors_entry_body(entry: &ForsEntry) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_bytes(&entry.secret_leaf)),
        Field::Dynamic(encode_dynamic_array(
            entry.auth_path.iter().map(|node| encode_bytes(node)).collect(),
        )),
    ])
}

fn encode_fors_signature_body(signature: &ForsSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_bytes(&signature.randomizer)),
        Field::Static(word_from_u32(signature.counter)),
        Field::Dynamic(encode_dynamic_array(
            signature.entries.iter().map(encode_fors_entry_body).collect(),
        )),
    ])
}

fn encode_wots_c_signature_body(signature: &WotsCSignature) -> Vec<u8> {
    signature.to_bytes()
}

fn encode_hypertree_layer_body(layer: &HypertreeLayerSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_bytes(&layer.wots_c_pk_hash)),
        Field::Dynamic(encode_wots_c_signature_body(&layer.wots_c_signature)),
        Field::Dynamic(encode_dynamic_array(
            layer.auth_path.iter().map(|node| encode_bytes(node)).collect(),
        )),
    ])
}

fn encode_stateless_signature_body(signature: &StatelessSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_fors_signature_body(&signature.fors)),
        Field::Dynamic(encode_dynamic_array(
            signature.hypertree.iter().map(encode_hypertree_layer_body).collect(),
        )),
    ])
}

fn decode_public_key(reader: &AbiReader, base: usize) -> Option<PublicKey> {
    Some(PublicKey {
        stateful_public_key: reader.decode_bytes(base, base)?,
        public_key_commitment: reader.decode_bytes(base, base.checked_add(32)?)?,
        pk_seed: reader.decode_bytes(base, base.checked_add(64)?)?,
        hypertree_root: reader.decode_bytes(base, base.checked_add(96)?)?,
    })
}

fn decode_stateful_signature(reader: &AbiReader, base: usize) -> Option<StatefulSignature> {
    Some(StatefulSignature {
        randomizer: reader.read_bytes32(base)?,
        counter: reader.read_u32(base.checked_add(32)?)?,
        chains: reader.decode_array_bytes32(base, base.checked_add(64)?, WOTS_CHAINS_STATEFUL)?,
        auth_path: reader.decode_array_bytes32(
            base,
            base.checked_add(96)?,
            MAX_STATEFUL_AUTH_PATH_LEN,
        )?,
    })
}

fn decode_fors_entry(reader: &AbiReader, base: usize) -> Option<ForsEntry> {
    Some(ForsEntry {
        secret_leaf: reader.decode_bytes32_field(base, base)?,
        auth_path: collect_hash_words(reader.decode_array_bytes(
            base,
            base.checked_add(32)?,
            FORS_TREE_HEIGHT as usize,
        )?)?,
    })
}

fn decode_fors_signature(reader: &AbiReader, base: usize) -> Option<ForsSignature> {
    Some(ForsSignature {
        randomizer: reader.decode_bytes32_field(base, base)?,
        counter: reader.read_u32(base.checked_add(32)?)?,
        entries: reader.decode_dynamic_array(
            base,
            base.checked_add(64)?,
            NUM_FORS_TREES as usize,
            decode_fors_entry,
        )?,
    })
}

fn decode_wots_c_signature(reader: &AbiReader, base: usize) -> Option<WotsCSignature> {
    WotsCSignature::decode(reader, base)
}

fn decode_hypertree_layer_signature(
    reader: &AbiReader,
    base: usize,
) -> Option<HypertreeLayerSignature> {
    let wots_head = base.checked_add(32)?;
    let wots_start = reader.decode_offset(base, wots_head)?;
    Some(HypertreeLayerSignature {
        wots_c_pk_hash: reader.decode_bytes32_field(base, base)?,
        wots_c_signature: decode_wots_c_signature(reader, wots_start)?,
        auth_path: collect_hash_words(reader.decode_array_bytes(
            base,
            base.checked_add(64)?,
            HYPERTREE_SUBTREE_HEIGHT,
        )?)?,
    })
}

fn decode_stateless_signature(reader: &AbiReader, base: usize) -> Option<StatelessSignature> {
    let fors_start = reader.decode_offset(base, base)?;
    Some(StatelessSignature {
        fors: decode_fors_signature(reader, fors_start)?,
        hypertree: reader.decode_dynamic_array(
            base,
            base.checked_add(32)?,
            NUM_HYPERTREE_LAYERS as usize,
            decode_hypertree_layer_signature,
        )?,
    })
}

// ---------------------------------------------------------------------
// Public codec surface
// ---------------------------------------------------------------------

/// Inverse of `SHRINCS.statefulEnvelope` / mirrors `encodeStatefulEnvelope`.
/// Layout: `abi.encode(PublicKey, SHRINCS.Signature)`.
pub fn encode_stateful_envelope(public_key: &PublicKey, signature: &StatefulSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![
        Field::Dynamic(encode_public_key_body(public_key)),
        Field::Dynamic(encode_stateful_signature_body(signature)),
    ])
}

/// Strict decoder for the layout `encode_stateful_envelope` produces. See
/// the module-level strictness note for how this differs from the Solidity
/// `statefulEnvelope` calldata re-tag.
pub fn decode_stateful_envelope(data: &[u8]) -> Option<(PublicKey, StatefulSignature)> {
    let reader = AbiReader::new(data);
    let public_key_start = reader.decode_offset(0, 0)?;
    let signature_start = reader.decode_offset(0, 32)?;
    let decoded = (
        decode_public_key(&reader, public_key_start)?,
        decode_stateful_signature(&reader, signature_start)?,
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
        Field::Dynamic(encode_public_key_body(public_key)),
        Field::Dynamic(encode_stateless_signature_body(signature)),
    ])
}

/// Strict decoder for the layout `encode_stateless_envelope` produces.
pub fn decode_stateless_envelope(data: &[u8]) -> Option<(PublicKey, StatelessSignature)> {
    let reader = AbiReader::new(data);
    let public_key_start = reader.decode_offset(0, 0)?;
    let signature_start = reader.decode_offset(0, 32)?;
    let decoded = (
        decode_public_key(&reader, public_key_start)?,
        decode_stateless_signature(&reader, signature_start)?,
    );
    reader.finish()?;
    Some(decoded)
}

/// Mirrors `SHRINCS.encodeStatelessKey`. Layout:
/// `abi.encode(bytes32 pkSeed, bytes32 hypertreeRoot)`, which for two static
/// words is exactly the 64-byte concatenation with no offsets.
pub fn encode_stateless_key(
    pk_seed: [u8; HASH_LEN],
    hypertree_root: [u8; HASH_LEN],
) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&pk_seed);
    out[32..].copy_from_slice(&hypertree_root);
    out
}

/// Byte-identical (for canonically framed inputs) to
/// `SHRINCS.sliceStatelessSignatureEnvelope` / mirrors
/// `SPHINCSPlusC.encodeStatelessSignatureEnvelope`. Layout:
/// `abi.encode(SPHINCSPlusC.Signature)`.
pub fn encode_stateless_signature_envelope(signature: &StatelessSignature) -> Vec<u8> {
    encode_tuple(alloc::vec![Field::Dynamic(encode_stateless_signature_body(
        signature
    ))])
}

/// Strict decoder for the layout `encode_stateless_signature_envelope`
/// produces.
pub fn decode_stateless_signature_envelope(data: &[u8]) -> Option<StatelessSignature> {
    let reader = AbiReader::new(data);
    let signature_start = reader.decode_offset(0, 0)?;
    let decoded = decode_stateless_signature(&reader, signature_start)?;
    reader.finish()?;
    Some(decoded)
}

/// Mirrors `SHRINCS.decodePublicKeyCommitment`: the verifier `key` bytes are
/// exactly one 32-byte commitment word, nothing else.
pub fn decode_public_key_commitment(key: &[u8]) -> Option<[u8; HASH_LEN]> {
    if key.len() != HASH_LEN {
        return None;
    }
    key.try_into().ok()
}


#[cfg(test)]
mod tests {
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

    fn sample_stateful_signature() -> StatefulSignature {
        StatefulSignature {
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
                    ForsEntry {
                        secret_leaf: [0x88; HASH_LEN],
                        auth_path: vec![[0x99; HASH_LEN], [0xA0; HASH_LEN]],
                    },
                    ForsEntry {
                        secret_leaf: [0xA1; HASH_LEN],
                        auth_path: vec![[0xA2; HASH_LEN]],
                    },
                ],
            },
            // One layer per profile layer: 8 at 256s, 1 at 128s. A fixed count
            // would exceed the decoder's `<= NUM_HYPERTREE_LAYERS` cap on the
            // single-layer 128s profiles.
            hypertree: (0..NUM_HYPERTREE_LAYERS)
                .map(|layer| HypertreeLayerSignature {
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
        assert_eq!(encode_stateful_envelope(&decoded_key, &decoded_sig), encoded);
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
        assert_eq!(encode_stateless_envelope(&decoded_key, &decoded_sig), encoded);
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

    #[test]
    fn stateless_signature_envelope_round_trips() {
        let signature = sample_stateless_signature();
        let encoded = encode_stateless_signature_envelope(&signature);
        let decoded =
            decode_stateless_signature_envelope(&encoded).expect("valid envelope must decode");
        assert_eq!(decoded, signature);
        assert_eq!(encode_stateless_signature_envelope(&decoded), encoded);
    }

    #[test]
    fn public_key_commitment_round_trips() {
        let commitment = [0x42; HASH_LEN];
        assert_eq!(decode_public_key_commitment(&commitment), Some(commitment));
    }

    #[test]
    fn prepare_stateless_delegation_extracts_pinned_sibling_shapes() {
        let mut public_key = sample_public_key();
        // Recompute a self-consistent commitment isn't in scope here (that's
        // `dispatch::public_key_commitment`'s job); use the crate helper to
        // build a matching bundle instead of hand-rolling the keccak call.
        let commitment = crate::shrincs::public_key_commitment(
            &public_key.stateful_public_key,
            &public_key.pk_seed.clone().try_into().unwrap(),
            &public_key.hypertree_root.clone().try_into().unwrap(),
        );
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
        assert_eq!(delegate_signature, encode_stateless_signature_envelope(&signature));

        // A wrong expected commitment must fail closed.
        let mut wrong_commitment = commitment;
        wrong_commitment[0] ^= 0x01;
        assert!(crate::shrincs::prepare_stateless_delegation(wrong_commitment, &envelope).is_none());
    }

    // --- (c) malformed-input rejection tests ------------------------------

    #[test]
    fn truncated_stateful_envelope_is_rejected() {
        let encoded =
            encode_stateful_envelope(&sample_public_key(), &sample_stateful_signature());
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
        let signature_start =
            usize::try_from(u32::from_be_bytes(
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

    #[test]
    fn public_key_commitment_wrong_length_is_rejected() {
        assert!(decode_public_key_commitment(&[0u8; 31]).is_none());
        assert!(decode_public_key_commitment(&[0u8; 33]).is_none());
    }

    #[test]
    fn stateless_signature_with_empty_hypertree_round_trips_as_empty() {
        // Unlike the Solidity slice-copy re-tag (which Panics on an empty
        // hypertree/authPath because it indexes the last element), this
        // strict abi.decode-style path has no such precondition and simply
        // decodes the zero-length array.
        let signature = StatelessSignature {
            fors: ForsSignature {
                randomizer: [0x01; HASH_LEN],
                counter: 0,
                entries: vec![],
            },
            hypertree: vec![],
        };
        let encoded = encode_stateless_signature_envelope(&signature);
        assert_eq!(
            decode_stateless_signature_envelope(&encoded),
            Some(signature)
        );
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

        let mut stateless =
            encode_stateless_signature_envelope(&sample_stateless_signature());
        stateless.extend_from_slice(&[0xAA, 0xBB]);
        assert!(
            decode_stateless_signature_envelope(&stateless).is_none(),
            "trailing junk on stateless signature envelope must be rejected"
        );
    }

    #[test]
    fn oversized_array_length_is_rejected() {
        // Stateful chains are `bytes32[]` capped at WOTS_CHAINS_STATEFUL.
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
        write_abi_usize(&mut encoded, chains_start, WOTS_CHAINS_STATEFUL + 1);
        assert!(
            decode_stateful_envelope(&encoded).is_none(),
            "chains length WOTS_CHAINS_STATEFUL+1 must be rejected"
        );

        // FORS entries are a dynamic struct array capped at NUM_FORS_TREES.
        let mut encoded = encode_stateless_signature_envelope(&sample_stateless_signature());
        // Outer head: one offset to the signature body.
        let sig_start = read_abi_usize(&encoded, 0);
        // Signature body head: fors_off@0, hypertree_off@32.
        let fors_start = sig_start + read_abi_usize(&encoded, sig_start);
        // ForsSignature head: randomizer_off@0, counter@32, entries_off@64.
        let entries_start = fors_start + read_abi_usize(&encoded, fors_start + 64);
        write_abi_usize(&mut encoded, entries_start, NUM_FORS_TREES as usize + 1);
        assert!(
            decode_stateless_signature_envelope(&encoded).is_none(),
            "FORS entries length NUM_FORS_TREES+1 must be rejected"
        );
    }

    #[test]
    fn aliased_dynamic_array_offsets_are_rejected() {
        // Build a valid `bytes[]` auth_path of two elements inside a FORS
        // entry, then rewrite both element offsets to the first payload so a
        // lenient decoder would double-read one blob (alias). Sequential
        // offset checks must reject.
        let mut encoded =
            encode_stateless_signature_envelope(&sample_stateless_signature());
        let sig_start = read_abi_usize(&encoded, 0);
        let fors_start = sig_start + read_abi_usize(&encoded, sig_start);
        let entries_start = fors_start + read_abi_usize(&encoded, fors_start + 64);
        // entries: length word, then one offset per entry (sample has 2).
        // Offsets are relative to the start of the offset table (entries_start+32).
        let entry0_start =
            entries_start + 32 + read_abi_usize(&encoded, entries_start + 32);
        // ForsEntry head: secret_leaf_off@0, auth_path_off@32.
        let auth_start = entry0_start + read_abi_usize(&encoded, entry0_start + 32);
        // auth_path is bytes[] with length 2; force the second element offset
        // equal to the first (relative to the offset table at auth_start+32).
        let first_elem_rel = read_abi_usize(&encoded, auth_start + 32);
        write_abi_usize(&mut encoded, auth_start + 64, first_elem_rel);
        assert!(
            decode_stateless_signature_envelope(&encoded).is_none(),
            "aliased bytes[] element offsets must be rejected"
        );
    }
}
