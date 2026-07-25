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

//! SHRINCS public-key wire type, its ABI codec, and the shared
//! stateful-public-key layout / commitment helpers.
//!
//! `PublicKey`'s `to_bytes`/`from_bytes` are byte-identical to the historical
//! `envelope::encode_public_key_body`/`decode_public_key`, wrapped one more
//! offset level (mirroring `sphincs_plus_c::Signature::to_bytes`) for a
//! standalone `abi.encode(SHRINCS.PublicKey)` form; the composite
//! `signature::encode_stateful_envelope`/`encode_stateless_envelope` use
//! `encode_body`/`decode` directly, without that extra layer.
//!
//! Also owns the encoded stateful-public-key wire layout (`pk_seed || root ||
//! max_signatures`) and the keccak commitment binding it, together with the
//! stateless `pk_seed`/`hypertree_root`, into one `public_key_commitment`.
//! Used by `dispatch`, `signer_utils`, and `signer` so encoding/decoding and
//! commitment computation stay in one place.

use alloc::vec::Vec;

use crate::primitives::abi::{encode_bytes, encode_tuple, AbiReader, Field};
use crate::hash::{keccak_packed, word32};
use crate::primitives::profiles::PROFILE_NAME;
use crate::primitives::HASH_LEN;
use super::uxmss::{PublicKey as StatefulPublicKey, STATEFUL_PUBLIC_KEY_BYTES};

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
    /// further outer offset. Byte-identical to the historical
    /// `envelope::encode_public_key_body`. Used both by `to_bytes` (wrapped
    /// one level further, below) and directly by the composite
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
    /// decoder's responsibility. Byte-identical to the historical
    /// `envelope::decode_public_key`.
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
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).ok_or(())
    }
}

/// Mirrors `SHRINCS.decodePublicKeyCommitment`: the verifier `key` bytes are
/// exactly one 32-byte commitment word, nothing else.
pub fn decode_public_key_commitment(key: &[u8]) -> Option<[u8; HASH_LEN]> {
    if key.len() != HASH_LEN {
        return None;
    }
    key.try_into().ok()
}

pub(crate) fn public_key_commitment(
    stateful_public_key: &[u8],
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    keccak_packed(&[
        b"shrincs-public-key/",
        PROFILE_NAME.as_bytes(),
        stateful_public_key,
        pk_seed,
        hypertree_root,
    ])
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
    fn public_key_commitment_round_trips() {
        let commitment = [0x42; HASH_LEN];
        assert_eq!(decode_public_key_commitment(&commitment), Some(commitment));
    }

    #[test]
    fn public_key_commitment_wrong_length_is_rejected() {
        assert!(decode_public_key_commitment(&[0u8; 31]).is_none());
        assert!(decode_public_key_commitment(&[0u8; 33]).is_none());
    }
}
