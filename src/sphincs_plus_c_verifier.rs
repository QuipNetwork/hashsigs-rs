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


//! ERC-7913-shaped independent SPHINCS+C verifier facade.
//!
//! Key = (pk_seed || hypertree_root) as two 32-byte words. Input is an arbitrary
//! 32-byte hash. No SHRINCS commitment or action envelope.

use crate::sphincs_plus_c::{self, SphincsPlusCPublicKey};
use crate::types::{StatelessSignature, HASH_LEN};

/// Independent stateless-only verifier (Solidity `SPHINCSPlusCVerifier` shape).
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

    /// `keccak256("quip.sphincsplusc-verifier.v1")`. Mirrors
    /// `SPHINCSPlusCVerifier.VERSION_TAG`: names this verifier's key/envelope
    /// format family, not the compiled parameter profile.
    pub fn version_tag() -> [u8; HASH_LEN] {
        crate::hash::keccak_packed(&[b"quip.sphincsplusc-verifier.v1"])
    }

    /// Verify a SPHINCS+C signature over a 32-byte hash.
    ///
    /// `key` is `pk_seed || hypertree_root` (exactly 64 bytes).
    pub fn verify(
        &self,
        key: &[u8],
        hash: &[u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        if key.len() != 64 {
            return false;
        }
        let Some(pk) = SphincsPlusCPublicKey::from_slices(&key[..32], &key[32..64]) else {
            return false;
        };
        sphincs_plus_c::verify_hash(&pk, hash, signature)
    }

    /// Verify with an already-decoded public key.
    pub fn verify_with_pk(
        &self,
        pk: &SphincsPlusCPublicKey,
        hash: &[u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        sphincs_plus_c::verify_hash(pk, hash, signature)
    }

    /// Verify over arbitrary message bytes (non-ERC-7913 helper).
    pub fn verify_message(
        &self,
        pk: &SphincsPlusCPublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        sphincs_plus_c::verify(pk, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_tag_matches_pinned_solidity_constant() {
        // keccak256("quip.sphincsplusc-verifier.v1"), computed independently
        // and pinned here so drift in either the literal string or the hash
        // routine fails loud instead of silently matching itself.
        const EXPECTED: [u8; HASH_LEN] = [
            0xb3, 0xee, 0x3b, 0x4a, 0x95, 0x9f, 0xcc, 0xaf, 0x76, 0xdc, 0xbb, 0x8f, 0x88, 0x7c,
            0x05, 0xff, 0xe4, 0xbd, 0x73, 0xd8, 0x80, 0x32, 0xd7, 0xe2, 0xe5, 0xfd, 0xc8, 0x3a,
            0x67, 0x17, 0x29, 0xa8,
        ];
        assert_eq!(SphincsPlusCVerifier::version_tag(), EXPECTED);
    }
}
