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
