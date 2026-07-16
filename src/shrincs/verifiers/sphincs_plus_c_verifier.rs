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

//! Public stateless-only verifier surface.

use crate::shrincs::core::shrincs as core_shrincs;
#[cfg(any(test, feature = "wasm-bindings"))]
use crate::shrincs::core::sphincs_plus_c;
use crate::shrincs::types::{ActionContext, PublicKey, StatelessSignature, HASH_LEN};

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

    pub fn verify(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        context: &ActionContext,
        signature: &StatelessSignature,
    ) -> bool {
        core_shrincs::verify_stateless(
            expected_public_key_commitment,
            public_key,
            context,
            signature,
        )
    }

    #[cfg(any(test, feature = "wasm-bindings"))]
    #[allow(dead_code)]
    pub(crate) fn verify_unsafe_raw(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        public_key: &PublicKey,
        message: &[u8],
        signature: &StatelessSignature,
    ) -> bool {
        let _ = expected_public_key_commitment;
        sphincs_plus_c::verify_stateless_raw(public_key, message, signature)
    }

    pub fn action_message_hash(
        &self,
        expected_public_key_commitment: [u8; HASH_LEN],
        context: &ActionContext,
    ) -> [u8; HASH_LEN] {
        core_shrincs::stateless_action_message_hash(expected_public_key_commitment, context)
    }
}
