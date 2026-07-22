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

//! Shared SHRINCS public-key layout and commitment helpers.
//!
//! Owns the encoded stateful-public-key wire layout (`pk_seed || root ||
//! max_signatures`) and the keccak commitment binding it, together with the
//! stateless `pk_seed`/`hypertree_root`, into one `public_key_commitment`.
//! Used by `dispatch`, `signer_utils`, and `signer` so encoding/decoding and
//! commitment computation stay in one place.

use alloc::vec::Vec;

use crate::primitives::hash::{keccak_packed, word32};
use crate::primitives::profiles::PROFILE_NAME;
use crate::types::{StatefulPublicKey, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES};

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
