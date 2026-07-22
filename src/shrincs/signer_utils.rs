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

//! Signer-specific helpers.
//!
//! The byte-layout primitives (hashing, packing, address words, base-w digits,
//! bit-packed digest reads) are shared with the verifier and live in
//! `components::hash`; they are re-exported here so signer call sites keep the same
//! import path. The encoded stateful public-key wire helper is owned by
//! `components::public_key` and re-exported here for compatibility. Only the
//! helpers that are genuinely signer-specific (seed KDF and public-key
//! assembly) are defined below.

// Re-export the byte-identical helpers shared with the verifier. Keeping one copy
// in `components::hash` prevents the two sides from drifting apart (F-08 / Q2).
use alloc::vec::Vec;

pub(crate) use crate::hash::hash_packed;
#[allow(unused_imports)]
pub(crate) use crate::hash::word32;

use crate::types::{PublicKey, HASH_LEN};
use super::public_key::public_key_commitment;

pub(crate) fn public_key_from_components(
    stateful_public_key: Vec<u8>,
    pk_seed: [u8; HASH_LEN],
    hypertree_root: [u8; HASH_LEN],
) -> PublicKey {
    let public_key_commitment =
        public_key_commitment(&stateful_public_key, &pk_seed, &hypertree_root);
    PublicKey {
        stateful_public_key,
        public_key_commitment: public_key_commitment.to_vec(),
        pk_seed: pk_seed.to_vec(),
        hypertree_root: hypertree_root.to_vec(),
    }
}

pub(crate) fn derive32(domain: &[u8], seed: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    // Small deterministic KDF used only inside SHRINCS key generation. Domain
    // tags separate the different seeds derived from the same master input.
    hash_packed(&[domain, seed, data])
}
