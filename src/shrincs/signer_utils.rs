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

//! Signer-specific helpers for the SHRINCS hybrid scheme.
//!
//! `hash_packed` is re-exported from the shared `crate::shrincs::hash` module so signer
//! call sites keep one import path; keeping a single copy prevents the signer
//! and verifier from drifting apart. Only the helpers that are genuinely
//! signer-specific (seed KDF and public-key assembly) are defined below.

// Re-export the byte-identical helper shared with the verifier. Keeping one copy
// in `crate::shrincs::hash` prevents the two sides from drifting apart.
use alloc::vec::Vec;

pub(crate) use crate::shrincs::hash::hash_packed;

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
