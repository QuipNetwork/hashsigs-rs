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
//! import path. Only the helpers that are genuinely signer-specific (seed KDF,
//! public-key assembly, encoded stateful key layout) are defined below.

// Re-export the byte-identical helpers shared with the verifier. Keeping one copy
// in `components::hash` prevents the two sides from drifting apart (F-08 / Q2).
pub(crate) use super::super::components::hash::{
    base_w16_digit, base_w_digit, hash_node, hash_packed, word32, wots_digest_bytes,
};

use super::super::types::{PublicKey, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES};
use super::super::profiles::PROFILE_NAME;

pub(crate) const WOTS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
pub(crate) const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;

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

pub(crate) fn public_key_commitment(
    stateful_public_key: &[u8],
    pk_seed: &[u8; HASH_LEN],
    hypertree_root: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // The commitment tag binds the compile-time profile id (F-08 / Q2), so a
    // public key from one profile can never collide with another's: the
    // preimage is `shrincs-public-key/<PROFILE_NAME>`, sourced from the profile
    // machinery rather than a scattered literal.
    hash_packed(&[
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
    // Keep this byte layout identical to `decode_stateful_public_key`:
    // pk_seed || root || max_signatures as big-endian u32.
    let mut out = Vec::with_capacity(STATEFUL_PUBLIC_KEY_BYTES);
    out.extend_from_slice(&pk_seed);
    out.extend_from_slice(&root);
    out.extend_from_slice(&max_signatures.to_be_bytes());
    out
}

pub(crate) fn derive32(domain: &[u8], seed: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    // Small deterministic KDF used only inside SHRINCS key generation. Domain
    // tags separate the different seeds derived from the same master input.
    hash_packed(&[domain, seed, data])
}
