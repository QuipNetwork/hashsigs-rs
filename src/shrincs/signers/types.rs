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

//! Signer-owned secret-key types.

use core::fmt;

use crate::shrincs::verifier::HASH_LEN;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Signer operations return `None` when stateful leaves are exhausted or
/// WOTS-C/FORS-C grinding fails within the configured counter budget.
pub type ShrincsSignerResult<T> = Option<T>;

/// Secret material for both the stateful fast path and stateless recovery path.
///
/// These fields are deterministic derivations from seed material. Treat this as
/// private key material: anyone with these seeds can sign.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ShrincsSigningKey {
    /// Secret seed used to derive stateful WOTS-C chain secrets.
    pub stateful_sk_seed: [u8; HASH_LEN],
    /// Secret PRF seed used to derive stateful WOTS-C message randomizers.
    pub stateful_prf_seed: [u8; HASH_LEN],
    /// Public seed used in stateful WOTS-C and stateful tree hashing.
    pub stateful_pk_seed: [u8; HASH_LEN],
    /// Root of the stateful unbalanced tree committed in the public key.
    pub stateful_root: [u8; HASH_LEN],
    /// Highest stateful leaf index this key may sign with.
    pub max_stateful_signatures: u32,
    /// Next monotonic stateful leaf index. Persist this after each stateful signature.
    pub next_stateful_leaf_index: u32,
    /// Stateless SK.seed-style material used to derive FORS-C and hypertree WOTS-C secrets.
    pub stateless_sk_seed: [u8; HASH_LEN],
    /// Stateless SK.prf-style material used to derive stateless message randomizers.
    pub stateless_prf_seed: [u8; HASH_LEN],
    /// Global public seed used in FORS-C, hypertree WOTS-C, and Merkle node hashing.
    pub pk_seed: [u8; HASH_LEN],
    /// Top hypertree root committed in the public key.
    pub hypertree_root: [u8; HASH_LEN],
}

impl fmt::Debug for ShrincsSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShrincsSigningKey")
            .field("stateful_sk_seed", &"<redacted>")
            .field("stateful_prf_seed", &"<redacted>")
            .field("stateful_pk_seed", &"<redacted>")
            .field("stateful_root", &"<redacted>")
            .field("max_stateful_signatures", &self.max_stateful_signatures)
            .field("next_stateful_leaf_index", &self.next_stateful_leaf_index)
            .field("stateless_sk_seed", &"<redacted>")
            .field("stateless_prf_seed", &"<redacted>")
            .field("pk_seed", &"<redacted>")
            .field("hypertree_root", &"<redacted>")
            .finish()
    }
}
