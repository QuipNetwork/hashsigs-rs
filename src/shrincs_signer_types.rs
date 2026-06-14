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

use super::verifier::{ParameterSetId, HASH_LEN};

/// Signer operations return `None` when inputs are outside the supported
/// production profile, stateful leaves are exhausted, or WOTS-C/FORS-C grinding
/// fails within the configured counter budget.
pub type ShrincsSignerResult<T> = Option<T>;

/// Secret material for both the stateful fast path and stateless recovery path.
///
/// These fields are deterministic derivations from seed material. Treat this as
/// private key material: anyone with these seeds can sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShrincsSigningKey {
    /// Parameter profile this secret key was generated for.
    pub parameter_set_id: ParameterSetId,
    /// Secret seed used to derive stateful WOTS-C chain secrets.
    pub stateful_sk_seed: [u8; HASH_LEN],
    /// Public seed used in stateful WOTS-C and stateful tree hashing.
    pub stateful_pk_seed: [u8; HASH_LEN],
    /// Root of the stateful unbalanced tree committed in the public key.
    pub stateful_root: [u8; HASH_LEN],
    /// Highest stateful leaf index this key may sign with.
    pub max_stateful_signatures: u32,
    /// Next monotonic stateful leaf index. Persist this after each stateful signature.
    pub next_stateful_leaf_index: u32,
    /// Secret seed used to derive FORS-C secret leaves.
    pub fors_sk_seed: [u8; HASH_LEN],
    /// Public seed used in FORS-C leaf/node hashing.
    pub fors_pk_seed: [u8; HASH_LEN],
    /// Master seed for deriving per-layer hypertree WOTS-C signing keys.
    pub hypertree_seed: [u8; HASH_LEN],
    /// Public seed used in hypertree WOTS-C and Merkle node hashing.
    pub hypertree_pk_seed: [u8; HASH_LEN],
    /// Top hypertree root committed in the public key.
    pub hypertree_root: [u8; HASH_LEN],
}
