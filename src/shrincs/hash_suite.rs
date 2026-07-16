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

//! Compile-time SHRINCS scheme-hash suite selection.
//!
//! This seam governs only the scheme hashes used inside FORS-C, hypertree,
//! WOTS-C, and UXMSS computations. Solidity keeps EVM-domain hashes
//! (canonical action hashes, public-key commitments, profile identity) on
//! keccak under every suite; Rust mirrors that split.

use crate::shrincs::types::HASH_LEN;

#[cfg(feature = "profile-256s-sha2")]
use crate::shrincs::types::HASH_SUITE_SHA2_256;
#[cfg(not(feature = "profile-256s-sha2"))]
use crate::shrincs::types::HASH_SUITE_KECCAK_256;

#[cfg(feature = "profile-256s-sha2")]
pub const HASH_SUITE_ID: u32 = HASH_SUITE_SHA2_256;
#[cfg(not(feature = "profile-256s-sha2"))]
pub const HASH_SUITE_ID: u32 = HASH_SUITE_KECCAK_256;

#[cfg(feature = "profile-256s-sha2")]
pub(crate) fn scheme_hash(data: &[u8]) -> [u8; HASH_LEN] {
    solana_program::hash::hash(data).to_bytes()
}

#[cfg(not(feature = "profile-256s-sha2"))]
pub(crate) fn scheme_hash(data: &[u8]) -> [u8; HASH_LEN] {
    solana_program::keccak::hash(data).to_bytes()
}
