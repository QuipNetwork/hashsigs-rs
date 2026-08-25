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

//! Keccak-256 scheme-hash suite (HASH_SUITE_ID = 1).

use crate::HASH_LEN;

/// Unused in a build that enables only sha2 profiles, which the wasm and
/// Python packages produce one of per artifact. See `Keccak256Suite`.
#[allow(dead_code)]
pub fn scheme_hash_parts(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    crate::hash::backend::keccak256v(parts)
}
