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


//! SHA-256 scheme-hash suite (HASH_SUITE_ID = 2).

use crate::types::HASH_LEN;
use crate::types::HASH_SUITE_SHA2_256;

pub const HASH_SUITE_ID: u32 = HASH_SUITE_SHA2_256;

pub fn scheme_hash(data: &[u8]) -> [u8; HASH_LEN] {
    solana_program::hash::hash(data).to_bytes()
}
