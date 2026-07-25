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

//! Scheme-neutral building blocks shared by `sphincs_plus_c` and `shrincs`:
//! WOTS-C chain walk and grind, streaming treehash, compile-time profiles,
//! and fixed-capacity buffers. Nothing in here knows about either scheme's
//! key or envelope shapes.

// HASH_LEN is the 32-byte hash *slot* width shared by every profile: every
// hash-valued wire field is a 32-byte slot (Solidity `bytes32`) regardless of
// the parameter set. A truncated profile emits high-aligned, zero-padded node
// values inside this slot (see HASH_TRUNC_LEN and `mask_hash`).
pub const HASH_LEN: usize = 32;

pub(crate) mod abi;
pub(crate) mod buf;
pub(crate) mod profiles;
pub(crate) mod treehash;
