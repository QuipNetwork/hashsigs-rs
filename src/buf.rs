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

//! Fixed-capacity hash-node buffers.
//!
//! Allocation policy: verify-path buffers whose size is a compile-time
//! profile constant live on the stack on every target, Solana included.
//! Solana's bump allocator never frees, so per-layer heap buffers would
//! accumulate against the 32 KiB program heap (8 × 2 KiB per 256s stateless
//! verify); the 2 KiB WOTS-C segment buffer fits the 4 KiB SBF stack frame
//! instead, which `cargo-build-sbf` verifies at compile time (stack-offset
//! overflows are build warnings treated as findings).

use crate::types::HASH_LEN;

pub(crate) type NodeBuf<const N: usize> = [[u8; HASH_LEN]; N];

/// Zero-initialized buffer of `N` hash nodes.
pub(crate) fn node_buf<const N: usize>() -> NodeBuf<N> {
    [[0u8; HASH_LEN]; N]
}
