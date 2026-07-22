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

//! Fixed-capacity hash-node buffers: stack arrays by default, heap on Solana.
//!
//! Allocation policy: verify-path buffers whose size is a compile-time
//! profile constant live on the stack. The exception is Solana, whose SBF
//! stack frames are capped at 4 KiB — buffers that can reach ≥1 KiB there
//! (WOTS-C endpoint segments: 2 KiB at 256s) move to the 32 KiB program heap
//! instead. Buffers that stay under 1 KiB across every profile (FORS roots,
//! digest buffers) use plain arrays directly and do not come through here.

// `target_os = "solana"` is a real SBF target but not in rustc's default
// check-cfg allow-list for host builds.
#![allow(unexpected_cfgs)]

use crate::types::HASH_LEN;

#[cfg(any(target_os = "solana", feature = "solana"))]
pub(crate) type NodeBuf<const N: usize> = alloc::vec::Vec<[u8; HASH_LEN]>;
#[cfg(not(any(target_os = "solana", feature = "solana")))]
pub(crate) type NodeBuf<const N: usize> = [[u8; HASH_LEN]; N];

/// Zero-initialized buffer of `N` hash nodes.
pub(crate) fn node_buf<const N: usize>() -> NodeBuf<N> {
    #[cfg(any(target_os = "solana", feature = "solana"))]
    {
        alloc::vec![[0u8; HASH_LEN]; N]
    }
    #[cfg(not(any(target_os = "solana", feature = "solana")))]
    {
        [[0u8; HASH_LEN]; N]
    }
}
