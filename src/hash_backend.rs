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

//! Portable vs Solana-syscall hash backend.
//!
//! On `target_os = "solana"` (or with the `solana` feature) this routes through
//! `solana_program` so SBF builds use the cheap keccak/sha256 syscalls. Every
//! other target uses the pure-Rust `sha3` / `sha2` crates. Off-chain,
//! `solana_program`'s hashers already fall back to those same algorithms, so
//! outputs are expected to be byte-identical (proven by golden vectors).

// `target_os = "solana"` is a real SBF target but not in rustc's default
// check-cfg allow-list for host builds.
#![allow(unexpected_cfgs)]

use crate::types::HASH_LEN;

/// Keccak-256 (not NIST SHA3-256).
#[inline]
pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    #[cfg(any(target_os = "solana", feature = "solana"))]
    {
        solana_program::keccak::hash(data).to_bytes()
    }
    #[cfg(not(any(target_os = "solana", feature = "solana")))]
    {
        use sha3::{Digest, Keccak256};
        let digest = Keccak256::digest(data);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&digest);
        out
    }
}

/// SHA-256 (scheme-hash suite for `profile-256s-sha2`).
#[inline]
#[cfg_attr(not(shrincs_hash_suite_sha2), allow(dead_code))]
pub(crate) fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    #[cfg(any(target_os = "solana", feature = "solana"))]
    {
        solana_program::hash::hash(data).to_bytes()
    }
    #[cfg(not(any(target_os = "solana", feature = "solana")))]
    {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(data);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&digest);
        out
    }
}
