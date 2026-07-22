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

/// Keccak-256 (not NIST SHA3-256) over the concatenation of `parts`.
///
/// Hashing is vectored on both backends so no packed heap buffer is ever
/// materialized: Solana uses the `sol_keccak256` syscall's native multi-slice
/// form (`hashv`), every other target absorbs the parts incrementally.
#[inline]
pub(crate) fn keccak256v(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    #[cfg(all(
        test,
        feature = "std",
        not(feature = "parallel"),
        not(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))
    ))]
    metrics::record(parts);
    #[cfg(any(target_os = "solana", feature = "solana"))]
    {
        solana_program::keccak::hashv(parts).to_bytes()
    }
    #[cfg(not(any(target_os = "solana", feature = "solana")))]
    {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        for part in parts {
            hasher.update(part);
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Keccak-256 over a single flat slice. All non-test callers are gated on
/// `std` (`account`), so embedded (`no_std + alloc`) builds see it as dead.
#[inline]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) fn keccak256(data: &[u8]) -> [u8; HASH_LEN] {
    keccak256v(&[data])
}

/// SHA-256 over the concatenation of `parts` (scheme-hash suite for
/// `profile-256s-sha2`). Vectored like `keccak256v`.
#[inline]
#[cfg_attr(not(shrincs_hash_suite_sha2), allow(dead_code))]
pub(crate) fn sha256v(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    #[cfg(all(
        test,
        feature = "std",
        not(feature = "parallel"),
        not(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))
    ))]
    metrics::record(parts);
    #[cfg(any(target_os = "solana", feature = "solana"))]
    {
        solana_program::hash::hashv(parts).to_bytes()
    }
    #[cfg(not(any(target_os = "solana", feature = "solana")))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

/// Test-only accounting of hash-syscall shapes, used by the compute-unit
/// estimator: Solana charges each hash syscall
/// `base(85) + Σ_slices max(mem_op_base(10), byte_cost(1) * len/2)`
/// (agave `SyscallHash`), so the recorded call count and per-slice cost sum
/// reproduce the exact on-chain syscall CU floor.
///
/// Thread-local so concurrent unit tests cannot pollute each other's counts;
/// consequently the estimator only runs without the `parallel` feature (rayon
/// worker threads would record into their own counters).
#[cfg(all(
    test,
    feature = "std",
    not(feature = "parallel"),
    not(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))
))]
pub(crate) mod metrics {
    use core::cell::Cell;

    const MEM_OP_BASE_COST: u64 = 10;
    const HASH_BASE_COST: u64 = 85;

    thread_local! {
        static CALLS: Cell<u64> = const { Cell::new(0) };
        static BYTES: Cell<u64> = const { Cell::new(0) };
        static SLICE_COST: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn record(parts: &[&[u8]]) {
        CALLS.with(|calls| calls.set(calls.get() + 1));
        for part in parts {
            let len = part.len() as u64;
            BYTES.with(|bytes| bytes.set(bytes.get() + len));
            SLICE_COST.with(|cost| cost.set(cost.get() + MEM_OP_BASE_COST.max(len / 2)));
        }
    }

    /// (hash calls, total bytes hashed, Σ per-slice CU) since the last reset.
    pub(crate) fn snapshot() -> (u64, u64, u64) {
        (
            CALLS.with(Cell::get),
            BYTES.with(Cell::get),
            SLICE_COST.with(Cell::get),
        )
    }

    pub(crate) fn reset() {
        CALLS.with(|calls| calls.set(0));
        BYTES.with(|bytes| bytes.set(0));
        SLICE_COST.with(|cost| cost.set(0));
    }

    /// Exact agave syscall charge for the recorded calls.
    pub(crate) fn estimated_syscall_cu(calls: u64, slice_cost: u64) -> u64 {
        calls * HASH_BASE_COST + slice_cost
    }
}
