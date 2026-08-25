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
//!
//! The suite is never selected on its own: it is `<P as Profile>::Suite`, an
//! associated type of the profile, so a profile can never be paired with the
//! wrong suite and two profiles with different suites coexist in one build.

pub const HASH_SUITE_KECCAK_256: u32 = 1;
pub const HASH_SUITE_SHA2_256: u32 = 2;

mod keccak;
mod sha2;

/// A scheme hash suite. Selected per profile as `Profile::Suite`, not by a
/// global cfg, so that profiles using different suites coexist in one build.
// Not yet consumed outside tests: `src/hash/ops.rs` starts reading this
// through `Profile::Suite` in Task 3.
#[allow(dead_code)]
pub trait HashSuite {
    /// Wire identifier for this suite. An ABI value: never renumber it.
    const HASH_SUITE_ID: u32;

    /// Hash the concatenation of `parts` under this suite.
    fn scheme_hash_parts(parts: &[&[u8]]) -> [u8; crate::HASH_LEN];
}

/// Keccak-256 scheme hashes. The default under every profile except
/// `shrincs-256s-sha2`.
#[allow(dead_code)]
pub struct Keccak256Suite;

impl HashSuite for Keccak256Suite {
    const HASH_SUITE_ID: u32 = HASH_SUITE_KECCAK_256;

    fn scheme_hash_parts(parts: &[&[u8]]) -> [u8; crate::HASH_LEN] {
        keccak::scheme_hash_parts(parts)
    }
}

/// SHA2-256 scheme hashes, used by `shrincs-256s-sha2`.
#[allow(dead_code)]
pub struct Sha2256Suite;

impl HashSuite for Sha2256Suite {
    const HASH_SUITE_ID: u32 = HASH_SUITE_SHA2_256;

    fn scheme_hash_parts(parts: &[&[u8]]) -> [u8; crate::HASH_LEN] {
        sha2::scheme_hash_parts(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suites_have_distinct_ids() {
        assert_eq!(Keccak256Suite::HASH_SUITE_ID, HASH_SUITE_KECCAK_256);
        assert_eq!(Sha2256Suite::HASH_SUITE_ID, HASH_SUITE_SHA2_256);
    }

    #[test]
    fn both_suites_compile_together_and_differ() {
        let parts: &[&[u8]] = &[b"shrincs", b"suite"];
        let k = Keccak256Suite::scheme_hash_parts(parts);
        let s = Sha2256Suite::scheme_hash_parts(parts);
        assert_ne!(k, s, "keccak and sha2 must not agree on the same input");
    }
}
