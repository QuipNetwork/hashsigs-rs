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

//! Per-profile SHRINCS parameters as a trait.
//!
//! Eight of the ten varying parameters live here as associated constants.
//! The two that size fixed arrays, `NUM_WOTS_CHAINS` and
//! `NUM_HYPERTREE_LAYERS`, also appear as explicit const generic parameters on
//! the core types, because a trait associated constant cannot be an array
//! length on stable Rust. `assert_widths` makes the two copies agree at
//! compile time.
//!
//! Every value mirrors the Solidity `SHRINCSParams` library for the same
//! profile. Keep the narrow integer types: the wire encoding and the Solidity
//! parity both depend on them.

use crate::hash::suite::HashSuite;

/// One SHRINCS parameter tuple, together with its scheme hash suite.
pub trait Profile {
    /// Scheme hash suite. EVM-domain hashes stay on keccak under every
    /// profile; this governs only the scheme hashes.
    type Suite: HashSuite;

    /// Profile identity string, for example `shrincs-256s`.
    const PROFILE_NAME: &'static str;

    /// `keccak256(PROFILE_NAME)`. Wire identity: the Solidity contracts compare
    /// against this value, so it is ABI-bearing. Each profile module sets it
    /// from the build script's generated identity for that profile, never by
    /// hand, and [`str_eq`] proves the two copies of the name agree at compile
    /// time. Binding it to the profile type rather than to a build-script
    /// global is what lets two profiles coexist in one build without one of
    /// them carrying the other's id.
    const PROFILE_ID: [u8; 32];

    const HASH_TRUNC_LEN: usize;
    const STATELESS_SIGNATURE_LIMIT: u64;
    const HYPERTREE_HEIGHT: u8;
    const NUM_HYPERTREE_LAYERS: u8;
    const FORS_TREE_HEIGHT: u8;
    const NUM_FORS_TREES: u8;
    const WOTS_CHAIN_LEN: u16;
    const NUM_WOTS_CHAINS: u16;
    const FORS_C_MAX_GRIND_COUNTER: u32;
    const WOTS_TARGET_SUM: u32;
}

/// Checks that the const generic array widths agree with the profile's own
/// constants.
///
/// Being a `const fn` makes this callable in a const context; it does not by
/// itself make a mismatch fail compilation. Called from an ordinary runtime
/// path, a mismatch is only a runtime panic. To get the compile-time
/// guarantee, the caller must force const evaluation by consuming the call
/// from an associated const, for example:
///
/// ```ignore
/// const WIDTHS_AGREE: () = assert_widths::<P, NUM_CHAINS, NUM_LAYERS>();
/// ```
///
/// and then reading that associated const (`let () = Self::WIDTHS_AGREE;`)
/// from the constructor. Evaluated that way, a mismatch fails compilation
/// with `error[E0080]: evaluation panicked: ...` at monomorphisation. Every
/// core constructor must use this pattern, not a bare call.
pub const fn assert_widths<P: Profile, const NUM_CHAINS: usize, const NUM_LAYERS: usize>() {
    assert!(
        P::NUM_WOTS_CHAINS as usize == NUM_CHAINS,
        "NUM_WOTS_CHAINS const generic parameter disagrees with the profile"
    );
    assert!(
        P::NUM_HYPERTREE_LAYERS as usize == NUM_LAYERS,
        "NUM_HYPERTREE_LAYERS const generic parameter disagrees with the profile"
    );
}

/// `str` equality usable in a const context on stable Rust.
///
/// Each profile module consumes this from a `const _: () = assert!(...)` item
/// to prove its hand-transcribed [`Profile::PROFILE_NAME`] is byte-identical to
/// the name the build script hashed into that profile's `PROFILE_ID`. A typo in
/// either copy is a wire break that no golden vector would catch. As with
/// [`assert_widths`], the `const` item is what forces evaluation: a bare call
/// from a runtime path would only panic at runtime.
pub(crate) const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSuite;
    impl crate::hash::suite::HashSuite for FakeSuite {
        const HASH_SUITE_ID: u32 = 1;
        fn scheme_hash_parts(_parts: &[&[u8]]) -> [u8; crate::HASH_LEN] {
            [0u8; crate::HASH_LEN]
        }
    }

    struct FakeProfile;
    impl Profile for FakeProfile {
        type Suite = FakeSuite;
        const PROFILE_NAME: &'static str = "fake";
        const PROFILE_ID: [u8; 32] = [0u8; 32];
        const HASH_TRUNC_LEN: usize = 32;
        const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
        const HYPERTREE_HEIGHT: u8 = 64;
        const NUM_HYPERTREE_LAYERS: u8 = 8;
        const FORS_TREE_HEIGHT: u8 = 14;
        const NUM_FORS_TREES: u8 = 22;
        const WOTS_CHAIN_LEN: u16 = 16;
        const NUM_WOTS_CHAINS: u16 = 64;
        const FORS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;
        const WOTS_TARGET_SUM: u32 = 480;
    }

    #[test]
    fn trait_constants_are_readable() {
        assert_eq!(FakeProfile::NUM_WOTS_CHAINS, 64);
        assert_eq!(FakeProfile::WOTS_TARGET_SUM, 480);
        assert_eq!(<FakeProfile as Profile>::Suite::HASH_SUITE_ID, 1);
    }

    #[test]
    fn matching_widths_pass_the_check() {
        assert_widths::<FakeProfile, 64, 8>();
    }

    // Genuine compile-time assertion: forces `assert_widths` to run at const
    // evaluation, in the same const-item pattern real constructors use. If
    // the width-agreement check regressed into a runtime-only check, this
    // item would still compile whether or not the widths agree, which is
    // exactly the failure mode the runtime test above cannot catch. As
    // written, with matching widths, this item must compile; a mismatched
    // pair here would fail with `error[E0080]: evaluation panicked`.
    const _: () = assert_widths::<FakeProfile, 64, 8>();
}
