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

//! One module per SHRINCS profile. The features are additive: enabling two
//! profiles compiles two instantiations, which is the point of this design.
//!
//! `profile-256s` is also implied by the `default-profile-256s` default
//! feature, so the default profile and its `crate::Shrincs` alias exist in a
//! plain `cargo build`.

#[cfg(feature = "profile-128s-q18")]
pub mod p128s_q18;
#[cfg(feature = "profile-128s-q20")]
pub mod p128s_q20;
#[cfg(any(feature = "profile-256s", feature = "default-profile-256s"))]
pub mod p256s;
#[cfg(feature = "profile-256s-sha2")]
pub mod p256s_sha2;

// The build-selected profile, for the surfaces that still name exactly one.
// Transitional; see the module docs.
#[doc(hidden)]
pub mod selected;

#[cfg(all(
    test,
    feature = "profile-256s",
    feature = "profile-256s-sha2",
    feature = "profile-128s-q18",
    feature = "profile-128s-q20"
))]
mod tests {
    use crate::profile::Profile;

    #[test]
    fn every_profile_keeps_its_documented_values() {
        use crate::profiles::p128s_q18::Profile128sQ18;
        use crate::profiles::p128s_q20::Profile128sQ20;
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        assert_eq!(Profile256s::NUM_WOTS_CHAINS, 64);
        assert_eq!(Profile256s::NUM_HYPERTREE_LAYERS, 8);
        assert_eq!(Profile256s::FORS_TREE_HEIGHT, 14);
        assert_eq!(Profile256s::STATELESS_SIGNATURE_LIMIT, 1_048_576);
        assert_eq!(Profile256s::WOTS_TARGET_SUM, 480);

        assert_eq!(Profile128sQ18::NUM_WOTS_CHAINS, 32);
        assert_eq!(Profile128sQ18::STATELESS_SIGNATURE_LIMIT, 262_144);
        assert_eq!(Profile128sQ20::STATELESS_SIGNATURE_LIMIT, 1_048_576);
        assert_eq!(Profile128sQ18::FORS_C_MAX_GRIND_COUNTER, 1 << 28);

        assert_eq!(Profile256sSha2::NUM_WOTS_CHAINS, 64);
        assert_eq!(Profile256sSha2::HASH_TRUNC_LEN, 32);
    }
}

// The acceptance criterion for the whole plan: two profiles that differ only
// by scheme hash suite, instantiated in the same build. Gated on the pair
// rather than on all four features, because `build.rs` still rejects more than
// one explicit profile feature per build — `--features profile-256s-sha2`
// leaves the default `default-profile-256s` on, so this pair does compile
// together today and the test actually runs.
#[cfg(all(
    test,
    feature = "profile-256s-sha2",
    any(feature = "profile-256s", feature = "default-profile-256s")
))]
mod coexistence_tests {
    use crate::profile::Profile;

    #[test]
    fn profiles_that_differ_only_by_suite_coexist() {
        use crate::hash::suite::HashSuite;
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        assert_ne!(
            <Profile256s as Profile>::Suite::HASH_SUITE_ID,
            <Profile256sSha2 as Profile>::Suite::HASH_SUITE_ID
        );
        assert_eq!(
            Profile256s::NUM_WOTS_CHAINS,
            Profile256sSha2::NUM_WOTS_CHAINS
        );
    }
}
