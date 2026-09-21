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
//! `profile-256s` is in the crate's `default` feature list, so the default
//! profile and its `crate::Shrincs` alias exist in a plain `cargo build`.

/// Build-script-generated profile identity, one `pub mod` per profile, each
/// holding that profile's `PROFILE_NAME` and `PROFILE_ID`
/// (`keccak256(PROFILE_NAME)`). Every profile is generated regardless of which
/// features are on, so the unused ones are dead code by construction.
#[allow(dead_code)]
pub(crate) mod identity {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identities.rs"));
}

#[cfg(feature = "experimental-profile-128s-q18")]
pub mod p128s_q18;
#[cfg(feature = "experimental-profile-128s-q18-sha2")]
pub mod p128s_q18_sha2;
#[cfg(feature = "experimental-profile-128s-q20")]
pub mod p128s_q20;
#[cfg(feature = "experimental-profile-128s-q20-sha2")]
pub mod p128s_q20_sha2;
#[cfg(feature = "profile-256s")]
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
    feature = "experimental-profile-128s-q18",
    feature = "experimental-profile-128s-q20",
    feature = "experimental-profile-128s-q18-sha2",
    feature = "experimental-profile-128s-q20-sha2"
))]
mod tests {
    use crate::profile::Profile;

    #[test]
    fn every_profile_keeps_its_documented_values() {
        use crate::profiles::p128s_q18::Profile128sQ18;
        use crate::profiles::p128s_q18_sha2::Profile128sQ18Sha2;
        use crate::profiles::p128s_q20::Profile128sQ20;
        use crate::profiles::p128s_q20_sha2::Profile128sQ20Sha2;
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

        assert_eq!(Profile128sQ18Sha2::NUM_WOTS_CHAINS, 32);
        assert_eq!(Profile128sQ18Sha2::HASH_TRUNC_LEN, 16);
        assert_eq!(Profile128sQ18Sha2::STATELESS_SIGNATURE_LIMIT, 262_144);
        assert_eq!(Profile128sQ18Sha2::FORS_C_MAX_GRIND_COUNTER, 1 << 28);
        assert_eq!(Profile128sQ20Sha2::STATELESS_SIGNATURE_LIMIT, 1_048_576);
    }

    /// Each `*-sha2` profile is the exact numeric twin of its keccak profile.
    ///
    /// The assertions above pin a few values per profile by hand; this pins
    /// every numeric parameter of a twin pair against the other member, which
    /// is the property the sha2 profiles are defined by. A transcription slip
    /// in one constant compiles clean and changes the bytes the profile
    /// produces, so nothing else in the crate would catch it.
    #[test]
    fn every_sha2_profile_is_the_numeric_twin_of_its_keccak_profile() {
        use crate::profiles::p128s_q18::Profile128sQ18;
        use crate::profiles::p128s_q18_sha2::Profile128sQ18Sha2;
        use crate::profiles::p128s_q20::Profile128sQ20;
        use crate::profiles::p128s_q20_sha2::Profile128sQ20Sha2;
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        /// Every numeric parameter a profile declares, in declaration order, as
        /// one comparable tuple, so a twin pair is checked in a single
        /// assertion rather than one constant at a time.
        #[allow(clippy::type_complexity)]
        fn params<P: Profile>() -> (usize, u64, u8, u8, u8, u8, u16, u16, u32, u32) {
            (
                P::HASH_TRUNC_LEN,
                P::STATELESS_SIGNATURE_LIMIT,
                P::HYPERTREE_HEIGHT,
                P::NUM_HYPERTREE_LAYERS,
                P::FORS_TREE_HEIGHT,
                P::NUM_FORS_TREES,
                P::WOTS_CHAIN_LEN,
                P::NUM_WOTS_CHAINS,
                P::FORS_C_MAX_GRIND_COUNTER,
                P::WOTS_TARGET_SUM,
            )
        }

        assert_eq!(params::<Profile256sSha2>(), params::<Profile256s>());
        assert_eq!(params::<Profile128sQ18Sha2>(), params::<Profile128sQ18>());
        assert_eq!(params::<Profile128sQ20Sha2>(), params::<Profile128sQ20>());
    }

    /// Every compiled profile's identity and suite, not only the selected one.
    ///
    /// The per-module guards run against whichever profile the build binds to,
    /// so a non-selected profile could carry another profile's `PROFILE_ID` or
    /// hash suite and still build clean and pass every other test. `PROFILE_ID`
    /// is the value the Solidity contracts compare against, and the suite
    /// decides the scheme hash, so both are ABI-bearing for a consumer that
    /// pins a non-default profile.
    #[test]
    fn every_profile_owns_its_identity_and_suite() {
        use crate::hash::backend::keccak256;
        use crate::hash::suite::{HashSuite, HASH_SUITE_KECCAK_256, HASH_SUITE_SHA2_256};
        use crate::profiles::p128s_q18::Profile128sQ18;
        use crate::profiles::p128s_q18_sha2::Profile128sQ18Sha2;
        use crate::profiles::p128s_q20::Profile128sQ20;
        use crate::profiles::p128s_q20_sha2::Profile128sQ20Sha2;
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        fn check<P: Profile>(name: &str, suite_id: u32) {
            assert_eq!(P::PROFILE_NAME, name, "PROFILE_NAME");
            assert_eq!(
                P::PROFILE_ID,
                keccak256(name.as_bytes()),
                "PROFILE_ID is not keccak256({name})"
            );
            assert_eq!(
                <P::Suite as HashSuite>::HASH_SUITE_ID,
                suite_id,
                "hash suite for {name}"
            );
        }

        check::<Profile256s>("shrincs-256s-keccak", HASH_SUITE_KECCAK_256);
        check::<Profile256sSha2>("shrincs-256s-sha2", HASH_SUITE_SHA2_256);
        check::<Profile128sQ18>("shrincs-128s-q18-keccak", HASH_SUITE_KECCAK_256);
        check::<Profile128sQ20>("shrincs-128s-q20-keccak", HASH_SUITE_KECCAK_256);
        check::<Profile128sQ18Sha2>("shrincs-128s-q18-sha2", HASH_SUITE_SHA2_256);
        check::<Profile128sQ20Sha2>("shrincs-128s-q20-sha2", HASH_SUITE_SHA2_256);
    }

    /// Each profile module's public alias must name its OWN profile type.
    ///
    /// `WIDTHS_AGREE` compares widths, and the profiles group by width (256s
    /// with 256s-sha2 at 64/8; q18, q20 and both their sha2 twins at 32/1), so
    /// any member of a group can be substituted into another's alias without
    /// any width guard firing. This pins the type parameter itself.
    #[test]
    fn every_alias_names_its_own_profile() {
        use crate::profiles::p128s_q18::Profile128sQ18;
        use crate::profiles::p128s_q18_sha2::Profile128sQ18Sha2;
        use crate::profiles::p128s_q20::Profile128sQ20;
        use crate::profiles::p128s_q20_sha2::Profile128sQ20Sha2;
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        fn name_of<P: Profile, const C: usize, const L: usize>(
            _: core::marker::PhantomData<crate::shrincs::ShrincsCore<P, C, L>>,
        ) -> &'static str {
            P::PROFILE_NAME
        }
        use core::marker::PhantomData as Pd;

        assert_eq!(
            name_of(Pd::<crate::profiles::p256s::Shrincs>),
            Profile256s::PROFILE_NAME
        );
        assert_eq!(
            name_of(Pd::<crate::profiles::p256s_sha2::Shrincs>),
            Profile256sSha2::PROFILE_NAME
        );
        assert_eq!(
            name_of(Pd::<crate::profiles::p128s_q18::Shrincs>),
            Profile128sQ18::PROFILE_NAME
        );
        assert_eq!(
            name_of(Pd::<crate::profiles::p128s_q20::Shrincs>),
            Profile128sQ20::PROFILE_NAME
        );
        assert_eq!(
            name_of(Pd::<crate::profiles::p128s_q18_sha2::Shrincs>),
            Profile128sQ18Sha2::PROFILE_NAME
        );
        assert_eq!(
            name_of(Pd::<crate::profiles::p128s_q20_sha2::Shrincs>),
            Profile128sQ20Sha2::PROFILE_NAME
        );
    }
}

// The acceptance criterion for the whole plan: two profiles that differ only
// by scheme hash suite, instantiated in the same build. Gated on the pair
// rather than on all four features so it still runs under
// `--features profile-256s-sha2`, which leaves the default `profile-256s` on.
#[cfg(all(test, feature = "profile-256s-sha2", feature = "profile-256s"))]
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
