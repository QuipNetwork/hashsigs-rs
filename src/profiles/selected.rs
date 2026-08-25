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

//! The build-selected profile, for the surfaces that still name exactly one.
//!
//! The algorithms are generic over `P: Profile` and every profile module in
//! this directory is compiled independently. Three surfaces nevertheless still
//! name a single profile: the non-generic public facades (`ShrincsVerifier`,
//! `SphincsPlusCVerifier`, `crate::shrincs`'s re-exported parameter tuple), the
//! `wasm` bindings, and the in-crate test modules — the last of which must
//! track whichever profile the golden vectors under `vectors/` were generated
//! for. [`SelectedProfile`] is that one profile.
//!
//! Each `cfg` arm below aliases one complete profile type. The suite is never
//! chosen separately from the parameters: it comes from
//! `<SelectedProfile as Profile>::Suite`, so a profile can never be paired with
//! the wrong hash suite. (The transitional bridge this module replaces did
//! select its suite from an independent cfg, which is precisely the defect
//! this module does not reproduce.)
//!
//! TRANSITIONAL. The `shrincs_profile_*` cfgs come from `build.rs`, which still
//! permits only one profile per build. When that restriction is lifted, each of
//! the three surfaces above takes its own profile parameter and this module
//! goes away.

use crate::hash::suite::HashSuite;
use crate::profile::Profile;

/// The build-script-generated profile identity: `PROFILE_NAME` and
/// `PROFILE_ID`, the keccak256 of the name that the Solidity contracts match.
mod identity {
    include!(concat!(env!("OUT_DIR"), "/shrincs_profile_identity.rs"));
}

/// `keccak256(PROFILE_NAME)`. Wire identity, not part of the [`Profile`] trait.
pub use identity::PROFILE_ID;

#[cfg(shrincs_profile_128s_q18)]
pub use crate::profiles::p128s_q18::Profile128sQ18 as SelectedProfile;
#[cfg(shrincs_profile_128s_q20)]
pub use crate::profiles::p128s_q20::Profile128sQ20 as SelectedProfile;
#[cfg(shrincs_profile_256s)]
pub use crate::profiles::p256s::Profile256s as SelectedProfile;
#[cfg(shrincs_profile_256s_sha2)]
pub use crate::profiles::p256s_sha2::Profile256sSha2 as SelectedProfile;

/// `SelectedProfile::NUM_WOTS_CHAINS` as an array width. A plain `const`, not a
/// generic expression, so it is legal in array-length position.
pub const NUM_CHAINS: usize = <SelectedProfile as Profile>::NUM_WOTS_CHAINS as usize;

/// `SelectedProfile::NUM_HYPERTREE_LAYERS` as an array width.
pub const NUM_LAYERS: usize = <SelectedProfile as Profile>::NUM_HYPERTREE_LAYERS as usize;

/// Compile-time proof that the two width constants above agree with the trait
/// constants, in the same associated-const form the core types use.
const _: () = crate::profile::assert_widths::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>();

/// Compile-time proof that the hand-transcribed `PROFILE_NAME` on the selected
/// profile type is byte-identical to the one `build.rs` hashed into
/// `PROFILE_ID`. `PROFILE_ID` is ABI-bearing: the Solidity contracts compare
/// against it, so a typo in either copy is a wire break that no golden vector
/// would catch. `const` evaluation makes that a build failure.
const _: () = assert!(
    konst_str_eq(
        <SelectedProfile as Profile>::PROFILE_NAME,
        identity::PROFILE_NAME
    ),
    "profile type PROFILE_NAME disagrees with the build script's profile identity"
);

/// `str` equality usable in a const context on stable Rust.
const fn konst_str_eq(a: &str, b: &str) -> bool {
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

/// The scheme-hash suite id of the selected profile, for the sites that fold it
/// into a preimage or a wire field.
pub const SELECTED_HASH_SUITE_ID: u32 =
    <<SelectedProfile as Profile>::Suite as HashSuite>::HASH_SUITE_ID;
