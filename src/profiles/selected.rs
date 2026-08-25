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
//! TRANSITIONAL. Every enabled profile compiles; the single
//! `shrincs_default_profile_*` cfg from `build.rs` names only which one these
//! surfaces bind to. When each of the three surfaces above takes its own
//! profile parameter, this module goes away.

use crate::hash::suite::HashSuite;
use crate::profile::Profile;

#[cfg(shrincs_default_profile_128s_q18)]
pub use crate::profiles::p128s_q18::Profile128sQ18 as SelectedProfile;
#[cfg(shrincs_default_profile_128s_q20)]
pub use crate::profiles::p128s_q20::Profile128sQ20 as SelectedProfile;
#[cfg(shrincs_default_profile_256s)]
pub use crate::profiles::p256s::Profile256s as SelectedProfile;
#[cfg(shrincs_default_profile_256s_sha2)]
pub use crate::profiles::p256s_sha2::Profile256sSha2 as SelectedProfile;

/// `keccak256(PROFILE_NAME)` for the selected profile. Taken from the profile
/// type, so it cannot drift to another profile's id in a multi-profile build.
pub const PROFILE_ID: [u8; 32] = <SelectedProfile as Profile>::PROFILE_ID;

/// `SelectedProfile::NUM_WOTS_CHAINS` as an array width. A plain `const`, not a
/// generic expression, so it is legal in array-length position.
pub const NUM_CHAINS: usize = <SelectedProfile as Profile>::NUM_WOTS_CHAINS as usize;

/// `SelectedProfile::NUM_HYPERTREE_LAYERS` as an array width.
pub const NUM_LAYERS: usize = <SelectedProfile as Profile>::NUM_HYPERTREE_LAYERS as usize;

// NUM_CHAINS and NUM_LAYERS above are defined directly from
// `<SelectedProfile as Profile>::NUM_WOTS_CHAINS`/`NUM_HYPERTREE_LAYERS`, so
// they cannot disagree with those trait constants by construction -- an
// `assert_widths` check against them here would compare a value to itself
// and could never fail. The real drift risk is each profile module's own
// alias, which repeats the widths as independent literals
// (`pub type Shrincs = ShrincsCore<P, N, M>`); that is guarded per profile,
// beside each alias, in `src/profiles/p*.rs`.
//
// The `PROFILE_NAME`/`PROFILE_ID` agreement guard now lives per profile, in
// each profile module, so it covers every compiled profile rather than only the
// selected one.

/// The scheme-hash suite id of the selected profile, for the sites that fold it
/// into a preimage or a wire field.
pub const SELECTED_HASH_SUITE_ID: u32 =
    <<SelectedProfile as Profile>::Suite as HashSuite>::HASH_SUITE_ID;
