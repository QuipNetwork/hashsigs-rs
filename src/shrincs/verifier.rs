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

//! Compatibility verifier entrypoint.
//!
//! Public verifier surfaces now live under `shrincs::verifiers::*`. This module
//! preserves the frozen `hashsigs_rs::shrincs::verifier::*` path by re-exporting
//! the same types and constants.

pub use super::hash_suite::HASH_SUITE_ID;
pub use super::profiles::{
    FORS_TREE_HEIGHT, HASH_TRUNC_LEN, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
    NUM_WOTS_CHAINS, PROFILE_ID, PROFILE_NAME, STATELESS_SIGNATURE_LIMIT, WOTS_BASE_STATEFUL,
    WOTS_CHAIN_LEN, WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
    WOTS_TARGET_SUM_STATELESS,
};
pub use super::types::*;
pub use super::verifiers::shrincs_verifier::ShrincsVerifier;
pub use super::verifiers::sphincs_plus_c_verifier::SphincsPlusCVerifier;
