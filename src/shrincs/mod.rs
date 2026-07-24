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


//! SHRINCS hybrid scheme: commitments, action hashes, dispatch.
//!
//! Wraps independent `sphincs_plus_c` (stateless) and `uxmss` (stateful).

pub(crate) mod uxmss;
mod dispatch;
/// The composed SHRINCS key: SPHINCS+C ⊕ UXMSS ⊕ commitment.
pub mod keys;
mod public_key;
mod signer_types;
mod signer_utils;

pub mod signer;
pub mod verifier;

#[cfg(test)]
mod vector_conformance;
#[cfg(test)]
pub(crate) mod test_fixtures;

pub use crate::verifier::{VerifierInterface, VerifyOutcome};
pub use keys::{Commitment, Keys};
pub use signer::{ShrincsSigner, ShrincsSignerResult, ShrincsStatefulSigner};
pub use dispatch::prepare_stateless_delegation;
pub use verifier::ShrincsVerifier;

pub use crate::primitives::hash_suite::HASH_SUITE_ID;
pub use crate::primitives::profiles::{
    FORS_C_MAX_GRIND_COUNTER, FORS_TREE_HEIGHT, HASH_TRUNC_LEN, HYPERTREE_HEIGHT,
    NUM_FORS_TREES, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, PROFILE_ID, PROFILE_NAME,
    STATELESS_SIGNATURE_LIMIT, WOTS_BASE_STATEFUL, WOTS_CHAIN_LEN, WOTS_CHAINS_STATEFUL,
    WOTS_TARGET_SUM_STATEFUL, WOTS_TARGET_SUM_STATELESS,
};
pub use crate::types::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey,
    StatefulPublicKey, StatefulSignature, StatelessSignature, WotsCSignature,
    ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, ADDRESS_TYPE_WOTS_HASH, HASH_LEN,
    HASH_SUITE_KECCAK_256, HASH_SUITE_SHA2_256, STATEFUL_PUBLIC_KEY_BYTES,
};

// Re-export commitment helpers used by wasm/tests.
#[allow(unused_imports)] // used by wasm/test modules under cfg
pub(crate) use dispatch::{
    matches_expected_public_key_commitment, valid_public_key, verify_stateful,
    verify_stateful_unsafe_raw, verify_stateless,
};
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use dispatch::verify_stateless_unsafe_raw;
#[allow(unused_imports)]
pub(crate) use public_key::{
    decode_stateful_public_key, encode_stateful_public_key, public_key_commitment,
};
#[allow(unused_imports)]
pub(crate) use signer_utils::{derive32, public_key_from_components};

#[cfg(test)]
mod profile_tests {
    #[test]
    fn active_profile_id_matches_keccak_of_profile_name() {
        let expected = crate::primitives::hash_backend::keccak256(crate::primitives::profiles::PROFILE_NAME.as_bytes());
        assert_eq!(crate::primitives::profiles::PROFILE_ID, expected);
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    #[test]
    fn active_128_profile_uses_raised_fors_grind_budget() {
        assert_eq!(crate::primitives::profiles::FORS_TREE_HEIGHT, 24);
        assert_eq!(crate::primitives::profiles::FORS_C_MAX_GRIND_COUNTER, 1 << 28);
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn active_non_128_profile_keeps_default_fors_grind_budget() {
        assert_eq!(crate::primitives::profiles::FORS_C_MAX_GRIND_COUNTER, 1 << 24);
    }
}
