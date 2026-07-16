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

//! SHRINCS signer / verifier primitives and shared types.

pub(crate) mod components;
pub(crate) mod core;
pub(crate) mod profiles;
pub(crate) mod shrincs_verifier_utils;
pub(crate) mod signers;
pub(crate) mod verifiers;
mod types;
pub mod signer;
pub mod verifier;

#[cfg(test)]
mod vector_conformance;

#[cfg(test)]
mod compatibility_tests {
    use super::{signer, verifier};
    use crate::shrincs;

    #[test]
    fn root_and_module_signer_paths_still_match() {
        fn assert_result_type(_: signer::ShrincsSignerResult<()>) {}

        let _root_signer = shrincs::ShrincsSigner::keygen;
        let _module_signer = signer::ShrincsSigner::keygen;
        let _root_import = shrincs::ShrincsSigner::import_signing_key;
        let _module_import = signer::ShrincsSigner::import_signing_key;
        let _root_stateful = shrincs::ShrincsSigner::sign_stateful_raw;
        let _module_stateful = signer::ShrincsSigner::sign_stateful_raw;
        let _root_stateless = shrincs::ShrincsSigner::sign_stateless_raw;
        let _module_stateless = signer::ShrincsSigner::sign_stateless_raw;

        assert_result_type(None::<()>);
    }

    #[test]
    fn root_and_module_verifier_paths_still_match() {
        let _root_verifier = shrincs::ShrincsVerifier::new;
        let _module_verifier = verifier::ShrincsVerifier::new;
        let _root_stateless_only = shrincs::SphincsPlusCVerifier::new;
        let _module_stateless_only = verifier::SphincsPlusCVerifier::new;

        let _root_profile = shrincs::PROFILE_NAME;
        let _shim_profile = verifier::PROFILE_NAME;
        let _legacy_profile = signer::verifier::PROFILE_NAME;
    }
}

pub use signer::{ShrincsSigner, ShrincsSignerResult, ShrincsSigningKey};
pub use profiles::{
    FORS_TREE_HEIGHT, HASH_TRUNC_LEN, HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS,
    NUM_WOTS_CHAINS, PROFILE_NAME, STATELESS_SIGNATURE_LIMIT, WOTS_BASE_STATEFUL,
    WOTS_CHAIN_LEN, WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};
pub use types::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, RotationContext,
    RotationTarget, StatefulPublicKey, StatefulRotationTarget, StatefulSignature,
    StatelessSignature, WotsCSignature, ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE,
    ADDRESS_TYPE_WOTS_HASH, HASH_LEN, HASH_SUITE_KECCAK_256, STATEFUL_PUBLIC_KEY_BYTES,
};
pub use verifier::{ShrincsVerifier, SphincsPlusCVerifier};
