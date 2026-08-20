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

mod action_context;
mod dispatch;
/// The composed SHRINCS key (SPHINCS+C ⊕ UXMSS ⊕ commitment), the public-key
/// wire type, and the [`key::Commitment`].
///
/// `pub` because `Keys` and `PublicKey` are part of the crate's public
/// wire-type surface: the `tests/` integration suite and the `solana`
/// workspace member reconstruct them from their DTOs at the canonical path
/// `crate::shrincs::key::{Keys, PublicKey}` (also re-exported as
/// `crate::shrincs::{Keys, PublicKey}`). Consolidated from the former `keys` +
/// `public_key` modules to mirror `sphincs_plus_c::key`.
pub mod key;
/// The primary SHRINCS signature (the stateful UXMSS fast-path signature),
/// its ABI codec, and the composite envelope codecs.
///
/// `pub` (rather than `pub(crate)`) for the same reason as `public_key`
/// above: `Signature` is part of the crate's public wire-type surface,
/// canonically `crate::shrincs::signature::Signature` (also re-exported as
/// `crate::shrincs::Signature`).
pub mod signature;
pub(crate) mod uxmss;

pub mod signer;
pub mod verifier;

#[cfg(test)]
pub(crate) mod test_fixtures;
#[cfg(test)]
mod vector_conformance;

pub use crate::verifier::{VerifierInterface, VerifyOutcome};
pub use dispatch::prepare_stateless_delegation;
pub use key::{Commitment, Keys};
pub use signer::{sign, ShrincsSigner, ShrincsSignerResult};
pub use verifier::{ShrincsVerifier, ShrincsVerifierExt};

pub use crate::hash::suite::HASH_SUITE_ID;
pub use crate::hash::suite::{HASH_SUITE_KECCAK_256, HASH_SUITE_SHA2_256};
pub use crate::hash::{ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, ADDRESS_TYPE_WOTS_HASH};
pub use crate::profiles::{
    FORS_C_MAX_GRIND_COUNTER, FORS_TREE_HEIGHT, HASH_TRUNC_LEN, HYPERTREE_HEIGHT, NUM_FORS_TREES,
    NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS, PROFILE_ID, PROFILE_NAME, STATELESS_SIGNATURE_LIMIT,
    WOTS_CHAIN_LEN,
};
pub use crate::HASH_LEN;
pub use action_context::ActionContext;
pub use key::PublicKey;
pub use signature::{
    decode_stateful_envelope, decode_stateless_envelope, encode_stateful_envelope,
    encode_stateless_envelope, Signature,
};
pub use uxmss::STATEFUL_PUBLIC_KEY_BYTES;
// SHRINCS genuinely has a stateless signing path (SPHINCS+C is the stateless
// half of the hybrid key), so this is a legitimate semantic re-export, not a
// component shim: `shrincs::StatelessSignature` names that path's wire type
// at its canonical home, `sphincs_plus_c::Signature`.
pub use crate::sphincs_plus_c::Signature as StatelessSignature;

// Re-export commitment helpers used by wasm/tests. Each re-export is consumed
// only by the wasm-bindings and/or test modules under `cfg`, so it is unused
// in a plain library build — hence the per-item `unused_imports` allows.
#[allow(unused_imports)] // consumed by test_support/wasm under cfg
pub(crate) use crate::hash::derive32;
#[allow(unused_imports)] // consumed by dispatch tests under cfg(test)
#[cfg(test)]
pub(crate) use dispatch::verify_stateless_unsafe_raw;
#[allow(unused_imports)] // used by wasm/test modules under cfg
pub(crate) use dispatch::{
    matches_expected_public_key_commitment, valid_public_key, verify_stateful,
    verify_stateful_unsafe_raw, verify_stateless,
};
#[allow(unused_imports)] // consumed by wasm/test modules under cfg
pub(crate) use key::{decode_stateful_public_key, encode_stateful_public_key};
#[allow(unused_imports)] // consumed by wasm/test modules under cfg
pub(crate) use signer::public_key_from_components;

#[cfg(test)]
mod profile_tests {
    #[test]
    fn active_profile_id_matches_keccak_of_profile_name() {
        let expected = crate::hash::backend::keccak256(crate::profiles::PROFILE_NAME.as_bytes());
        assert_eq!(crate::profiles::PROFILE_ID, expected);
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    #[test]
    fn active_128_profile_uses_raised_fors_grind_budget() {
        assert_eq!(crate::profiles::FORS_TREE_HEIGHT, 24);
        assert_eq!(crate::profiles::FORS_C_MAX_GRIND_COUNTER, 1 << 28);
    }

    #[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
    #[test]
    fn active_non_128_profile_keeps_default_fors_grind_budget() {
        assert_eq!(crate::profiles::FORS_C_MAX_GRIND_COUNTER, 1 << 24);
    }
}
