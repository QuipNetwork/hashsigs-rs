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

pub mod signer;
pub mod verifier;

pub use signer::{ShrincsSigner, ShrincsSignerResult, ShrincsSigningKey};
pub use verifier::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, ParameterSetId, ParamsView,
    PublicKey, RotationContext, RotationTarget, ShrincsVerifier, StatefulPublicKey,
    StatefulRotationTarget, StatefulSignature, StatelessSignature, WotsCSignature,
    ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, ADDRESS_TYPE_WOTS_HASH, HASH_LEN,
    HASH_SUITE_KECCAK_256, STATEFUL_PUBLIC_KEY_BYTES, WOTS_BASE_STATEFUL,
    WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};

/// Resolve the fixed SHRINCS parameter table for a supported profile.
pub fn default_params_view(parameter_set_id: ParameterSetId) -> ParamsView {
    ShrincsVerifier::default_params_view(parameter_set_id)
}
