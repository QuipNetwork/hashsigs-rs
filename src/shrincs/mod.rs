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

pub use signer::{
    CompactSignature, CompactSigningKey, ShrincsSigner, ShrincsSignerResult, ShrincsSigningKey,
};
pub use verifier::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, RotationContext,
    RotationTarget, ShrincsVerifier, StatelessSignature, WotsCSignature, ADDRESS_TYPE_FORS_TREE,
    ADDRESS_TYPE_TREE, ADDRESS_TYPE_WOTS_HASH, HASH_LEN, HASH_SUITE_KECCAK_256,
    STATELESS_SIGNATURE_LIMIT, WOTS_TARGET_SUM,
};
