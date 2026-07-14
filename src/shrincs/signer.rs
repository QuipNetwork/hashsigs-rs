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

//! Public SHRINCS key generation and signing facade.
//!
//! - `shrincs_signer_fors_c` opens the fixed FORS forest for a message digest.
//! - `shrincs_signer_hypertree` carries the FORS root to the hypertree root.

pub(crate) use super::verifier;

#[path = "shrincs_signer_compact.rs"]
mod shrincs_signer_compact;
#[path = "shrincs_signer_fors_c.rs"]
mod shrincs_signer_fors_c;
#[path = "shrincs_signer_hypertree.rs"]
mod shrincs_signer_hypertree;
#[path = "shrincs_signer_types.rs"]
mod shrincs_signer_types;
#[path = "shrincs_signer_utils.rs"]
mod shrincs_signer_utils;

pub use self::shrincs_signer_types::{
    CompactSignature, CompactSigningKey, ShrincsSignerResult, ShrincsSigningKey,
};

use self::shrincs_signer_compact::{
    compact_keygen as compact_keygen_inner, sign_compact_raw as sign_compact_raw_inner,
};
use self::shrincs_signer_fors_c::sign_fors_c;
use self::shrincs_signer_hypertree::{hypertree_public_root, sign_hypertree};
use self::shrincs_signer_utils::{derive32, public_key_from_components};
use self::verifier::{ActionContext, PublicKey, ShrincsVerifier, StatelessSignature, HASH_LEN};

pub struct ShrincsSigner;

impl ShrincsSigner {
    /// Deterministically derive signing material and a public key from seed material.
    ///
    /// The public key contains the stateless `PK.seed` and hypertree `PK.root`.
    /// The message-specific FORS root is derived during signing and authenticated
    /// by the hypertree.
    pub fn keygen(seed_material: &[u8]) -> ShrincsSignerResult<(ShrincsSigningKey, PublicKey)> {
        let stateless_sk_seed = derive32(b"shrincs-stateless-sk-seed", seed_material, &[]);
        let stateless_prf_seed = derive32(b"shrincs-stateless-prf-seed", seed_material, &[]);
        let pk_seed = derive32(b"shrincs-pk-seed", seed_material, &[]);
        let hypertree_root = hypertree_public_root(&stateless_sk_seed, &pk_seed);

        let signing_key = ShrincsSigningKey {
            stateless_sk_seed,
            stateless_prf_seed,
            pk_seed,
            hypertree_root,
        };
        let public_key = public_key_from_components(pk_seed, hypertree_root);

        Some((signing_key, public_key))
    }

    /// Sign raw bytes with FORS-C plus the hypertree.
    ///
    /// The signature verifies under the long-lived public key returned by
    /// `keygen`; the message-specific FORS root is carried only inside the
    /// signature/hypertree flow.
    pub fn sign_stateless_raw(
        signing_key: &ShrincsSigningKey,
        message: &[u8],
    ) -> ShrincsSignerResult<StatelessSignature> {
        let signed_fors = sign_fors_c(signing_key, message)?;
        let hypertree = sign_hypertree(
            signing_key,
            signed_fors.root,
            signed_fors.tree_index,
            signed_fors.leaf_index,
        )?;
        Some(StatelessSignature {
            fors: signed_fors.signature,
            hypertree,
        })
    }

    /// Derive one JARDIN-style compact slot from master secret and device r.
    pub fn compact_keygen(
        master_sk_seed: &[u8; HASH_LEN],
        slot_randomness: &[u8; HASH_LEN],
        q: u8,
    ) -> ShrincsSignerResult<CompactSigningKey> {
        compact_keygen_inner(master_sk_seed, slot_randomness, q)
    }

    /// Sign an already-built 32-byte compact Type 2 message hash.
    pub fn sign_compact_raw(
        signing_key: &CompactSigningKey,
        message: &[u8],
    ) -> ShrincsSignerResult<CompactSignature> {
        sign_compact_raw_inner(signing_key, message)
    }

    /// Sign a canonical compact account action.
    pub fn sign_compact_action(
        signing_key: &CompactSigningKey,
        context: &ActionContext,
    ) -> ShrincsSignerResult<CompactSignature> {
        let message = Self::compact_action_message_hash(context);
        sign_compact_raw_inner(signing_key, &message)
    }

    /// Build the canonical compact Type 2 account-action message hash.
    pub fn compact_action_message_hash(context: &ActionContext) -> [u8; HASH_LEN] {
        ShrincsVerifier::new().compact_action_message_hash(context)
    }

    /// Build the compact slot id registered by the account wrapper.
    pub fn compact_slot_id(
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        ShrincsVerifier::new().compact_slot_id(sub_pk_seed, sub_pk_root)
    }

    /// Build the stateless authorization hash for compact slot registration.
    pub fn compact_slot_registration_message_hash(
        context: &verifier::RotationContext,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        ShrincsVerifier::new().compact_slot_registration_message_hash(
            context,
            sub_pk_seed,
            sub_pk_root,
        )
    }

    /// Build the stateless authorization hash for compact slot revocation.
    pub fn compact_slot_revocation_message_hash(
        context: &verifier::RotationContext,
        sub_pk_seed: &[u8; HASH_LEN],
        sub_pk_root: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        ShrincsVerifier::new().compact_slot_revocation_message_hash(
            context,
            sub_pk_seed,
            sub_pk_root,
        )
    }
}
