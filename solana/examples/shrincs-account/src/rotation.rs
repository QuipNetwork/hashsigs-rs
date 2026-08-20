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

//! Key-rotation authorization: the rebuilt replacement for the deleted core
//! rotation preimage.
//!
//! `hashsigs_rs::shrincs::dispatch::{rotate_stateful_via_stateless,
//! stateless_rotate}` (deleted at `d982d45~1:src/shrincs/dispatch.rs` lines
//! 138 and 189) authorized a rotation over a *dedicated* preimage
//! (`stateful_rotation_message_hash` / `full_rotation_message_hash`) via a
//! raw-verify entry point unreachable from outside the core crate. That
//! preimage and both core methods are gone.
//!
//! This module reproduces every OTHER check those methods made --
//! reject-zero-`max_signatures`, recompute-and-compare the next commitment --
//! but replaces the authorization step with an ordinary action authorized
//! through the same PUBLIC `ShrincsVerifier::verify_stateless` every other
//! stateless action in this crate uses (see [`crate::processor::process_verify_stateless_action`]):
//! the payload is `rotate_stateful_payload`/`rotate_full_payload`
//! (`crate::messages`), tagged `ACTION_ROTATE_STATEFUL`/`ACTION_ROTATE_FULL`,
//! and verified as an [`ActionContext`] digest like any other action. A
//! signature over the deleted dedicated preimage is therefore NOT
//! byte-compatible with what this module accepts -- this is an intentional
//! wrapper-level convention (an example owns its own message-wrapping
//! choices; the core crate stays a pure, minimal-surface primitive with no
//! rotation-shaped opinions of its own).
//!
//! Both rotation flavors are authorized by the SAME signer: the CURRENT
//! installed key's stateless recovery half. `authorize_fresh_key_rotation`
//! keeps that stateless half in place (only the stateful bundle changes);
//! `authorize_full_key_rotation` may replace it too.

use hashsigs_rs::shrincs::verifier::{
    ActionContext, PublicKey, ShrincsVerifier, StatelessSignature, HASH_LEN,
    STATEFUL_PUBLIC_KEY_BYTES,
};

use crate::messages;
use crate::processor::ShrincsAccountError;
use crate::state::ShrincsAccountState;

/// Inputs shared by both rotation flavors' authorization step, bundled to
/// stay within this project's positional-argument budget (mirrors
/// [`crate::pda::LeafBitmapAccounts`]'s bundling pattern).
pub(crate) struct RotationAuthorization<'a> {
    /// Current on-chain state; supplies `nonce`/`key_version` (the action
    /// context) and `current_public_key_commitment` (what `current_public_key`
    /// must match).
    pub state: &'a ShrincsAccountState,
    /// This account's signing domain: `messages::domain_separator(program_id, account)`.
    pub domain_separator: [u8; HASH_LEN],
    /// The CURRENT installed key, decoded from the caller-supplied DTO.
    pub current_public_key: &'a PublicKey,
    /// The CURRENT key's stateless signature over this rotation's action digest.
    pub recovery_signature: &'a StatelessSignature,
}

/// Read `max_signatures` from the last 4 bytes of a 68-byte encoded stateful
/// public key (`pk_seed(32) || root(32) || max_signatures_be(4)`). Mirrors
/// the crate-private `hashsigs_rs::shrincs::key::decode_stateful_public_key`,
/// which this wrapper cannot call; the slice is exactly 4 bytes by
/// construction (`STATEFUL_PUBLIC_KEY_BYTES - 64 == 4`), so the `try_into`
/// cannot fail.
fn next_max_signatures(next_stateful_public_key: &[u8; STATEFUL_PUBLIC_KEY_BYTES]) -> u32 {
    // Direct byte construction: indices 64..68 are compile-time in-bounds for a
    // [u8; STATEFUL_PUBLIC_KEY_BYTES] (= 68), so this cannot panic and needs no
    // fallible conversion.
    u32::from_be_bytes([
        next_stateful_public_key[64],
        next_stateful_public_key[65],
        next_stateful_public_key[66],
        next_stateful_public_key[67],
    ])
}

/// Read a `Vec<u8>` public-key component (`pk_seed`/`hypertree_root`) as a
/// fixed 32-byte array. A length mismatch means the caller-supplied
/// `current_public_key` is malformed; fail the same way `verify_stateless`
/// itself fails closed on a malformed key (`ShrincsAccountError::InvalidSignature`)
/// rather than inventing a separate error for a case the public verifier
/// would reject anyway.
fn fixed_hash(component: &[u8]) -> Result<[u8; HASH_LEN], ShrincsAccountError> {
    <[u8; HASH_LEN]>::try_from(component).map_err(|_| ShrincsAccountError::InvalidSignature)
}

/// Authorize `action_type`/`payload_hash` as an ordinary action against the
/// CURRENT key's stateless half -- the shared tail of both rotation flavors'
/// authorization step (step 4 of both: build the `ActionContext` from state
/// and verify through the public `ShrincsVerifier::verify_stateless`).
fn authorize_action(
    auth: &RotationAuthorization,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
) -> Result<(), ShrincsAccountError> {
    let context: ActionContext = messages::action_context(
        auth.domain_separator,
        auth.state.nonce,
        auth.state.key_version,
        action_type,
        payload_hash,
    );
    let ok = ShrincsVerifier::new().verify_stateless(
        auth.state.current_public_key_commitment,
        auth.current_public_key,
        &context,
        auth.recovery_signature,
    );
    if ok {
        Ok(())
    } else {
        Err(ShrincsAccountError::InvalidSignature)
    }
}

/// Authorize a fresh-key (stateful-only) rotation: the next commitment binds
/// `next_stateful_public_key` to the CURRENT stateless half
/// (`current_public_key.pk_seed`/`hypertree_root`), since that half is kept
/// unchanged by this rotation flavor. On success the caller installs
/// `next_commitment` and preserves `stateless_signatures_used`.
pub(crate) fn authorize_fresh_key_rotation(
    auth: &RotationAuthorization,
    next_stateful_public_key: &[u8; STATEFUL_PUBLIC_KEY_BYTES],
    next_commitment: [u8; HASH_LEN],
) -> Result<(), ShrincsAccountError> {
    if next_max_signatures(next_stateful_public_key) == 0 {
        return Err(ShrincsAccountError::RotationTargetInvalid);
    }

    let current_pk_seed = fixed_hash(&auth.current_public_key.pk_seed)?;
    let current_hypertree_root = fixed_hash(&auth.current_public_key.hypertree_root)?;
    let computed = ShrincsVerifier::new().public_key_commitment(
        next_stateful_public_key,
        current_pk_seed,
        current_hypertree_root,
    );
    if computed != next_commitment {
        return Err(ShrincsAccountError::CommitmentMismatch);
    }

    let payload_hash =
        messages::rotate_stateful_payload(next_stateful_public_key, &next_commitment);
    authorize_action(auth, messages::ACTION_ROTATE_STATEFUL, payload_hash)
}

/// Authorize a full key rotation: the next commitment binds
/// `next_stateful_public_key` to the NEW stateless half
/// (`next_pk_seed`/`next_hypertree_root`), since this rotation flavor may
/// replace the stateless key material too. On success the caller installs
/// `next_commitment` and resets `stateless_signatures_used` only if
/// [`stateless_half_changed`] reports the stateless half actually moved.
pub(crate) fn authorize_full_key_rotation(
    auth: &RotationAuthorization,
    next_stateful_public_key: &[u8; STATEFUL_PUBLIC_KEY_BYTES],
    next_pk_seed: [u8; HASH_LEN],
    next_hypertree_root: [u8; HASH_LEN],
    next_commitment: [u8; HASH_LEN],
) -> Result<(), ShrincsAccountError> {
    if next_max_signatures(next_stateful_public_key) == 0 {
        return Err(ShrincsAccountError::RotationTargetInvalid);
    }

    let computed = ShrincsVerifier::new().public_key_commitment(
        next_stateful_public_key,
        next_pk_seed,
        next_hypertree_root,
    );
    if computed != next_commitment {
        return Err(ShrincsAccountError::CommitmentMismatch);
    }

    let payload_hash = messages::rotate_full_payload(
        next_stateful_public_key,
        &next_pk_seed,
        &next_hypertree_root,
        &next_commitment,
    );
    authorize_action(auth, messages::ACTION_ROTATE_FULL, payload_hash)
}

/// Whether a full rotation's target stateless half
/// (`next_pk_seed`/`next_hypertree_root`) differs from `current_public_key`'s
/// -- the deleted port's `stateless_key_changed` (`solana/src/account.rs`
/// prior to `5e13d35~1`, `process_rotate_full_key`, line ~789): reused to
/// decide whether `stateless_signatures_used` resets. A rotation target that
/// reuses the current stateless key material keeps the same few-time
/// stateless key, so its usage accounting must carry forward rather than
/// reset.
pub(crate) fn stateless_half_changed(
    current_public_key: &PublicKey,
    next_pk_seed: &[u8; HASH_LEN],
    next_hypertree_root: &[u8; HASH_LEN],
) -> bool {
    current_public_key.pk_seed.as_slice() != next_pk_seed.as_slice()
        || current_public_key.hypertree_root.as_slice() != next_hypertree_root.as_slice()
}
