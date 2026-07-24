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

//! Message construction for SHRINCS account actions.
//!
//! Builds the [`ActionContext`] that `ShrincsVerifier::verify_stateful` /
//! `verify_stateless` (`hashsigs_rs::shrincs::verifier`) consume. The domain
//! separator and action-payload hashing are ported from the deleted Solana
//! account program (`solana/src/account.rs` prior to its removal at
//! `5e13d35~1`), which built:
//!
//! ```text
//! domain_separator = keccak256(keccak256("shrincs-account-v1") || program_id || account_pubkey)
//! ```
//!
//! i.e. the deployed *program id* stands in for Solidity's `chainid` and the
//! PDA's own pubkey stands in for `address(this)`; see that module's
//! "Domain separator" doc comment for the mapping rationale.
//!
//! Rotation is modeled here as an ordinary action rather than a distinct
//! signature-verification path: `ACTION_ROTATE_STATEFUL` / `ACTION_ROTATE_FULL`
//! select the payload shape (see [`rotate_stateful_payload`] /
//! [`rotate_full_payload`]), and callers feed the resulting [`ActionContext`]
//! into the same `verify_stateful`/`verify_stateless` every other action uses.
//! There is no rotation-specific preimage or raw-verify entry point.

use hashsigs_rs::shrincs::verifier::{ActionContext, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES};
use solana_program::keccak::hashv;
use solana_program::pubkey::Pubkey;

/// Stable domain tag for this wrapper family: `keccak256(b"shrincs-account-v1")`.
pub const DOMAIN_TAG: [u8; HASH_LEN] = [
    0x2e, 0x88, 0x46, 0x80, 0x14, 0xd6, 0x98, 0xa3, 0x09, 0x4d, 0x3f, 0x8d, 0xec, 0xa0, 0x02, 0x3e,
    0xaa, 0x1b, 0x68, 0x71, 0xe9, 0x34, 0x16, 0x9e, 0x10, 0x4e, 0xaf, 0x24, 0xee, 0x50, 0xe0, 0x00,
];

/// Action-type tag for a stateful-signature action:
/// `keccak256(b"shrincs-account-example/stateful-action")`.
pub const ACTION_STATEFUL: [u8; HASH_LEN] = [
    0x45, 0x00, 0xb6, 0x1a, 0x34, 0x6f, 0x0e, 0x89, 0xd0, 0xdc, 0x3b, 0xe9, 0x06, 0x34, 0xba, 0x83,
    0x3e, 0xeb, 0x99, 0x19, 0x16, 0x77, 0x7b, 0x69, 0x0b, 0x7a, 0x24, 0xd5, 0xa5, 0xc1, 0x0a, 0x94,
];

/// Action-type tag for a stateless-signature action:
/// `keccak256(b"shrincs-account-example/stateless-action")`.
pub const ACTION_STATELESS: [u8; HASH_LEN] = [
    0x90, 0x72, 0x7a, 0x05, 0x2a, 0x33, 0x58, 0x21, 0x5e, 0xb0, 0x33, 0xa4, 0x95, 0x22, 0x9e, 0x52,
    0x05, 0x25, 0xb3, 0x61, 0x6b, 0x39, 0xfd, 0x78, 0x6e, 0x4e, 0x7a, 0x35, 0x7a, 0xf1, 0x34, 0xc6,
];

/// Action-type tag for a stateful-only key rotation:
/// `keccak256(b"shrincs-account-example/rotate-stateful")`.
pub const ACTION_ROTATE_STATEFUL: [u8; HASH_LEN] = [
    0x63, 0x55, 0x73, 0xc2, 0x1a, 0xa2, 0x81, 0x6d, 0xfc, 0xde, 0x70, 0x99, 0xf8, 0xa0, 0xca, 0xfd,
    0x72, 0xfe, 0xac, 0x2b, 0xd7, 0x38, 0x73, 0x3d, 0xf4, 0x8b, 0x99, 0x34, 0x40, 0xa5, 0x28, 0x00,
];

/// Action-type tag for a full key rotation: `keccak256(b"shrincs-account-example/rotate-full")`.
pub const ACTION_ROTATE_FULL: [u8; HASH_LEN] = [
    0x7b, 0x29, 0xc4, 0x28, 0xfd, 0x81, 0xe3, 0x83, 0x85, 0x97, 0xb4, 0xc6, 0xde, 0xca, 0xe5, 0x49,
    0xe8, 0xc1, 0xda, 0xe7, 0xad, 0x90, 0x77, 0x60, 0x18, 0xcd, 0xd3, 0x82, 0x90, 0xdb, 0xc1, 0x0b,
];

/// Compute the canonical signing domain for `account` under `program_id`:
/// `keccak256(DOMAIN_TAG || program_id(32) || account(32))`.
///
/// Off-chain signers must call this (or replicate it) to build the exact
/// `ActionContext` a given action instruction will check against.
pub fn domain_separator(program_id: &Pubkey, account: &Pubkey) -> [u8; HASH_LEN] {
    hashv(&[&DOMAIN_TAG, program_id.as_ref(), account.as_ref()]).0
}

/// Pack the fields the retained `ShrincsVerifier::verify_stateful` /
/// `verify_stateless` check against into an [`ActionContext`].
pub fn action_context(
    domain_separator: [u8; HASH_LEN],
    nonce: [u8; HASH_LEN],
    key_version: [u8; HASH_LEN],
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
) -> ActionContext {
    ActionContext {
        domain_separator,
        nonce,
        key_version,
        action_type,
        payload_hash,
    }
}

/// Hash an action's payload for [`ActionContext::payload_hash`]:
/// `keccak256(action_selector || payload)`.
pub fn action_payload(action_selector: &[u8; HASH_LEN], payload: &[u8]) -> [u8; HASH_LEN] {
    hashv(&[action_selector, payload]).0
}

/// Payload hash for a stateful-only rotation (`ACTION_ROTATE_STATEFUL`):
/// `keccak256(next_stateful_public_key || next_commitment)`.
pub fn rotate_stateful_payload(
    next_stateful_public_key: &[u8; STATEFUL_PUBLIC_KEY_BYTES],
    next_commitment: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hashv(&[next_stateful_public_key, next_commitment]).0
}

/// Payload hash for a full key rotation (`ACTION_ROTATE_FULL`):
/// `keccak256(next_stateful_public_key || next_pk_seed || next_hypertree_root || next_commitment)`.
pub fn rotate_full_payload(
    next_stateful_public_key: &[u8; STATEFUL_PUBLIC_KEY_BYTES],
    next_pk_seed: &[u8; HASH_LEN],
    next_hypertree_root: &[u8; HASH_LEN],
    next_commitment: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hashv(&[
        next_stateful_public_key,
        next_pk_seed,
        next_hypertree_root,
        next_commitment,
    ])
    .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_matches_keccak_of_message() {
        assert_eq!(
            DOMAIN_TAG,
            solana_program::keccak::hash(b"shrincs-account-v1").0
        );
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let program_id = Pubkey::new_unique();
        let account = Pubkey::new_unique();
        assert_eq!(
            domain_separator(&program_id, &account),
            domain_separator(&program_id, &account)
        );
    }

    #[test]
    fn domain_separator_changes_with_program_id() {
        let account = Pubkey::new_unique();
        let program_a = Pubkey::new_unique();
        let program_b = Pubkey::new_unique();
        assert_ne!(
            domain_separator(&program_a, &account),
            domain_separator(&program_b, &account)
        );
    }

    #[test]
    fn domain_separator_changes_with_account() {
        let program_id = Pubkey::new_unique();
        let account_a = Pubkey::new_unique();
        let account_b = Pubkey::new_unique();
        assert_ne!(
            domain_separator(&program_id, &account_a),
            domain_separator(&program_id, &account_b)
        );
    }

    #[test]
    fn action_tags_are_pairwise_distinct() {
        let tags = [
            ACTION_STATEFUL,
            ACTION_STATELESS,
            ACTION_ROTATE_STATEFUL,
            ACTION_ROTATE_FULL,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags[{i}] collided with tags[{j}]");
            }
        }
    }

    #[test]
    fn action_context_packs_fields_positionally() {
        let context = action_context(
            [1u8; HASH_LEN],
            [2u8; HASH_LEN],
            [3u8; HASH_LEN],
            [4u8; HASH_LEN],
            [5u8; HASH_LEN],
        );
        assert_eq!(context.domain_separator, [1u8; HASH_LEN]);
        assert_eq!(context.nonce, [2u8; HASH_LEN]);
        assert_eq!(context.key_version, [3u8; HASH_LEN]);
        assert_eq!(context.action_type, [4u8; HASH_LEN]);
        assert_eq!(context.payload_hash, [5u8; HASH_LEN]);
    }

    #[test]
    fn action_payload_deterministic_and_selector_sensitive() {
        let selector_a = ACTION_STATEFUL;
        let selector_b = ACTION_STATELESS;
        let payload = b"payload-bytes";
        assert_eq!(
            action_payload(&selector_a, payload),
            action_payload(&selector_a, payload)
        );
        assert_ne!(
            action_payload(&selector_a, payload),
            action_payload(&selector_b, payload)
        );
    }

    #[test]
    fn rotate_stateful_payload_deterministic_and_input_sensitive() {
        let key_a = [1u8; STATEFUL_PUBLIC_KEY_BYTES];
        let key_b = [2u8; STATEFUL_PUBLIC_KEY_BYTES];
        let commitment_a = [3u8; HASH_LEN];
        let commitment_b = [4u8; HASH_LEN];

        assert_eq!(
            rotate_stateful_payload(&key_a, &commitment_a),
            rotate_stateful_payload(&key_a, &commitment_a)
        );
        assert_ne!(
            rotate_stateful_payload(&key_a, &commitment_a),
            rotate_stateful_payload(&key_b, &commitment_a)
        );
        assert_ne!(
            rotate_stateful_payload(&key_a, &commitment_a),
            rotate_stateful_payload(&key_a, &commitment_b)
        );
    }

    #[test]
    fn rotate_full_payload_deterministic_and_input_sensitive() {
        let key = [1u8; STATEFUL_PUBLIC_KEY_BYTES];
        let pk_seed_a = [2u8; HASH_LEN];
        let pk_seed_b = [3u8; HASH_LEN];
        let root_a = [4u8; HASH_LEN];
        let root_b = [5u8; HASH_LEN];
        let commitment_a = [6u8; HASH_LEN];
        let commitment_b = [7u8; HASH_LEN];

        let base = rotate_full_payload(&key, &pk_seed_a, &root_a, &commitment_a);
        assert_eq!(base, rotate_full_payload(&key, &pk_seed_a, &root_a, &commitment_a));
        assert_ne!(base, rotate_full_payload(&key, &pk_seed_b, &root_a, &commitment_a));
        assert_ne!(base, rotate_full_payload(&key, &pk_seed_a, &root_b, &commitment_a));
        assert_ne!(base, rotate_full_payload(&key, &pk_seed_a, &root_a, &commitment_b));
    }
}
