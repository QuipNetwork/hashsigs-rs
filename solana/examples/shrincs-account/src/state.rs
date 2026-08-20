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

//! SHRINCS account PDA state layout.
//!
//! Ported near-verbatim from the deleted Solana account program
//! (`solana/src/account.rs` prior to its removal at `5e13d35~1`). That
//! version derived `HASH_LEN` from `hashsigs_rs::shrincs`; this crate keeps
//! state/PDA logic free of a `hashsigs-rs` dependency, so it is redefined
//! locally as a plain `usize` constant instead.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{program_error::ProgramError, pubkey::Pubkey};

/// Length in bytes of a SHRINCS hash/commitment/nonce/key-version field.
pub const HASH_LEN: usize = 32;

/// Current stateful leaf-tracking / recovery policy enforced by the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatefulPolicy {
    /// Accept only the next expected stateful leaf index.
    MonotonicIndex = 0,
    /// Treat stateless signatures as recovery/rotation authority once
    /// recovery mode is entered.
    RecoveryRotation = 1,
    /// Track stateful leaf reuse with a per-key-version bitmap.
    LeafBitmap = 2,
}

impl TryFrom<u8> for StatefulPolicy {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StatefulPolicy::MonotonicIndex),
            1 => Ok(StatefulPolicy::RecoveryRotation),
            2 => Ok(StatefulPolicy::LeafBitmap),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

/// PDA-resident SHRINCS account state. Field order fixes the Borsh layout;
/// append-only if the layout ever needs to grow.
///
/// # Borsh exception
///
/// Fields are `pub` because Borsh serialization requires public fields on
/// account state. Callers (and on-chain instruction handlers) must preserve
/// the state-machine invariants among policy, recovery mode, leaf index, and
/// frozen flags — do not treat this as a free bag of independent values.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShrincsAccountState {
    /// Installed bundle commitment currently trusted by the wrapper.
    pub current_public_key_commitment: [u8; HASH_LEN],
    /// Account owner allowed to change wrapper policy and enter recovery mode.
    pub owner: Pubkey,
    /// Canonical action/rotation nonce consumed on successful wrapper operations.
    pub nonce: [u8; HASH_LEN],
    /// Installed-key epoch incremented whenever a fresh key bundle is installed.
    pub key_version: [u8; HASH_LEN],
    /// Number of stateless signatures consumed under the current installed key.
    pub stateless_signatures_used: u64,
    /// Current stateful leaf-tracking / recovery policy (`StatefulPolicy` as `u8`).
    pub stateful_policy: u8,
    /// Whether stateful leaf consumption has frozen policy changes for the current key epoch.
    pub stateful_policy_frozen: bool,
    /// Next expected stateful leaf when monotonic tracking is active.
    pub next_stateful_leaf_index: u32,
    /// Whether the wrapper is currently in recovery mode for stateless rotation.
    pub recovery_mode: bool,
}

/// Increment a big-endian 256-bit integer in place, propagating carry from
/// the last byte backward. Wraps to all-zero if every byte overflows (i.e.
/// incrementing `[0xff; 32]` yields `[0x00; 32]`), matching
/// `hashsigs_rs::account::increment_u256_be`.
pub fn increment_u256_be(value: &mut [u8; HASH_LEN]) {
    for byte in value.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_borsh_round_trip() {
        let state = ShrincsAccountState {
            current_public_key_commitment: [1u8; HASH_LEN],
            owner: Pubkey::new_unique(),
            nonce: [2u8; HASH_LEN],
            key_version: [3u8; HASH_LEN],
            stateless_signatures_used: 7,
            stateful_policy: StatefulPolicy::LeafBitmap as u8,
            stateful_policy_frozen: true,
            next_stateful_leaf_index: 42,
            recovery_mode: true,
        };

        let bytes = borsh::to_vec(&state).expect("serialize");
        // 32+32+32+32+8+1+1+4+1 = 143 bytes; every field is fixed-size.
        assert_eq!(bytes.len(), 143);

        let round_tripped = ShrincsAccountState::try_from_slice(&bytes).expect("deserialize");
        assert_eq!(state, round_tripped);
    }

    #[test]
    fn stateful_policy_try_from_round_trips() {
        assert_eq!(
            StatefulPolicy::try_from(0).unwrap(),
            StatefulPolicy::MonotonicIndex
        );
        assert_eq!(
            StatefulPolicy::try_from(1).unwrap(),
            StatefulPolicy::RecoveryRotation
        );
        assert_eq!(
            StatefulPolicy::try_from(2).unwrap(),
            StatefulPolicy::LeafBitmap
        );
    }

    #[test]
    fn stateful_policy_try_from_rejects_unknown_value() {
        assert_eq!(
            StatefulPolicy::try_from(3),
            Err(ProgramError::InvalidAccountData)
        );
    }

    #[test]
    fn increment_u256_be_from_zero() {
        let mut value = [0u8; HASH_LEN];
        increment_u256_be(&mut value);
        let mut expected = [0u8; HASH_LEN];
        expected[HASH_LEN - 1] = 1;
        assert_eq!(value, expected);
    }

    #[test]
    fn increment_u256_be_carries_into_previous_byte() {
        let mut value = [0u8; HASH_LEN];
        value[HASH_LEN - 1] = 0xff;
        increment_u256_be(&mut value);
        let mut expected = [0u8; HASH_LEN];
        expected[HASH_LEN - 2] = 1;
        assert_eq!(value, expected);
    }

    #[test]
    fn increment_u256_be_wraps_to_zero_on_full_overflow() {
        let mut value = [0xffu8; HASH_LEN];
        increment_u256_be(&mut value);
        assert_eq!(value, [0u8; HASH_LEN]);
    }
}
