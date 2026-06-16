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

//! Account-policy layer scaffold for `hashsigs-rs`.
//!
//! This module stays inside the main crate for now, but remains logically
//! separate from the core cryptographic primitives. It is the future home for:
//!
//! - nonce ownership
//! - key-version ownership
//! - stateful leaf tracking
//! - stateless usage accounting
//! - recovery / rotation policy

use crate::shrincs::{ActionContext, ParameterSetId, PublicKey, RotationContext, HASH_LEN};

/// Stateful-leaf / recovery policy owned by the account manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatefulPolicy {
    /// Accept only the next expected stateful leaf index.
    MonotonicIndex,
    /// Treat stateless signatures as recovery / rotation authority.
    RecoveryRotation,
    /// Track stateful leaf reuse via a bitmap or equivalent sparse set.
    LeafBitmap,
}

/// Persisted account state that sits above the core SHRINCS primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    /// Installed hybrid public key currently trusted by the account manager.
    pub public_key: PublicKey,
    /// Active parameter set for the installed key.
    pub parameter_set_id: ParameterSetId,
    /// Canonical freshness nonce encoded in the same 32-byte form used by the core verifier.
    pub nonce: [u8; HASH_LEN],
    /// Current key epoch encoded in the same 32-byte form used by the core verifier.
    pub key_version: [u8; HASH_LEN],
    /// Count of stateless signatures consumed under the installed key.
    pub stateless_signatures_used: u64,
    /// Active stateful leaf / recovery policy.
    pub stateful_policy: StatefulPolicy,
    /// Next expected stateful leaf for monotonic tracking.
    pub next_stateful_leaf_index: u32,
    /// Whether stateless recovery mode is currently armed.
    pub recovery_mode: bool,
}

impl AccountState {
    /// Initialize account state around an installed public key.
    pub fn new(public_key: PublicKey, parameter_set_id: ParameterSetId) -> Self {
        Self {
            public_key,
            parameter_set_id,
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
            stateless_signatures_used: 0,
            stateful_policy: StatefulPolicy::MonotonicIndex,
            next_stateful_leaf_index: 1,
            recovery_mode: false,
        }
    }

    /// Build the canonical action context from the current account state.
    pub fn action_context(
        &self,
        domain_separator: [u8; HASH_LEN],
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
    ) -> ActionContext {
        ActionContext {
            domain_separator,
            nonce: self.nonce,
            key_version: self.key_version,
            action_type,
            payload_hash,
        }
    }

    /// Build the canonical rotation context from the current account state.
    pub fn rotation_context(&self, domain_separator: [u8; HASH_LEN]) -> RotationContext {
        RotationContext {
            domain_separator,
            nonce: self.nonce,
            key_version: self.key_version,
        }
    }
}
