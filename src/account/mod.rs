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

//! Stateful/stateless SHRINCS account wrapper, mirroring Solidity's account contract.
//!
//! Sits above `shrincs` in the DAG: it adds policy (stateful leaf-reuse
//! handling, recovery/rotation arming) and typed error reporting around the
//! `ShrincsVerifier` primitives, but owns no cryptography itself. This module
//! is a line-by-line port of the Solidity account wrapper. Identifiers
//! (methods, fields, locals) intentionally mirror the Solidity camelCase names
//! so the two implementations can be cross-read and audited against each other.
#![allow(non_snake_case)]

use std::collections::HashMap;

use crate::primitives::hash_backend;
use crate::envelope::{self, Erc1271Envelope};
use crate::shrincs::{
    ActionContext, PublicKey, RotationContext, RotationTarget, ShrincsVerifier,
    StatefulRotationTarget, StatefulSignature, StatelessSignature, HASH_LEN,
    STATELESS_SIGNATURE_LIMIT,
};

fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    hash_backend::keccak256(data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatefulPolicy {
    // Accept only the next expected stateful leaf index.
    MonotonicIndex,
    // Treat stateless signatures as recovery/rotation authority once recovery mode is entered.
    RecoveryRotation,
    // Track stateful leaf reuse with a per-key-version bitmap.
    LeafBitmap,
}

// Freshly installed keys begin stateful signing at leaf 1.
pub const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;

// Stable domain tag for this wrapper family.
pub const DOMAIN_TAG_MESSAGE: &[u8] = b"shrincs-account-v1";

// Distinct wrapper failure reasons. Each maps to its own typed JS error code in
// the wasm layer so a rejection is never collapsed into a single boolean. This
// intentionally departs from the Solidity boolean-parity port (approved review
// decision for MR !2): crypto-invalid, policy-frozen, budget-exhausted,
// recovery-not-armed, and leaf/policy rejections are all separately observable.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    #[error("only the account owner may perform this action")]
    OnlyOwner,
    #[error("the recovery-rotation policy must be active for this operation")]
    RecoveryPolicyRequired,
    #[error("stateful monotonic leaf index rollback is not allowed")]
    StatefulIndexRollback,
    #[error("stateful policy changes are frozen after the first stateful use in this key epoch")]
    StatefulPolicyFrozen,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("the stateless signature budget is exhausted for the current key epoch")]
    BudgetExhausted,
    #[error("recovery mode is not armed")]
    RecoveryNotArmed,
    #[error("the stateful signing path is disabled under the recovery-rotation policy")]
    StatefulPathDisabled,
    #[error("the stateful leaf is not accepted by the active anti-reuse policy")]
    StatefulLeafRejected,
    #[error("the ERC-1271 signature envelope could not be decoded")]
    MalformedSignature,
}

// Typed mirror of the six Solidity contract events. The Solidity wrapper emits
// these via `emit` at fixed points in each state transition; this port records
// the same payloads in an in-memory log so callers can observe the transition
// trail. Field names and values mirror the Solidity events exactly, including
// which nonce/keyVersion snapshot each emission captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEvent {
    // Solidity: StatefulPolicySet(StatefulPolicy indexed policy, uint32 nextStatefulLeafIndex).
    StatefulPolicySet {
        policy: StatefulPolicy,
        nextStatefulLeafIndex: u32,
    },
    // Solidity: RecoveryModeEntered(uint256 indexed keyVersion).
    RecoveryModeEntered {
        keyVersion: [u8; HASH_LEN],
    },
    // Solidity: KeyRotated(bytes32 indexed previous, bytes32 indexed next, uint256 nextKeyVersion).
    KeyRotated {
        previousShrincsPublicKey: [u8; HASH_LEN],
        nextShrincsPublicKey: [u8; HASH_LEN],
        nextKeyVersion: [u8; HASH_LEN],
    },
    // Solidity: StatefulSignatureVerified(uint32 indexed leafIndex, uint256 indexed nonce, uint256 indexed keyVersion).
    StatefulSignatureVerified {
        leafIndex: u32,
        nonce: [u8; HASH_LEN],
        keyVersion: [u8; HASH_LEN],
    },
    // Solidity: StatelessSignatureVerified(uint64 usedCount, uint256 indexed nonce, uint256 indexed keyVersion).
    StatelessSignatureVerified {
        usedCount: u64,
        nonce: [u8; HASH_LEN],
        keyVersion: [u8; HASH_LEN],
    },
    // Solidity: StatelessRotationConsumed(uint64 usedCount, uint256 indexed nonce, uint256 indexed keyVersion, bytes32 indexed next, bool fullRotation).
    StatelessRotationConsumed {
        usedCount: u64,
        nonce: [u8; HASH_LEN],
        keyVersion: [u8; HASH_LEN],
        nextShrincsPublicKey: [u8; HASH_LEN],
        fullRotation: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShrincsAccountVerifierExample {
    // Installed bundle commitment currently trusted by the wrapper.
    currentShrincsPublicKey: [u8; HASH_LEN],
    // Account owner allowed to change wrapper policy and enter recovery mode.
    owner: [u8; HASH_LEN],
    // Chain identity used when deriving the canonical signing domain.
    chainId: [u8; HASH_LEN],
    // Contract/account identity used when deriving the canonical signing domain.
    contractAddress: [u8; 20],
    // Canonical action/rotation nonce consumed on successful wrapper operations.
    nonce: [u8; HASH_LEN],
    // Installed-key epoch incremented whenever a fresh key bundle is installed.
    keyVersion: [u8; HASH_LEN],
    // Number of stateless signatures consumed under the current installed key.
    statelessSignaturesUsed: u64,
    // Current stateful leaf-tracking / recovery policy enforced by the wrapper.
    statefulPolicy: StatefulPolicy,
    // Whether stateful leaf consumption has frozen policy changes for the current key epoch.
    statefulPolicyFrozen: bool,
    // Next expected stateful leaf when monotonic tracking is active.
    nextStatefulLeafIndex: u32,
    // Whether the wrapper is currently in recovery mode for stateless rotation.
    recoveryMode: bool,

    usedLeafBitmap: HashMap<([u8; HASH_LEN], u64), U256>,

    // Ordered log of emitted contract events, mirroring Solidity's `emit`
    // trail. Not part of the Solidity storage layout; it is observability the
    // EVM provides through the transaction receipt. This vector grows on every
    // emitting operation and is never pruned automatically (unlike
    // `usedLeafBitmap`, a rotation does not clear it): callers that keep an
    // instance alive across many operations must call `drain_events()`
    // periodically to bound the log's memory.
    events: Vec<AccountEvent>,
}

impl ShrincsAccountVerifierExample {
    // constructor: Install the initial key commitment and start in the default safe wrapper mode.
    // 1. Record the deployer as the wrapper owner.
    // 2. Install the initial SHRINCS public-key commitment.
    // 3. Start with monotonic stateful leaf tracking.
    // 4. Expect the first stateful signature to use leaf 1.
    pub fn new(
        owner: [u8; HASH_LEN],
        chainId: [u8; HASH_LEN],
        contractAddress: [u8; 20],
        initialShrincsPublicKey: [u8; HASH_LEN],
    ) -> Self {
        Self {
            // Record the deployer as the wrapper administrator.
            owner,
            // Install the first trusted SHRINCS public-key commitment.
            currentShrincsPublicKey: initialShrincsPublicKey,
            // Preserve the deployment identity that defines the canonical signing domain.
            chainId,
            contractAddress,
            nonce: [0u8; HASH_LEN],
            keyVersion: [0u8; HASH_LEN],
            statelessSignaturesUsed: 0,
            // Default to ordered stateful signing under monotonic leaf tracking.
            statefulPolicy: StatefulPolicy::MonotonicIndex,
            statefulPolicyFrozen: false,
            // Fresh keys begin consuming stateful leaves from index 1.
            nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
            recoveryMode: false,
            usedLeafBitmap: HashMap::new(),
            events: Vec::new(),
        }
    }

    pub fn currentShrincsPublicKey(&self) -> [u8; HASH_LEN] {
        self.currentShrincsPublicKey
    }

    pub fn owner(&self) -> [u8; HASH_LEN] {
        self.owner
    }

    pub fn chainId(&self) -> [u8; HASH_LEN] {
        self.chainId
    }

    pub fn contractAddress(&self) -> [u8; 20] {
        self.contractAddress
    }

    pub fn nonce(&self) -> [u8; HASH_LEN] {
        self.nonce
    }

    pub fn keyVersion(&self) -> [u8; HASH_LEN] {
        self.keyVersion
    }

    pub fn statelessSignaturesUsed(&self) -> u64 {
        self.statelessSignaturesUsed
    }

    pub fn statefulPolicy(&self) -> StatefulPolicy {
        self.statefulPolicy
    }

    pub fn nextStatefulLeafIndex(&self) -> u32 {
        self.nextStatefulLeafIndex
    }

    pub fn statefulPolicyFrozen(&self) -> bool {
        self.statefulPolicyFrozen
    }

    pub fn recoveryMode(&self) -> bool {
        self.recoveryMode
    }

    // events: Borrow the ordered event trail emitted so far without clearing it.
    pub fn events(&self) -> &[AccountEvent] {
        &self.events
    }

    // drain_events: Take and clear the accumulated event trail. Mirrors reading
    // and consuming the events a Solidity transaction would have emitted.
    // Bounding the event log is the caller's responsibility: nothing else
    // clears `events`, so a long-lived instance must drain periodically to keep
    // the trail from growing without bound.
    pub fn drain_events(&mut self) -> Vec<AccountEvent> {
        std::mem::take(&mut self.events)
    }

    // emit: Append one contract event to the ordered trail at a Solidity `emit`
    // point.
    fn emit(&mut self, event: AccountEvent) {
        self.events.push(event);
    }

    // verifyStatefulUncheckedMessage: Internal raw stateful verification for tests and
    // support harnesses only.
    // 1. Recover the stateful leaf index from the auth-path length.
    // 2. Check the active leaf-tracking policy before any cryptographic work.
    // 3. Verify the caller-supplied message directly without building canonical action context.
    // 4. Commit the consumed leaf only after signature verification succeeds.
    // 5. Emit the usual stateful verification event without advancing the wrapper nonce.
    #[cfg(test)]
    pub(crate) fn verifyStatefulUncheckedMessage(
        &mut self,
        publicKey: &PublicKey,
        message: &[u8],
        signature: &StatefulSignature,
    ) -> bool {
        // This path bypasses canonical wrapper message construction and therefore
        // remains internal-only.
        // Defense-in-depth: reject an auth path so long its length would truncate when
        // narrowed to u32 before it becomes the consumed leaf index.
        if signature.auth_path.len() > u32::MAX as usize {
            return false;
        }
        // Recover the consumed stateful leaf from the signature layout.
        let leafIndex = signature.auth_path.len() as u32;
        // Stop early if the active policy disallows this leaf.
        if !self.precheckStatefulLeafUse(leafIndex) {
            return false;
        }

        // Verify the caller-supplied message directly against the current installed key.
        let ok = ShrincsVerifier::new().verify_stateful_unsafe_raw(
            self.currentShrincsPublicKey,
            publicKey,
            message,
            signature,
        );
        if !ok {
            return false;
        }

        // Record the leaf only after the signature is known to be valid.
        self.commitStatefulLeafUse(leafIndex);
        // Emit the same observability event as the canonical stateful action flow.
        // This path does not advance the nonce, so the emitted nonce is the current one.
        self.emit(AccountEvent::StatefulSignatureVerified {
            leafIndex,
            nonce: self.nonce,
            keyVersion: self.keyVersion,
        });
        true
    }

    // verifyStatefulAction: Canonical stateful account-action verification path.
    // 1. Recover the leaf index that this stateful signature consumes.
    // 2. Reject leaves that violate the active stateful policy.
    // 3. Build the canonical typed action context from wrapper-owned freshness state.
    // 4. Verify the signature against that canonical action message.
    // 5. Commit the leaf, emit the verification event, and then advance the nonce.
    pub fn verifyStatefulAction(
        &mut self,
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatefulSignature,
    ) -> Result<(), AccountError> {
        // Defense-in-depth: reject an auth path so long its length would truncate when
        // narrowed to u32 before it becomes the consumed leaf index.
        if signature.auth_path.len() > u32::MAX as usize {
            return Err(AccountError::InvalidSignature);
        }
        // Recover the consumed stateful leaf from the signature layout.
        let leafIndex = signature.auth_path.len() as u32;
        // Stop early with the distinct reason if the active policy disallows this leaf.
        self.checkStatefulLeafUse(leafIndex)?;

        // Bind the action to this contract instance, nonce, and key epoch.
        let context = ActionContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
            action_type: actionType,
            payload_hash: payloadHash,
        };

        // Verify the canonical typed action under the installed key commitment.
        let ok = ShrincsVerifier::new().verify_stateful(
            self.currentShrincsPublicKey,
            publicKey,
            &context,
            signature,
        );
        if !ok {
            return Err(AccountError::InvalidSignature);
        }

        // Consume the leaf only after the action signature verifies.
        self.commitStatefulLeafUse(leafIndex);
        // Emit before nonce advancement so observers see the consumed nonce value.
        self.emit(AccountEvent::StatefulSignatureVerified {
            leafIndex,
            nonce: self.nonce,
            keyVersion: self.keyVersion,
        });
        // Advance freshness state after a successful action.
        increment_u256_be(&mut self.nonce);
        Ok(())
    }

    // verifyStatelessAction: Canonical stateless account-action verification path.
    // 1. Reject stateless actions when recovery mode gating forbids them.
    // 2. Enforce the fixed stateless usage budget for the current key epoch.
    // 3. Build the canonical typed action context from wrapper-owned freshness state.
    // 4. Verify the stateless signature against that canonical action message.
    // 5. Advance nonce and stateless-usage counters only after success.
    pub fn verifyStatelessAction(
        &mut self,
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> Result<(), AccountError> {
        // Recovery-only policy forbids stateless actions until recovery mode is explicitly entered.
        if self.statefulPolicy == StatefulPolicy::RecoveryRotation && !self.recoveryMode {
            return Err(AccountError::RecoveryNotArmed);
        }
        // Enforce the per-key stateless usage budget.
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return Err(AccountError::BudgetExhausted);
        }

        // Bind the action to this contract instance, nonce, and key epoch.
        let context = ActionContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
            action_type: actionType,
            payload_hash: payloadHash,
        };

        // Verify the canonical typed action under the installed key commitment.
        let ok = ShrincsVerifier::new().verify_stateless(
            self.currentShrincsPublicKey,
            publicKey,
            &context,
            signature,
        );
        if !ok {
            return Err(AccountError::InvalidSignature);
        }

        // Capture the consumed nonce before advancing; Solidity emits `nonce - 1`,
        // i.e. the pre-increment value.
        let consumedNonce = self.nonce;
        // Advance wrapper freshness and stateless usage state after success.
        increment_u256_be(&mut self.nonce);
        self.statelessSignaturesUsed += 1;
        // Emit the consumed nonce value from the pre-increment state.
        self.emit(AccountEvent::StatelessSignatureVerified {
            usedCount: self.statelessSignaturesUsed,
            nonce: consumedNonce,
            keyVersion: self.keyVersion,
        });
        Ok(())
    }

    // isValidSignature: ERC-1271 compatibility view for canonical SHRINCS
    // account-action signatures.
    // 1. Decode the leading envelope mode byte and dispatch the remainder as
    //    a stateful or stateless action envelope.
    // 2. Rebuild the current action context from wrapper-owned state.
    // 3. Require the supplied hash to match the canonical action hash.
    // 4. Verify the embedded SHRINCS signature without mutating any state
    //    (no leaf commit, no nonce advance, no stateless-budget consumption).
    //
    // Revert-model divergence: Solidity reverts on an empty signature (no
    // mode byte) or a malformed envelope, and returns 0xffffffff for an
    // unknown mode byte or a well-formed-but-invalid signature. Rust has no
    // revert channel, and `envelope::decode_1271_envelope` itself already
    // collapses "empty", "unknown mode", and "malformed payload" into one
    // `None` (see its doc comment) rather than duplicating its mode-byte
    // read here — so all three map to `AccountError::MalformedSignature`.
    pub fn isValidSignature(
        &self,
        hash: [u8; HASH_LEN],
        signature: &[u8],
    ) -> Result<(), AccountError> {
        match envelope::decode_1271_envelope(signature) {
            Some(Erc1271Envelope::Stateful {
                public_key,
                action_type,
                payload_hash,
                signature,
            }) => self.isValidStatefulActionSignatureNow(
                hash,
                &public_key,
                action_type,
                payload_hash,
                &signature,
            ),
            Some(Erc1271Envelope::Stateless {
                public_key,
                action_type,
                payload_hash,
                signature,
            }) => self.isValidStatelessActionSignatureNow(
                hash,
                &public_key,
                action_type,
                payload_hash,
                &signature,
            ),
            None => Err(AccountError::MalformedSignature),
        }
    }

    // isValidStatefulActionSignatureNow: Read-only helper for canonical
    // stateful action verification.
    // 1. Recover the leaf index this signature would consume.
    // 2. Enforce the active stateful leaf policy WITHOUT consuming the leaf.
    // 3. Rebuild the canonical action context from wrapper-owned state.
    // 4. Require the supplied hash to match the canonical stateful action
    //    hash and the context to be well-formed.
    // 5. Verify the signature over that hash through the raw-hash stateful
    //    path (mirrors `SHRINCS.verify`), without committing the leaf.
    fn isValidStatefulActionSignatureNow(
        &self,
        hash: [u8; HASH_LEN],
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatefulSignature,
    ) -> Result<(), AccountError> {
        // Defense-in-depth: reject an auth path so long its length would truncate when
        // narrowed to u32 before it becomes the consumed leaf index.
        if signature.auth_path.len() > u32::MAX as usize {
            return Err(AccountError::InvalidSignature);
        }
        let leafIndex = signature.auth_path.len() as u32;
        // Precheck the policy gate without recording any leaf use.
        self.checkStatefulLeafUse(leafIndex)?;

        let context = ActionContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
            action_type: actionType,
            payload_hash: payloadHash,
        };
        if ShrincsVerifier::new()
            .stateful_action_message_hash(self.currentShrincsPublicKey, &context)
            != hash
        {
            return Err(AccountError::InvalidSignature);
        }
        if !crate::shrincs::valid_action_context(&context) {
            return Err(AccountError::InvalidSignature);
        }

        let ok = crate::shrincs::verify_stateful_unsafe_raw(
            self.currentShrincsPublicKey,
            publicKey,
            &hash,
            signature,
        );
        if !ok {
            return Err(AccountError::InvalidSignature);
        }
        Ok(())
    }

    // isValidStatelessActionSignatureNow: Read-only helper for canonical
    // stateless action verification.
    // 1. Enforce recovery-mode gating and the stateless usage budget WITHOUT
    //    consuming either.
    // 2. Rebuild the canonical action context from wrapper-owned state.
    // 3. Require the supplied hash to match the canonical stateless action
    //    hash and the context to be well-formed.
    // 4. Verify the signature over that hash through the raw-hash stateless
    //    path (mirrors `SHRINCS.verifyStatelessUncheckedMessage`), without
    //    advancing the nonce or the stateless-signature counter.
    fn isValidStatelessActionSignatureNow(
        &self,
        hash: [u8; HASH_LEN],
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> Result<(), AccountError> {
        // Recovery-only policy forbids stateless actions until recovery mode is explicitly entered.
        if self.statefulPolicy == StatefulPolicy::RecoveryRotation && !self.recoveryMode {
            return Err(AccountError::RecoveryNotArmed);
        }
        // Enforce the per-key stateless usage budget without consuming it.
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return Err(AccountError::BudgetExhausted);
        }

        let context = ActionContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
            action_type: actionType,
            payload_hash: payloadHash,
        };
        if ShrincsVerifier::new()
            .stateless_action_message_hash(self.currentShrincsPublicKey, &context)
            != hash
        {
            return Err(AccountError::InvalidSignature);
        }
        if !crate::shrincs::valid_action_context(&context) {
            return Err(AccountError::InvalidSignature);
        }

        let ok = crate::shrincs::verify_stateless_unsafe_raw(
            self.currentShrincsPublicKey,
            publicKey,
            &hash,
            signature,
        );
        if !ok {
            return Err(AccountError::InvalidSignature);
        }
        Ok(())
    }

    // rotateToFreshKey: Recovery-only path that replaces the installed stateful subkey.
    // 1. Require the wrapper to be in recovery-rotation mode.
    // 2. Require recovery mode to be actively entered by the owner.
    // 3. Enforce the stateless usage budget for the current key epoch.
    // 4. Build the canonical rotation context from wrapper-owned freshness state.
    // 5. Verify the stateless recovery signature and derive the next key commitment.
    // 6. Install the fresh key bundle and reset wrapper state for the new epoch.
    pub fn rotateToFreshKey(
        &mut self,
        currentPublicKey: &PublicKey,
        recoverySignature: &StatelessSignature,
        nextKey: &StatefulRotationTarget,
    ) -> Result<(), AccountError> {
        // Fresh-key rotation is available only in the dedicated recovery policy.
        if self.statefulPolicy != StatefulPolicy::RecoveryRotation {
            return Err(AccountError::RecoveryPolicyRequired);
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if !self.recoveryMode {
            return Err(AccountError::RecoveryNotArmed);
        }
        // Enforce the per-key stateless usage budget.
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return Err(AccountError::BudgetExhausted);
        }

        // Bind the rotation to this contract instance, nonce, and key epoch.
        let context = RotationContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
        };

        // Verify the stateless recovery signature and derive the next installed commitment.
        let Some(nextCompositePublicKey) = ShrincsVerifier::new().rotate_stateful_via_stateless(
            self.currentShrincsPublicKey,
            currentPublicKey,
            &context,
            recoverySignature,
            nextKey,
        ) else {
            return Err(AccountError::InvalidSignature);
        };

        // Count the recovery signature against the current stateless budget before preserving it
        // into the next stateful-only epoch.
        self.statelessSignaturesUsed += 1;
        // Announce the consumed recovery signature before any install resets wrapper state.
        // nonce/keyVersion are still the pre-install epoch values; fullRotation is false.
        self.emit(AccountEvent::StatelessRotationConsumed {
            usedCount: self.statelessSignaturesUsed,
            nonce: self.nonce,
            keyVersion: self.keyVersion,
            nextShrincsPublicKey: nextCompositePublicKey,
            fullRotation: false,
        });
        // Install the next stateful subkey while preserving stateless usage accounting because
        // the stateless key material is unchanged.
        self.installRotatedKey(nextCompositePublicKey, false);
        Ok(())
    }

    // rotateFullKey: Recovery-only path that replaces the full installed SHRINCS key bundle.
    // 1. Require the wrapper to be in recovery-rotation mode.
    // 2. Require recovery mode to be actively entered by the owner.
    // 3. Enforce the stateless usage budget for the current key epoch.
    // 4. Build the canonical rotation context from wrapper-owned freshness state.
    // 5. Verify the stateless recovery signature and derive the next key commitment.
    // 6. Install the new key bundle and reset wrapper state for the new epoch.
    pub fn rotateFullKey(
        &mut self,
        currentPublicKey: &PublicKey,
        recoverySignature: &StatelessSignature,
        nextKey: &RotationTarget,
    ) -> Result<(), AccountError> {
        // Full-key rotation is available only in the dedicated recovery policy.
        if self.statefulPolicy != StatefulPolicy::RecoveryRotation {
            return Err(AccountError::RecoveryPolicyRequired);
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if !self.recoveryMode {
            return Err(AccountError::RecoveryNotArmed);
        }
        // Enforce the per-key stateless usage budget.
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return Err(AccountError::BudgetExhausted);
        }

        // Bind the rotation to this contract instance, nonce, and key epoch.
        let context = RotationContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
        };

        // Verify the stateless recovery signature and derive the next installed commitment.
        let Some(nextCompositePublicKey) = ShrincsVerifier::new().stateless_rotate(
            self.currentShrincsPublicKey,
            currentPublicKey,
            &context,
            recoverySignature,
            nextKey,
        ) else {
            return Err(AccountError::InvalidSignature);
        };

        // Count the recovery signature as the final stateless use under the old key.
        self.statelessSignaturesUsed += 1;
        // Announce the consumed recovery signature before any install resets wrapper state.
        // nonce/keyVersion are still the pre-install epoch values. Solidity's rotateFullKey
        // always tags this as a full rotation (fullRotation = true), independent of whether
        // the stateless key material actually changed.
        self.emit(AccountEvent::StatelessRotationConsumed {
            usedCount: self.statelessSignaturesUsed,
            nonce: self.nonce,
            keyVersion: self.keyVersion,
            nextShrincsPublicKey: nextCompositePublicKey,
            fullRotation: true,
        });
        // Reset the stateless budget only if the target actually replaces the stateless key
        // material. A rotation target that reuses the current pk_seed and hypertree_root keeps
        // the same few-time stateless key, so its usage accounting must carry forward.
        let statelessKeyChanged = nextKey.pk_seed != currentPublicKey.pk_seed
            || nextKey.hypertree_root != currentPublicKey.hypertree_root;
        // Install the next full key bundle and reset wrapper state for the new stateless epoch.
        self.installRotatedKey(nextCompositePublicKey, statelessKeyChanged);
        Ok(())
    }

    // isLeafUsed: Read bitmap-based stateful leaf usage for the current key epoch.
    // 1. Select the 256-leaf word containing the requested leaf.
    // 2. Select the bit inside that word for the requested leaf.
    // 3. Return whether that bit has already been marked as used.
    pub fn isLeafUsed(&self, leafIndex: u32) -> bool {
        // Group leaves into 256-bit words for compact bitmap storage.
        let wordIndex = u64::from(leafIndex) >> 8;
        // Select the bit inside that word corresponding to this leaf.
        let bitIndex = leafIndex & 0xff;
        // Return whether that bit has already been marked as used.
        self.usedLeafBitmap
            .get(&(self.keyVersion, wordIndex))
            .map(|usedBits| usedBits.bit(bitIndex))
            .unwrap_or(false)
    }

    // setStatefulPolicyMonotonicIndex: Switch to monotonic stateful leaf tracking.
    // 1. Only the owner may change the wrapper policy.
    // 2. Reject policy changes after any successful stateful leaf use in this key epoch.
    // 3. Prevent rollback to an earlier expected leaf index.
    // 4. Install monotonic tracking with the supplied next expected leaf.
    // 5. Exit recovery mode because the wrapper is returning to normal operation.
    // 6. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyMonotonicIndex(
        &mut self,
        caller: [u8; HASH_LEN],
        initialLeafIndex: u32,
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
        // Freeze the stateful tracking model once any stateful leaf has been consumed
        // in this epoch.
        if self.statefulPolicyFrozen {
            return Err(AccountError::StatefulPolicyFrozen);
        }
        // Never allow policy changes to roll back the expected monotonic leaf cursor.
        if initialLeafIndex < self.nextStatefulLeafIndex {
            return Err(AccountError::StatefulIndexRollback);
        }
        // Switch into ordered stateful leaf tracking.
        self.statefulPolicy = StatefulPolicy::MonotonicIndex;
        // Install the next expected stateful leaf supplied by the owner.
        self.nextStatefulLeafIndex = initialLeafIndex;
        // Leaving recovery-only mode returns the wrapper to normal operation.
        self.recoveryMode = false;
        self.emit(AccountEvent::StatefulPolicySet {
            policy: self.statefulPolicy,
            nextStatefulLeafIndex: self.nextStatefulLeafIndex,
        });
        Ok(())
    }

    // setStatefulPolicyRecoveryRotation: Switch to recovery-only stateless rotation mode.
    // 1. Only the owner may change the wrapper policy.
    // 2. Remain available even after the policy freeze so key rotation stays reachable.
    // 3. Preserve or initialize the stateful leaf cursor for later normal operation.
    // 4. Require an explicit enterRecoveryMode() call before stateless recovery is accepted.
    // 5. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyRecoveryRotation(
        &mut self,
        caller: [u8; HASH_LEN],
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
        // The policy freeze intentionally does NOT apply here. The freeze exists to stop
        // switches between leaf-tracking models (monotonic <-> bitmap) that would erase
        // leaf-use memory and enable stateful leaf reuse. RecoveryRotation disables the
        // stateful path entirely, so entering it cannot cause reuse — and it is the only
        // route to key rotation, which is what clears the freeze. Blocking it here would
        // permanently lock any account out of rotation after its first stateful signature.
        // The freeze flag stays set, so switching back to a leaf-tracking policy without
        // rotating first remains rejected.
        // Switch into the policy where stateless signatures serve as recovery authority.
        self.statefulPolicy = StatefulPolicy::RecoveryRotation;
        // Ensure the stateful cursor stays initialized for later normal operation.
        if self.nextStatefulLeafIndex == 0 {
            self.nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Require an explicit enterRecoveryMode() call before recovery signatures are accepted.
        self.recoveryMode = false;
        self.emit(AccountEvent::StatefulPolicySet {
            policy: self.statefulPolicy,
            nextStatefulLeafIndex: self.nextStatefulLeafIndex,
        });
        Ok(())
    }

    // setStatefulPolicyLeafBitmap: Switch to bitmap-based stateful leaf tracking.
    // 1. Only the owner may change the wrapper policy.
    // 2. Reject policy changes after any successful stateful leaf use in this key epoch.
    // 3. Preserve or initialize the stateful leaf cursor for future monotonic use.
    // 4. Exit recovery mode because the wrapper is returning to normal operation.
    // 5. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyLeafBitmap(
        &mut self,
        caller: [u8; HASH_LEN],
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
        // Freeze the stateful tracking model once any stateful leaf has been consumed
        // in this epoch.
        if self.statefulPolicyFrozen {
            return Err(AccountError::StatefulPolicyFrozen);
        }
        // Switch into out-of-order bitmap tracking for stateful leaf use.
        self.statefulPolicy = StatefulPolicy::LeafBitmap;
        // Ensure the stateful cursor stays initialized for future monotonic use.
        if self.nextStatefulLeafIndex == 0 {
            self.nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        }
        // Leaving recovery-only mode returns the wrapper to normal operation.
        self.recoveryMode = false;
        self.emit(AccountEvent::StatefulPolicySet {
            policy: self.statefulPolicy,
            nextStatefulLeafIndex: self.nextStatefulLeafIndex,
        });
        Ok(())
    }

    // enterRecoveryMode: Arm the wrapper for recovery-only stateless rotations.
    // 1. Only the owner may enter recovery mode.
    // 2. Require the dedicated recovery-rotation policy to already be active.
    // 3. Flip the recovery-mode flag so stateless recovery rotations are accepted.
    // 4. Emit the recovery-mode event for off-chain observers.
    pub fn enterRecoveryMode(&mut self, caller: [u8; HASH_LEN]) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
        // Recovery mode is meaningful only under the dedicated recovery policy.
        if self.statefulPolicy != StatefulPolicy::RecoveryRotation {
            return Err(AccountError::RecoveryPolicyRequired);
        }
        // Arm the wrapper so stateless recovery rotations are now accepted.
        self.recoveryMode = true;
        self.emit(AccountEvent::RecoveryModeEntered {
            keyVersion: self.keyVersion,
        });
        Ok(())
    }

    // checkStatefulLeafUse: Typed anti-reuse gate returning the distinct rejection reason.
    // 1. Reject all stateful signatures while the wrapper is configured for
    //    recovery-only authority.
    // 2. Under monotonic tracking, accept only the next expected leaf.
    // 3. Under bitmap tracking, accept only leaves that have not yet been marked used.
    // Exhaustive match: a future StatefulPolicy variant is a compile error here rather
    // than a silent accept, so this one-time-signature anti-reuse gate cannot fail open.
    pub(crate) fn checkStatefulLeafUse(&self, leafIndex: u32) -> Result<(), AccountError> {
        match self.statefulPolicy {
            // Recovery-rotation policy disables the stateful path entirely, whether or not
            // recovery mode has been explicitly armed yet.
            StatefulPolicy::RecoveryRotation => Err(AccountError::StatefulPathDisabled),
            // Ordered tracking accepts exactly one next leaf.
            StatefulPolicy::MonotonicIndex => {
                if leafIndex == self.nextStatefulLeafIndex {
                    Ok(())
                } else {
                    Err(AccountError::StatefulLeafRejected)
                }
            }
            // Bitmap tracking accepts any leaf that has not already been marked used.
            StatefulPolicy::LeafBitmap => {
                if self.isLeafUsed(leafIndex) {
                    Err(AccountError::StatefulLeafRejected)
                } else {
                    Ok(())
                }
            }
        }
    }

    // precheckStatefulLeafUse: Boolean anti-reuse gate for the internal raw stateful helper.
    // Thin wrapper over `checkStatefulLeafUse` that discards the distinct reason. Only the
    // test-only `verifyStatefulUncheckedMessage` needs the boolean form.
    #[cfg(test)]
    pub(crate) fn precheckStatefulLeafUse(&self, leafIndex: u32) -> bool {
        self.checkStatefulLeafUse(leafIndex).is_ok()
    }

    // commitStatefulLeafUse: Record a successfully verified stateful leaf under the active policy.
    // 1. Under monotonic tracking, advance the next expected leaf by one.
    // 2. Under bitmap tracking, mark the corresponding bit for this leaf as used.
    // 3. Freeze stateful policy changes for the remainder of the key epoch.
    // 4. Leave recovery-only mode unchanged because stateful signatures are blocked there.
    pub(crate) fn commitStatefulLeafUse(&mut self, leafIndex: u32) {
        // Exhaustive match so a future StatefulPolicy variant must declare how it records
        // a used leaf; an accepted-but-untracked leaf would reopen one-time-key reuse.
        match self.statefulPolicy {
            StatefulPolicy::MonotonicIndex => {
                // Move the expected cursor forward after one successful monotonic use.
                // saturating_add avoids an overflow panic (debug) / wrap (release) if
                // the owner-set cursor is ever near u32::MAX; the verifier already caps
                // usable leaves at max_signatures, so the saturation point is unreachable.
                self.nextStatefulLeafIndex = self.nextStatefulLeafIndex.saturating_add(1);
            }
            StatefulPolicy::LeafBitmap => {
                // Group leaves into 256-bit words for compact bitmap storage.
                let wordIndex = u64::from(leafIndex) >> 8;
                // Select the bit inside that word corresponding to this leaf.
                let bitIndex = leafIndex & 0xff;
                // Mark this leaf as consumed for the current key epoch.
                self.usedLeafBitmap
                    .entry((self.keyVersion, wordIndex))
                    .or_default()
                    .set_bit(bitIndex);
            }
            // Recovery-rotation blocks the stateful path (precheck rejects it), so there is
            // no leaf to record here.
            StatefulPolicy::RecoveryRotation => {}
        }
        // Any successful stateful verification fixes the tracking model for this key epoch.
        self.statefulPolicyFrozen = true;
    }

    // domainSeparator: Derive the wrapper's canonical signing domain.
    // 1. Start from a stable domain tag for this wrapper family.
    // 2. Bind the separator to the current chain id.
    // 3. Bind the separator to this contract instance.
    pub fn domainSeparator(&self) -> [u8; HASH_LEN] {
        // Bind wrapper signatures to this product tag, chain, and deployed contract instance.
        Self::computeDomainSeparator(self.chainId, self.contractAddress)
    }

    // computeDomainSeparator: Rust compatibility helper for Solidity domainSeparator().
    // 1. Start from a stable domain tag for this wrapper family.
    // 2. Bind the separator to the supplied chain id.
    // 3. Bind the separator to the supplied account/contract address.
    pub fn computeDomainSeparator(
        chainId: [u8; HASH_LEN],
        contractAddress: [u8; 20],
    ) -> [u8; HASH_LEN] {
        // Solidity uses keccak256("shrincs-account-v1") for DOMAIN_TAG.
        let DOMAIN_TAG = keccak256_hash(DOMAIN_TAG_MESSAGE);
        // Solidity abi.encode(bytes32,uint256,address) writes three 32-byte words.
        let mut encoded = Vec::with_capacity(HASH_LEN * 3);
        encoded.extend_from_slice(&DOMAIN_TAG);
        encoded.extend_from_slice(&chainId);
        // ABI-encoded address values are left-padded to one 32-byte word.
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(&contractAddress);
        keccak256_hash(&encoded)
    }

    // installRotatedKey: Install a rotated key bundle and reset wrapper state for the next epoch.
    // 1. Preserve the previous installed key commitment for the rotation event.
    // 2. Install the next SHRINCS public-key commitment.
    // 3. Advance nonce and key version to close the old authorization epoch.
    // 4. Reset or preserve stateless usage accounting according to the caller's intent.
    // 5. Reset stateful leaf tracking and policy-freeze state for the new key.
    // 6. Return the wrapper to the default monotonic non-recovery policy.
    // 7. Emit rotation and policy-reset events for off-chain observers.
    fn installRotatedKey(
        &mut self,
        nextCompositePublicKey: [u8; HASH_LEN],
        resetStatelessUsage: bool,
    ) {
        // Preserve the previous key commitment for the rotation event payload.
        let previousShrincsPublicKey = self.currentShrincsPublicKey;
        // Install the next trusted SHRINCS public-key commitment.
        self.currentShrincsPublicKey = nextCompositePublicKey;
        // Advance nonce and key epoch so old authorizations cannot be replayed.
        increment_u256_be(&mut self.nonce);
        increment_u256_be(&mut self.keyVersion);
        // Bound bitmap growth across rotations: leaf-use memory is scoped to a
        // key epoch, so drop every entry that does not belong to the new
        // keyVersion. Without this the map would accumulate one dead word per
        // touched leaf-word for every past epoch, growing without bound across
        // repeated rotations. Copy keyVersion first so the retain closure does
        // not borrow `self` while `usedLeafBitmap` is mutably borrowed.
        let currentKeyVersion = self.keyVersion;
        self.usedLeafBitmap
            .retain(|(entryKeyVersion, _), _| *entryKeyVersion == currentKeyVersion);
        // Reset per-key stateless usage accounting only when the caller rotates the
        // stateless key too.
        if resetStatelessUsage {
            self.statelessSignaturesUsed = 0;
        }
        // Reset stateful signing to the first leaf of the new key epoch.
        self.nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
        // Fresh key epochs allow policy selection again until the first stateful leaf is consumed.
        self.statefulPolicyFrozen = false;
        // Fresh installs return to the default safe wrapper policy.
        self.statefulPolicy = StatefulPolicy::MonotonicIndex;
        // Recovery mode ends once the new key has been installed.
        self.recoveryMode = false;
        // Emit rotation then policy-reset events for off-chain observers, in the
        // same order as Solidity. keyVersion is the post-increment value.
        self.emit(AccountEvent::KeyRotated {
            previousShrincsPublicKey,
            nextShrincsPublicKey: nextCompositePublicKey,
            nextKeyVersion: self.keyVersion,
        });
        self.emit(AccountEvent::StatefulPolicySet {
            policy: self.statefulPolicy,
            nextStatefulLeafIndex: self.nextStatefulLeafIndex,
        });
    }

    fn onlyOwner(&self, caller: [u8; HASH_LEN]) -> Result<(), AccountError> {
        if caller != self.owner {
            return Err(AccountError::OnlyOwner);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U256([u64; 4]);

impl U256 {
    fn bit(&self, bitIndex: u32) -> bool {
        // Callers derive bitIndex as `leafIndex & 0xff`, so it is always < 256; this
        // guard turns a would-be out-of-bounds limb index into a clear debug failure.
        debug_assert!(bitIndex < 256, "bitIndex {bitIndex} must be < 256");
        let limb = (bitIndex / 64) as usize;
        let offset = bitIndex % 64;
        (self.0[limb] & (1u64 << offset)) != 0
    }

    fn set_bit(&mut self, bitIndex: u32) {
        debug_assert!(bitIndex < 256, "bitIndex {bitIndex} must be < 256");
        let limb = (bitIndex / 64) as usize;
        let offset = bitIndex % 64;
        self.0[limb] |= 1u64 << offset;
    }
}

fn increment_u256_be(value: &mut [u8; HASH_LEN]) {
    // Solidity uint256 values are encoded big-endian in the Rust verifier.
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
    use std::sync::OnceLock;

    use crate::shrincs::ShrincsSigningKey;
    use crate::shrincs::test_fixtures::{
        account_cases_fixture_path, fixture_entry_opt, fixture_pair, fixture_path,
        load_account_cases_fixture_file, load_fixture_file, write_account_cases_fixture_file,
        AccountFullRotationCaseDto, AccountSignatureFixtureFile,
        AccountStatefulRotationCaseDto, AccountStatelessActionCaseDto,
        AccountWrongKeyStatelessActionCaseDto, KeyFixtureFile, TestKeyMode,
    };
    use crate::shrincs::{
        ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey as SignerPublicKey,
        ShrincsSigner, StatefulSignature as SignerStatefulSignature,
        StatelessSignature as SignerStatelessSignature, WotsCSignature,
    };
    fn id(byte: u8) -> [u8; HASH_LEN] {
        [byte; HASH_LEN]
    }

    fn address(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn to_public_key(input: &SignerPublicKey) -> PublicKey {
        PublicKey {
            stateful_public_key: input.stateful_public_key.clone(),
            public_key_commitment: input.public_key_commitment.clone(),
            pk_seed: input.pk_seed.clone(),
            hypertree_root: input.hypertree_root.clone(),
        }
    }

    fn to_stateful_signature(input: &SignerStatefulSignature) -> StatefulSignature {
        StatefulSignature {
            randomizer: input.randomizer,
            counter: input.counter,
            chains: input.chains.clone(),
            auth_path: input.auth_path.clone(),
        }
    }

    fn to_stateless_signature(input: &SignerStatelessSignature) -> StatelessSignature {
        StatelessSignature {
            fors: ForsSignature {
                randomizer: input.fors.randomizer,
                counter: input.fors.counter,
                entries: input
                    .fors
                    .entries
                    .iter()
                    .map(|entry| ForsEntry {
                        secret_leaf: entry.secret_leaf,
                        auth_path: entry.auth_path.clone(),
                    })
                    .collect(),
            },
            hypertree: input
                .hypertree
                .iter()
                .map(|layer| HypertreeLayerSignature {
                    wots_c_pk_hash: layer.wots_c_pk_hash,
                    wots_c_signature: WotsCSignature {
                        randomizer: layer.wots_c_signature.randomizer,
                        counter: layer.wots_c_signature.counter,
                        chains: layer.wots_c_signature.chains.clone(),
                    },
                    auth_path: layer.auth_path.clone(),
                })
                .collect(),
        }
    }

    fn public_key_commitment(
        stateful_public_key: &[u8],
        pk_seed: &[u8],
        hypertree_root: &[u8],
    ) -> [u8; HASH_LEN] {
        let mut packed = Vec::new();
        packed.extend_from_slice(b"shrincs-public-key/");
        packed.extend_from_slice(crate::shrincs::PROFILE_NAME.as_bytes());
        packed.extend_from_slice(stateful_public_key);
        packed.extend_from_slice(pk_seed);
        packed.extend_from_slice(hypertree_root);
        super::keccak256_hash(&packed)
    }

    fn expected_key(public_key: &PublicKey) -> [u8; HASH_LEN] {
        public_key.public_key_commitment.clone().try_into().unwrap()
    }

    use crate::test_support::stateful_only_key;


    fn fixture_or_fresh_key(seed_label: &'static str, max: u32) -> (ShrincsSigningKey, SignerPublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => ShrincsSigner::keygen(seed_label.as_bytes(), max)
                .unwrap_or_else(|| panic!("fresh keygen failed for seed label {seed_label:?}")),
            TestKeyMode::Fixture => cached_fixture_file()
                .and_then(|fixture_file| fixture_entry_opt(fixture_file, seed_label))
                .map(fixture_pair)
                .unwrap_or_else(|| {
                    ShrincsSigner::keygen(seed_label.as_bytes(), max).unwrap_or_else(|| {
                        panic!("fresh keygen failed for seed label {seed_label:?}")
                    })
                }),
        }
    }

    fn cheap_or_fresh_stateful_key(
        seed_label: &'static str,
        max: u32,
    ) -> (ShrincsSigningKey, SignerPublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => ShrincsSigner::keygen(seed_label.as_bytes(), max)
                .unwrap_or_else(|| panic!("fresh keygen failed for seed label {seed_label:?}")),
            TestKeyMode::Fixture => cached_fixture_file()
                .and_then(|fixture_file| fixture_entry_opt(fixture_file, seed_label))
                .map(fixture_pair)
                .unwrap_or_else(|| stateful_only_key(seed_label.as_bytes(), max)),
        }
    }

    fn cached_fixture_file() -> Option<&'static KeyFixtureFile> {
        static FIXTURE_FILE: OnceLock<Option<KeyFixtureFile>> = OnceLock::new();
        FIXTURE_FILE
            .get_or_init(|| match TestKeyMode::from_env() {
                TestKeyMode::Fresh => None,
                TestKeyMode::Fixture => {
                    let path = fixture_path();
                    if !path.is_file() {
                        return None;
                    }
                    let fixture_file = load_fixture_file(&path);
                    assert_eq!(
                        fixture_file.profile_name,
                        crate::shrincs::PROFILE_NAME,
                        "fixture profile mismatch",
                    );
                    Some(fixture_file)
                }
            })
            .as_ref()
    }

    #[derive(Debug, Clone)]
    struct CachedStatelessActionCase {
        public_key: PublicKey,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: StatelessSignature,
    }

    #[derive(Debug, Clone)]
    struct CachedStatefulRotationCase {
        public_key: PublicKey,
        next_target: StatefulRotationTarget,
        next_commitment: [u8; HASH_LEN],
        signature: StatelessSignature,
    }

    #[derive(Debug, Clone)]
    struct CachedFullRotationCase {
        public_key: PublicKey,
        next_target: RotationTarget,
        next_commitment: [u8; HASH_LEN],
        signature: StatelessSignature,
    }

    #[derive(Debug, Clone)]
    struct CachedWrongKeyStatelessActionCase {
        installed_public_key: PublicKey,
        signing_public_key: PublicKey,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: StatelessSignature,
    }

    #[derive(Debug, Clone)]
    struct CachedAccountSignatureFixtures {
        stateless_action: CachedStatelessActionCase,
        rotate_stateful: CachedStatefulRotationCase,
        rotate_stateful_boundary: CachedStatefulRotationCase,
        rotate_stateful_tamper: CachedStatefulRotationCase,
        rotate_full: CachedFullRotationCase,
        rotate_full_same_stateless: CachedFullRotationCase,
        stateless_tamper: CachedStatelessActionCase,
        stateless_wrong_key: CachedWrongKeyStatelessActionCase,
    }

    impl From<AccountStatelessActionCaseDto> for CachedStatelessActionCase {
        fn from(value: AccountStatelessActionCaseDto) -> Self {
            Self {
                public_key: value.public_key.into(),
                action_type: value.action_type,
                payload_hash: value.payload_hash,
                signature: value.signature.into(),
            }
        }
    }

    impl From<&CachedStatelessActionCase> for AccountStatelessActionCaseDto {
        fn from(value: &CachedStatelessActionCase) -> Self {
            Self {
                public_key: (&value.public_key).into(),
                action_type: value.action_type,
                payload_hash: value.payload_hash,
                signature: (&value.signature).into(),
            }
        }
    }

    impl From<AccountStatefulRotationCaseDto> for CachedStatefulRotationCase {
        fn from(value: AccountStatefulRotationCaseDto) -> Self {
            Self {
                public_key: value.public_key.into(),
                next_target: value.next_target.into(),
                next_commitment: value.next_commitment,
                signature: value.signature.into(),
            }
        }
    }

    impl From<&CachedStatefulRotationCase> for AccountStatefulRotationCaseDto {
        fn from(value: &CachedStatefulRotationCase) -> Self {
            Self {
                public_key: (&value.public_key).into(),
                next_target: (&value.next_target).into(),
                next_commitment: value.next_commitment,
                signature: (&value.signature).into(),
            }
        }
    }

    impl From<AccountFullRotationCaseDto> for CachedFullRotationCase {
        fn from(value: AccountFullRotationCaseDto) -> Self {
            Self {
                public_key: value.public_key.into(),
                next_target: value.next_target.into(),
                next_commitment: value.next_commitment,
                signature: value.signature.into(),
            }
        }
    }

    impl From<&CachedFullRotationCase> for AccountFullRotationCaseDto {
        fn from(value: &CachedFullRotationCase) -> Self {
            Self {
                public_key: (&value.public_key).into(),
                next_target: (&value.next_target).into(),
                next_commitment: value.next_commitment,
                signature: (&value.signature).into(),
            }
        }
    }

    impl From<AccountWrongKeyStatelessActionCaseDto> for CachedWrongKeyStatelessActionCase {
        fn from(value: AccountWrongKeyStatelessActionCaseDto) -> Self {
            Self {
                installed_public_key: value.installed_public_key.into(),
                signing_public_key: value.signing_public_key.into(),
                action_type: value.action_type,
                payload_hash: value.payload_hash,
                signature: value.signature.into(),
            }
        }
    }

    impl From<&CachedWrongKeyStatelessActionCase> for AccountWrongKeyStatelessActionCaseDto {
        fn from(value: &CachedWrongKeyStatelessActionCase) -> Self {
            Self {
                installed_public_key: (&value.installed_public_key).into(),
                signing_public_key: (&value.signing_public_key).into(),
                action_type: value.action_type,
                payload_hash: value.payload_hash,
                signature: (&value.signature).into(),
            }
        }
    }

    fn build_account_signature_fixtures_parallel() -> CachedAccountSignatureFixtures {
        std::thread::scope(|scope| {
            let stateless_action = scope.spawn(|| {
                build_cached_stateless_action_case(
                    "account stateless action seed",
                    4,
                    [5u8; HASH_LEN],
                    [6u8; HASH_LEN],
                )
            });
            let rotate_stateful = scope.spawn(|| {
                build_cached_stateful_rotation_case(
                    "account rotate stateful current seed",
                    4,
                    "account rotate stateful next seed",
                    8,
                )
            });
            let rotate_stateful_boundary = scope.spawn(|| {
                build_cached_stateful_rotation_case(
                    "account boundary rotate seed",
                    4,
                    "account boundary rotate next seed",
                    8,
                )
            });
            let rotate_stateful_tamper = scope.spawn(|| {
                build_cached_stateful_rotation_case(
                    "account rotate tamper current seed",
                    4,
                    "account rotate tamper next seed",
                    8,
                )
            });
            let rotate_full = scope.spawn(|| {
                build_cached_full_rotation_case(
                    "account rotate full current seed",
                    4,
                    "account rotate full next seed",
                    8,
                    false,
                )
            });
            let rotate_full_same_stateless = scope.spawn(|| {
                build_cached_full_rotation_case(
                    "account same stateless rotate seed",
                    4,
                    "account same stateless rotate next seed",
                    8,
                    true,
                )
            });
            let stateless_tamper = scope.spawn(|| {
                build_cached_stateless_action_case(
                    "account stateless tamper seed",
                    4,
                    [5u8; HASH_LEN],
                    [6u8; HASH_LEN],
                )
            });
            let stateless_wrong_key =
                scope.spawn(build_cached_wrong_key_stateless_action_case);

            CachedAccountSignatureFixtures {
                stateless_action: stateless_action.join().unwrap(),
                rotate_stateful: rotate_stateful.join().unwrap(),
                rotate_stateful_boundary: rotate_stateful_boundary.join().unwrap(),
                rotate_stateful_tamper: rotate_stateful_tamper.join().unwrap(),
                rotate_full: rotate_full.join().unwrap(),
                rotate_full_same_stateless: rotate_full_same_stateless.join().unwrap(),
                stateless_tamper: stateless_tamper.join().unwrap(),
                stateless_wrong_key: stateless_wrong_key.join().unwrap(),
            }
        })
    }

    fn cached_account_signature_fixtures() -> &'static CachedAccountSignatureFixtures {
        static FIXTURES: OnceLock<CachedAccountSignatureFixtures> = OnceLock::new();
        FIXTURES.get_or_init(|| {
            let path = account_cases_fixture_path();
            if path.is_file() {
                let fixture_file = load_account_cases_fixture_file(&path);
                assert_eq!(
                    fixture_file.profile_name,
                    crate::shrincs::PROFILE_NAME,
                    "account signature fixture profile mismatch",
                );
                CachedAccountSignatureFixtures {
                    stateless_action: fixture_file.stateless_action.into(),
                    rotate_stateful: fixture_file.rotate_stateful.into(),
                    rotate_stateful_boundary: fixture_file.rotate_stateful_boundary.into(),
                    rotate_stateful_tamper: fixture_file.rotate_stateful_tamper.into(),
                    rotate_full: fixture_file.rotate_full.into(),
                    rotate_full_same_stateless: fixture_file.rotate_full_same_stateless.into(),
                    stateless_tamper: fixture_file.stateless_tamper.into(),
                    stateless_wrong_key: fixture_file.stateless_wrong_key.into(),
                }
            } else {
                build_account_signature_fixtures_parallel()
            }
        })
    }

    fn build_cached_stateless_action_case(
        seed_label: &'static str,
        max: u32,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
    ) -> CachedStatelessActionCase {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = fixture_or_fresh_key(seed_label, max);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateless_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        CachedStatelessActionCase {
            public_key,
            action_type,
            payload_hash,
            signature: to_stateless_signature(&signature),
        }
    }

    fn build_cached_stateful_rotation_case(
        current_seed: &'static str,
        current_max: u32,
        next_seed: &'static str,
        next_max: u32,
    ) -> CachedStatefulRotationCase {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = fixture_or_fresh_key(current_seed, current_max);
        let (_, next_public_key) = fixture_or_fresh_key(next_seed, next_max);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let next_commitment = public_key_commitment(
            &next_public_key.stateful_public_key,
            &public_key.pk_seed,
            &public_key.hypertree_root,
        );
        let next_target = StatefulRotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_commitment.to_vec(),
        };
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;
        let context = RotationContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
        };
        let message =
            verifier.stateful_rotation_message_hash(expected, &public_key, &context, &next_target);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        CachedStatefulRotationCase {
            public_key,
            next_target,
            next_commitment,
            signature: to_stateless_signature(&signature),
        }
    }

    fn build_cached_full_rotation_case(
        current_seed: &'static str,
        current_max: u32,
        next_seed: &'static str,
        next_max: u32,
        reuse_stateless_key: bool,
    ) -> CachedFullRotationCase {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = fixture_or_fresh_key(current_seed, current_max);
        let (_, next_public_key) = fixture_or_fresh_key(next_seed, next_max);
        let public_key = to_public_key(&public_key);
        let next_public_key = to_public_key(&next_public_key);
        let expected = expected_key(&public_key);
        let next_target = RotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: if reuse_stateless_key {
                public_key_commitment(
                    &next_public_key.stateful_public_key,
                    &public_key.pk_seed,
                    &public_key.hypertree_root,
                )
                .to_vec()
            } else {
                next_public_key.public_key_commitment.clone()
            },
            pk_seed: if reuse_stateless_key {
                public_key.pk_seed.clone()
            } else {
                next_public_key.pk_seed.clone()
            },
            hypertree_root: if reuse_stateless_key {
                public_key.hypertree_root.clone()
            } else {
                next_public_key.hypertree_root.clone()
            },
        };
        let next_commitment = next_target.public_key_commitment.clone().try_into().unwrap();
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;
        let context = RotationContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
        };
        let message =
            verifier.full_rotation_message_hash(expected, &public_key, &context, &next_target);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        CachedFullRotationCase {
            public_key,
            next_target,
            next_commitment,
            signature: to_stateless_signature(&signature),
        }
    }

    fn build_cached_wrong_key_stateless_action_case() -> CachedWrongKeyStatelessActionCase {
        let verifier = ShrincsVerifier::new();
        let (_, key_a) = fixture_or_fresh_key("account stateless wrong-key A", 4);
        let (signing_b, key_b) = fixture_or_fresh_key("account stateless wrong-key B", 4);
        let installed_public_key = to_public_key(&key_a);
        let signing_public_key = to_public_key(&key_b);
        let expected_a = expected_key(&installed_public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected_a);
        let action_type = [5u8; HASH_LEN];
        let payload_hash = [6u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateless_action_message_hash(expected_a, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_b, &message).unwrap();
        CachedWrongKeyStatelessActionCase {
            installed_public_key,
            signing_public_key,
            action_type,
            payload_hash,
            signature: to_stateless_signature(&signature),
        }
    }

    #[test]
    #[ignore = "writes checked-in account signature fixtures on demand"]
    fn write_account_signature_fixture_file() {
        let fixtures = build_account_signature_fixtures_parallel();
        let fixture_file = AccountSignatureFixtureFile {
            profile_name: crate::shrincs::PROFILE_NAME.to_string(),
            stateless_action: (&fixtures.stateless_action).into(),
            rotate_stateful: (&fixtures.rotate_stateful).into(),
            rotate_stateful_boundary: (&fixtures.rotate_stateful_boundary).into(),
            rotate_stateful_tamper: (&fixtures.rotate_stateful_tamper).into(),
            rotate_full: (&fixtures.rotate_full).into(),
            rotate_full_same_stateless: (&fixtures.rotate_full_same_stateless).into(),
            stateless_tamper: (&fixtures.stateless_tamper).into(),
            stateless_wrong_key: (&fixtures.stateless_wrong_key).into(),
        };
        write_account_cases_fixture_file(&account_cases_fixture_path(), &fixture_file);
    }

    #[test]
    fn initializes_account_state_with_default_policy() {
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));

        assert_eq!(account.owner(), id(1));
        assert_eq!(
            account.domainSeparator(),
            ShrincsAccountVerifierExample::computeDomainSeparator(id(2), address(7))
        );
        assert_eq!(account.currentShrincsPublicKey(), id(3));
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
        assert!(!account.statefulPolicyFrozen());
        assert_eq!(account.nextStatefulLeafIndex(), INITIAL_STATEFUL_LEAF_INDEX);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.keyVersion(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 0);
        assert!(!account.recoveryMode());
    }

    #[test]
    fn owner_gates_policy_changes_and_recovery_mode() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));

        assert_eq!(
            account.setStatefulPolicyRecoveryRotation(id(9)),
            Err(AccountError::OnlyOwner)
        );
        assert_eq!(
            account.enterRecoveryMode(id(1)),
            Err(AccountError::RecoveryPolicyRequired)
        );

        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");

        assert_eq!(account.statefulPolicy(), StatefulPolicy::RecoveryRotation);
        assert!(account.recoveryMode());
    }

    #[test]
    fn monotonic_policy_advances_and_rejects_replay() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));

        assert!(account.precheckStatefulLeafUse(1));
        account.commitStatefulLeafUse(1);
        assert_eq!(account.nextStatefulLeafIndex(), 2);
        assert!(account.statefulPolicyFrozen());
        assert!(!account.precheckStatefulLeafUse(1));
        assert!(account.precheckStatefulLeafUse(2));
    }

    #[test]
    fn bitmap_policy_marks_used_leaves_per_key_epoch() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyLeafBitmap(id(1))
            .expect("owner can select bitmap policy");

        assert!(account.precheckStatefulLeafUse(9));
        account.commitStatefulLeafUse(9);
        assert!(account.isLeafUsed(9));
        assert!(account.statefulPolicyFrozen());
        assert!(!account.precheckStatefulLeafUse(9));

        account.installRotatedKey(id(4), true);
        assert!(!account.isLeafUsed(9));
        assert!(!account.statefulPolicyFrozen());
    }

    #[test]
    fn bitmap_policy_uses_same_word_and_bit_logic_as_solidity() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyLeafBitmap(id(1))
            .expect("owner can select bitmap policy");

        account.commitStatefulLeafUse(255);
        account.commitStatefulLeafUse(256);

        assert!(account.isLeafUsed(255));
        assert!(account.isLeafUsed(256));
        assert!(account
            .usedLeafBitmap
            .contains_key(&(account.keyVersion(), 0)));
        assert!(account
            .usedLeafBitmap
            .contains_key(&(account.keyVersion(), 1)));
    }

    #[test]
    fn install_fresh_key_resets_recovery_and_usage_state() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;

        account.installRotatedKey(id(4), true);

        assert_eq!(account.currentShrincsPublicKey(), id(4));
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.keyVersion()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 0);
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
        assert!(!account.statefulPolicyFrozen());
        assert_eq!(account.nextStatefulLeafIndex(), INITIAL_STATEFUL_LEAF_INDEX);
        assert!(!account.recoveryMode());
    }

    #[test]
    fn policy_changes_freeze_after_successful_stateful_use() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));

        account.commitStatefulLeafUse(1);

        assert_eq!(
            account.setStatefulPolicyLeafBitmap(id(1)),
            Err(AccountError::StatefulPolicyFrozen)
        );
        assert_eq!(
            account.setStatefulPolicyMonotonicIndex(id(1), 5),
            Err(AccountError::StatefulPolicyFrozen)
        );
        // RecoveryRotation stays selectable so the account can always rotate out of a
        // used key; the freeze flag itself stays set until rotation.
        assert_eq!(account.setStatefulPolicyRecoveryRotation(id(1)), Ok(()));
        assert!(account.statefulPolicyFrozen());
        assert_eq!(
            account.setStatefulPolicyLeafBitmap(id(1)),
            Err(AccountError::StatefulPolicyFrozen)
        );
    }

    #[test]
    fn recovery_rotation_blocks_stateful_path_before_and_during_recovery_mode() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");

        assert!(!account.precheckStatefulLeafUse(1));

        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        assert!(!account.precheckStatefulLeafUse(1));
    }

    #[test]
    fn raw_stateful_helper_verifies_message_without_advancing_nonce() {
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account raw helper seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let message = b"account raw helper message";
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, message).unwrap();
        let signature = to_stateful_signature(&signature);

        assert!(account.verifyStatefulUncheckedMessage(&public_key, message, &signature));
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.nextStatefulLeafIndex(), 2);
    }

    #[test]
    fn verify_stateful_action_advances_nonce_and_leaf() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account stateful action seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let signature = to_stateful_signature(&signature);

        account
            .verifyStatefulAction(&public_key, action_type, payload_hash, &signature)
            .expect("valid stateful action verifies");
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.nextStatefulLeafIndex(), 2);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateless_action_advances_nonce_and_usage_counter() {
        let case = &cached_account_signature_fixtures().stateless_action;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);

        account
            .verifyStatelessAction(&public_key, case.action_type, case.payload_hash, &case.signature)
            .expect("valid stateless action verifies");
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 1);
    }

    #[test]
    fn is_valid_signature_accepts_mode_one_stateful_without_mutating_state() {
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account isValidSignature stateful seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let hash = ShrincsVerifier::new().stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash).unwrap();
        let signature = to_stateful_signature(&signature);
        let envelope_bytes = envelope::encode_stateful_1271_envelope(
            &public_key,
            action_type,
            payload_hash,
            &signature,
        );

        let before = account.clone();
        account
            .isValidSignature(hash, &envelope_bytes)
            .expect("valid mode-1 envelope must verify");
        // Read-only: no leaf commit, no nonce advance, no event emitted, no
        // other field touched.
        assert_eq!(account, before);
    }

    #[test]
    fn is_valid_signature_accepts_mode_two_stateless_without_mutating_state() {
        let case = &cached_account_signature_fixtures().stateless_action;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type: case.action_type,
            payload_hash: case.payload_hash,
        };
        let hash = ShrincsVerifier::new().stateless_action_message_hash(expected, &context);
        let envelope_bytes = envelope::encode_stateless_1271_envelope(
            &public_key,
            case.action_type,
            case.payload_hash,
            &case.signature,
        );

        let before = account.clone();
        account
            .isValidSignature(hash, &envelope_bytes)
            .expect("valid mode-2 envelope must verify");
        // Read-only: no nonce advance, no stateless-usage consumption, no
        // event emitted, no other field touched.
        assert_eq!(account, before);
    }

    #[test]
    fn is_valid_signature_rejects_a_hash_that_does_not_match_the_canonical_action_hash() {
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account isValidSignature wrong hash seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [5u8; HASH_LEN];
        let payload_hash = [6u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let hash = ShrincsVerifier::new().stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash).unwrap();
        let signature = to_stateful_signature(&signature);
        let envelope_bytes = envelope::encode_stateful_1271_envelope(
            &public_key,
            action_type,
            payload_hash,
            &signature,
        );

        let mut wrong_hash = hash;
        wrong_hash[0] ^= 0x01;
        assert_eq!(
            account.isValidSignature(wrong_hash, &envelope_bytes),
            Err(AccountError::InvalidSignature)
        );
    }

    #[test]
    fn is_valid_signature_rejects_an_unknown_mode_byte() {
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account isValidSignature unknown mode seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [7u8; HASH_LEN];
        let payload_hash = [8u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let hash = ShrincsVerifier::new().stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash).unwrap();
        let signature = to_stateful_signature(&signature);
        let mut envelope_bytes = envelope::encode_stateful_1271_envelope(
            &public_key,
            action_type,
            payload_hash,
            &signature,
        );
        envelope_bytes[0] = 0x03;

        assert_eq!(
            account.isValidSignature(hash, &envelope_bytes),
            Err(AccountError::MalformedSignature)
        );
    }

    #[test]
    fn is_valid_signature_rejects_an_empty_envelope() {
        let expected = id(9);
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        assert_eq!(
            account.isValidSignature([0u8; HASH_LEN], &[]),
            Err(AccountError::MalformedSignature)
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_to_fresh_key_installs_next_stateful_commitment() {
        let case = &cached_account_signature_fixtures().rotate_stateful;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;

        account
            .rotateToFreshKey(&public_key, &case.signature, &case.next_target)
            .expect("valid stateful rotation succeeds");
        assert_eq!(account.currentShrincsPublicKey(), case.next_commitment);
        assert_eq!(account.keyVersion()[HASH_LEN - 1], 1);
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 8);
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
        assert!(!account.statefulPolicyFrozen());
        assert!(!account.recoveryMode());
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_full_key_installs_next_full_commitment() {
        let case = &cached_account_signature_fixtures().rotate_full;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;

        account
            .rotateFullKey(&public_key, &case.signature, &case.next_target)
            .expect("valid full rotation succeeds");
        assert_eq!(account.currentShrincsPublicKey(), case.next_commitment);
        assert_eq!(account.keyVersion()[HASH_LEN - 1], 1);
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 0);
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
        assert!(!account.statefulPolicyFrozen());
        assert!(!account.recoveryMode());
    }

    // A structurally valid but never-verifiable signature for exercising gates that
    // reject before any cryptographic work happens.
    fn empty_stateless_signature() -> StatelessSignature {
        StatelessSignature {
            fors: crate::shrincs::ForsSignature {
                randomizer: [0u8; 32],
                counter: 0,
                entries: Vec::new(),
            },
            hypertree: Vec::new(),
        }
    }

    #[test]
    fn failed_stateful_verification_does_not_freeze_policy() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account failed stateful freeze seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let mut signature = to_stateful_signature(&signature);
        // Corrupt the signature so verification fails after the policy precheck passes.
        signature.chains[0][0] ^= 0x01;

        assert_eq!(
            account.verifyStatefulAction(&public_key, action_type, payload_hash, &signature),
            Err(AccountError::InvalidSignature)
        );
        // A failed verification must leave all policy and freshness state untouched.
        assert!(!account.statefulPolicyFrozen());
        assert_eq!(account.nextStatefulLeafIndex(), INITIAL_STATEFUL_LEAF_INDEX);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(
            account.setStatefulPolicyLeafBitmap(id(1)),
            Ok(()),
            "policy changes must remain available after a failed verification",
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn recovery_rotation_remains_reachable_after_stateful_use() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            fixture_or_fresh_key("account recovery after use seed", 4);
        let (_, next_public_key) =
            fixture_or_fresh_key("account recovery after use next seed", 8);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);

        // Consume one stateful leaf through real verification, freezing leaf-tracking changes.
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let signature = to_stateful_signature(&signature);
        account
            .verifyStatefulAction(&public_key, action_type, payload_hash, &signature)
            .expect("valid stateful action verifies");
        assert!(account.statefulPolicyFrozen());

        // The recovery/rotation path must stay reachable — otherwise a used key could
        // never rotate again and the account would be permanently stuck.
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("recovery policy must remain selectable after stateful use");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");

        let next_commitment = public_key_commitment(
            &next_public_key.stateful_public_key,
            &public_key.pk_seed,
            &public_key.hypertree_root,
        );
        let next_target = StatefulRotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_commitment.to_vec(),
        };
        let rotation_context = RotationContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
        };
        let rotation_message = verifier.stateful_rotation_message_hash(
            expected,
            &public_key,
            &rotation_context,
            &next_target,
        );
        let rotation_signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &rotation_message).unwrap();
        let rotation_signature = to_stateless_signature(&rotation_signature);

        account
            .rotateToFreshKey(&public_key, &rotation_signature, &next_target)
            .expect("recovery rotation succeeds after stateful use");
        assert_eq!(account.currentShrincsPublicKey(), next_commitment);
        assert!(!account.statefulPolicyFrozen());
    }

    #[test]
    fn stateless_action_blocked_under_unarmed_recovery_policy() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");

        // The policy gate rejects before any cryptographic work, so a dummy signature suffices.
        assert_eq!(
            account.verifyStatelessAction(
                &PublicKey {
                    stateful_public_key: Vec::new(),
                    public_key_commitment: Vec::new(),
                    pk_seed: Vec::new(),
                    hypertree_root: Vec::new(),
                },
                [5u8; HASH_LEN],
                [6u8; HASH_LEN],
                &empty_stateless_signature(),
            ),
            Err(AccountError::RecoveryNotArmed)
        );
    }

    #[test]
    fn rotations_and_stateless_actions_blocked_at_stateless_budget_limit() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = STATELESS_SIGNATURE_LIMIT;

        let dummy_public_key = PublicKey {
            stateful_public_key: Vec::new(),
            public_key_commitment: Vec::new(),
            pk_seed: Vec::new(),
            hypertree_root: Vec::new(),
        };
        // All budget gates reject before verification, so dummy inputs suffice.
        assert_eq!(
            account.rotateToFreshKey(
                &dummy_public_key,
                &empty_stateless_signature(),
                &StatefulRotationTarget {
                    stateful_public_key: Vec::new(),
                    public_key_commitment: Vec::new(),
                },
            ),
            Err(AccountError::BudgetExhausted)
        );
        assert_eq!(
            account.rotateFullKey(
                &dummy_public_key,
                &empty_stateless_signature(),
                &RotationTarget {
                    stateful_public_key: Vec::new(),
                    public_key_commitment: Vec::new(),
                    pk_seed: Vec::new(),
                    hypertree_root: Vec::new(),
                },
            ),
            Err(AccountError::BudgetExhausted)
        );
        assert_eq!(
            account.verifyStatelessAction(
                &dummy_public_key,
                [5u8; HASH_LEN],
                [6u8; HASH_LEN],
                &empty_stateless_signature(),
            ),
            Err(AccountError::BudgetExhausted)
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn stateful_only_rotation_at_budget_boundary_lands_exhausted() {
        let case = &cached_account_signature_fixtures().rotate_stateful_boundary;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = STATELESS_SIGNATURE_LIMIT - 1;

        // The final budgeted stateless use may fund a stateful-only rotation...
        account
            .rotateToFreshKey(&public_key, &case.signature, &case.next_target)
            .expect("final budgeted stateless use funds the rotation");
        // ...but the preserved counter lands the new epoch exhausted: the unchanged
        // stateless key has no remaining budget, so no stateless path remains.
        assert_eq!(account.statelessSignaturesUsed(), STATELESS_SIGNATURE_LIMIT);
        assert_eq!(
            account.verifyStatelessAction(
                &public_key,
                [5u8; HASH_LEN],
                [6u8; HASH_LEN],
                &empty_stateless_signature(),
            ),
            Err(AccountError::BudgetExhausted)
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn full_rotation_with_unchanged_stateless_key_preserves_usage() {
        let case = &cached_account_signature_fixtures().rotate_full_same_stateless;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;

        account
            .rotateFullKey(&public_key, &case.signature, &case.next_target)
            .expect("full rotation with unchanged stateless key succeeds");
        assert_eq!(account.currentShrincsPublicKey(), case.next_commitment);
        // The stateless key did not change, so its usage budget must NOT be refreshed.
        assert_eq!(account.statelessSignaturesUsed(), 8);
    }

    #[test]
    fn increment_u256_be_carries_across_byte_boundaries() {
        // 0 -> 1 in the least-significant byte.
        let mut value = [0u8; HASH_LEN];
        increment_u256_be(&mut value);
        let mut expected = [0u8; HASH_LEN];
        expected[HASH_LEN - 1] = 1;
        assert_eq!(value, expected);

        // 0x..00ff -> 0x..0100: carry propagates into the next byte, matching
        // Solidity uint256 addition semantics.
        let mut value = [0u8; HASH_LEN];
        value[HASH_LEN - 1] = 0xff;
        increment_u256_be(&mut value);
        let mut expected = [0u8; HASH_LEN];
        expected[HASH_LEN - 2] = 1;
        assert_eq!(value, expected);

        // Full-width carry: all-ones wraps to zero (uint256 overflow wrap).
        let mut value = [0xffu8; HASH_LEN];
        increment_u256_be(&mut value);
        assert_eq!(value, [0u8; HASH_LEN]);
    }

    #[test]
    fn verify_stateful_action_rejects_wrong_public_key() {
        // Install key A, then present a different, fully valid key B (with a
        // genuine B-signed action over the account's canonical message). The
        // account must reject it because B's commitment != the installed key,
        // and no freshness state may advance.
        let verifier = ShrincsVerifier::new();
        let (_, key_a) = cheap_or_fresh_stateful_key("account wrong-key installed A", 4);
        let (mut signing_b, key_b) =
            cheap_or_fresh_stateful_key("account wrong-key attacker B", 4);
        let key_a = to_public_key(&key_a);
        let key_b = to_public_key(&key_b);
        let expected_a = expected_key(&key_a);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected_a);
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        // Sign the account's canonical message with B's key: cryptographically
        // valid under B, but B is not the installed key.
        let message = verifier.stateful_action_message_hash(expected_a, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_b, &message).unwrap();
        let signature = to_stateful_signature(&signature);

        assert_eq!(
            account.verifyStatefulAction(&key_b, action_type, payload_hash, &signature),
            Err(AccountError::InvalidSignature)
        );
        assert_eq!(account.currentShrincsPublicKey(), expected_a);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.nextStatefulLeafIndex(), INITIAL_STATEFUL_LEAF_INDEX);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_to_fresh_key_rejects_tampered_recovery_signature() {
        // A recovery rotation with a corrupted stateless signature must fail and
        // leave every piece of account state untouched (no key install, no nonce
        // or key-version advance, no stateless-usage consumption).
        let case = &cached_account_signature_fixtures().rotate_stateful_tamper;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner can select recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner can arm recovery mode");
        account.statelessSignaturesUsed = 7;
        let mut signature = case.signature.clone();
        // Corrupt the recovery signature so FORS-C verification fails.
        signature.fors.randomizer[0] ^= 0xff;

        assert_eq!(
            account.rotateToFreshKey(&public_key, &signature, &case.next_target),
            Err(AccountError::InvalidSignature)
        );
        assert_eq!(account.currentShrincsPublicKey(), expected);
        assert_eq!(account.keyVersion(), [0u8; HASH_LEN]);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 7);
        assert!(account.recoveryMode());
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateless_action_rejects_tampered_signature() {
        // A stateless action with a corrupted signature must fail with a distinct
        // InvalidSignature and leave the nonce and stateless-usage counter untouched.
        let case = &cached_account_signature_fixtures().stateless_tamper;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let mut signature = case.signature.clone();
        // Corrupt the FORS randomizer so verification fails after the policy gates pass.
        signature.fors.randomizer[0] ^= 0xff;

        assert_eq!(
            account.verifyStatelessAction(&public_key, case.action_type, case.payload_hash, &signature),
            Err(AccountError::InvalidSignature)
        );
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateless_action_rejects_wrong_public_key() {
        // Present a fully valid key-B stateless signature over the account's canonical
        // message while key A is installed. The account must reject (B's commitment is
        // not the installed key) and advance no freshness or usage state.
        let case = &cached_account_signature_fixtures().stateless_wrong_key;
        let expected_a = expected_key(&case.installed_public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected_a);

        assert_eq!(
            account.verifyStatelessAction(
                &case.signing_public_key,
                case.action_type,
                case.payload_hash,
                &case.signature,
            ),
            Err(AccountError::InvalidSignature)
        );
        assert_eq!(account.currentShrincsPublicKey(), expected_a);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }

    fn key_version_one() -> [u8; HASH_LEN] {
        let mut kv = [0u8; HASH_LEN];
        kv[HASH_LEN - 1] = 1;
        kv
    }

    #[test]
    fn policy_setters_emit_stateful_policy_set_with_new_values() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));

        // The constructor must not emit (Solidity's constructor emits nothing).
        assert!(account.events().is_empty());

        account
            .setStatefulPolicyMonotonicIndex(id(1), 5)
            .expect("owner sets monotonic policy");
        account
            .setStatefulPolicyLeafBitmap(id(1))
            .expect("owner sets bitmap policy");
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner sets recovery policy");

        assert_eq!(
            account.drain_events(),
            vec![
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::MonotonicIndex,
                    nextStatefulLeafIndex: 5,
                },
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::LeafBitmap,
                    nextStatefulLeafIndex: 5,
                },
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::RecoveryRotation,
                    nextStatefulLeafIndex: 5,
                },
            ],
        );
        // drain_events clears the log.
        assert!(account.events().is_empty());
    }

    #[test]
    fn enter_recovery_mode_emits_recovery_entered_after_policy_set() {
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3));
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner sets recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner arms recovery mode");

        assert_eq!(
            account.drain_events(),
            vec![
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::RecoveryRotation,
                    nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
                },
                AccountEvent::RecoveryModeEntered {
                    keyVersion: [0u8; HASH_LEN],
                },
            ],
        );
    }

    #[test]
    fn verify_stateful_action_emits_signature_verified_with_consumed_nonce() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            cheap_or_fresh_stateful_key("account stateful event seed", 4);
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [3u8; HASH_LEN];
        let payload_hash = [4u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let signature = to_stateful_signature(&signature);

        account
            .verifyStatefulAction(&public_key, action_type, payload_hash, &signature)
            .expect("valid stateful action verifies");

        // Emitted before the nonce advance: the consumed nonce is the pre-increment 0.
        assert_eq!(
            account.drain_events(),
            vec![AccountEvent::StatefulSignatureVerified {
                leafIndex: 1,
                nonce: [0u8; HASH_LEN],
                keyVersion: [0u8; HASH_LEN],
            }],
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateless_action_emits_signature_verified_with_consumed_nonce() {
        let case = &cached_account_signature_fixtures().stateless_action;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);

        account
            .verifyStatelessAction(&public_key, case.action_type, case.payload_hash, &case.signature)
            .expect("valid stateless action verifies");

        // Post-increment usage count (1) paired with the pre-increment consumed nonce (0).
        assert_eq!(
            account.drain_events(),
            vec![AccountEvent::StatelessSignatureVerified {
                usedCount: 1,
                nonce: [0u8; HASH_LEN],
                keyVersion: [0u8; HASH_LEN],
            }],
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_to_fresh_key_emits_consumed_then_rotated_then_policy_set() {
        let case = &cached_account_signature_fixtures().rotate_stateful;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner sets recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner arms recovery mode");
        account.statelessSignaturesUsed = 7;
        // Clear the setup events so only the rotation trail remains.
        account.drain_events();

        account
            .rotateToFreshKey(&public_key, &case.signature, &case.next_target)
            .expect("valid stateful rotation succeeds");

        assert_eq!(
            account.drain_events(),
            vec![
                AccountEvent::StatelessRotationConsumed {
                    usedCount: 8,
                    nonce: [0u8; HASH_LEN],
                    keyVersion: [0u8; HASH_LEN],
                    nextShrincsPublicKey: case.next_commitment,
                    fullRotation: false,
                },
                AccountEvent::KeyRotated {
                    previousShrincsPublicKey: expected,
                    nextShrincsPublicKey: case.next_commitment,
                    nextKeyVersion: key_version_one(),
                },
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::MonotonicIndex,
                    nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
                },
            ],
        );
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_full_key_emits_consumed_then_rotated_then_policy_set() {
        let case = &cached_account_signature_fixtures().rotate_full;
        let public_key = case.public_key.clone();
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        account
            .setStatefulPolicyRecoveryRotation(id(1))
            .expect("owner sets recovery policy");
        account
            .enterRecoveryMode(id(1))
            .expect("owner arms recovery mode");
        account.statelessSignaturesUsed = 7;
        // Clear the setup events so only the rotation trail remains.
        account.drain_events();

        account
            .rotateFullKey(&public_key, &case.signature, &case.next_target)
            .expect("valid full rotation succeeds");

        // usedCount is the pre-reset count (8): consumeStatelessRotationUse emits before
        // installFreshFullKey clears the budget. fullRotation is always true here.
        assert_eq!(
            account.drain_events(),
            vec![
                AccountEvent::StatelessRotationConsumed {
                    usedCount: 8,
                    nonce: [0u8; HASH_LEN],
                    keyVersion: [0u8; HASH_LEN],
                    nextShrincsPublicKey: case.next_commitment,
                    fullRotation: true,
                },
                AccountEvent::KeyRotated {
                    previousShrincsPublicKey: expected,
                    nextShrincsPublicKey: case.next_commitment,
                    nextKeyVersion: key_version_one(),
                },
                AccountEvent::StatefulPolicySet {
                    policy: StatefulPolicy::MonotonicIndex,
                    nextStatefulLeafIndex: INITIAL_STATEFUL_LEAF_INDEX,
                },
            ],
        );
        // The install reset the stateless budget after the event captured the pre-reset count.
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }

    #[test]
    fn rotation_prunes_previous_epoch_bitmap_entries() {
        // Bitmap leaf-use memory is scoped to a key epoch; a rotation must drop
        // every entry belonging to the old keyVersion so the map cannot grow
        // without bound across repeated rotations.
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(3), id(4));
        account
            .setStatefulPolicyLeafBitmap(id(1))
            .expect("owner selects bitmap policy");

        // Record two leaves in distinct 256-leaf words under the epoch-0 key.
        account.commitStatefulLeafUse(5);
        account.commitStatefulLeafUse(300);
        assert!(account.isLeafUsed(5));
        assert!(account.isLeafUsed(300));
        assert_eq!(account.usedLeafBitmap.len(), 2);
        let epoch_zero_key_version = account.keyVersion;

        // A rotation advances the key epoch and must clear the old entries.
        account.installRotatedKey(id(9), true);
        assert_ne!(account.keyVersion, epoch_zero_key_version);
        assert!(
            account.usedLeafBitmap.is_empty(),
            "old-epoch bitmap entries must be pruned on rotation",
        );
        // The freshly rotated epoch sees those leaves as unused again.
        assert!(!account.isLeafUsed(5));
        assert!(!account.isLeafUsed(300));
    }
}
