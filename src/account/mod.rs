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

// This module is a line-by-line port of the Solidity account wrapper. Identifiers
// (methods, fields, locals) intentionally mirror the Solidity camelCase names so the
// two implementations can be cross-read and audited against each other.
#![allow(non_snake_case)]

use std::collections::HashMap;

use solana_program::keccak::hash as keccak256_hash;

use crate::shrincs::{
    ActionContext, PublicKey, RotationContext, RotationTarget, ShrincsVerifier,
    StatefulRotationTarget, StatefulSignature, StatelessSignature, HASH_LEN,
    STATELESS_SIGNATURE_LIMIT,
};

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
        // Solidity emits StatefulSignatureVerified here; Rust returns the boolean result.
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
        // Solidity emits before nonce advancement so observers see the consumed nonce value.
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

        // Advance wrapper freshness and stateless usage state after success.
        increment_u256_be(&mut self.nonce);
        self.statelessSignaturesUsed += 1;
        // Solidity emits the consumed nonce value from the pre-increment state.
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
        let DOMAIN_TAG = keccak256_hash(DOMAIN_TAG_MESSAGE).to_bytes();
        // Solidity abi.encode(bytes32,uint256,address) writes three 32-byte words.
        let mut encoded = Vec::with_capacity(HASH_LEN * 3);
        encoded.extend_from_slice(&DOMAIN_TAG);
        encoded.extend_from_slice(&chainId);
        // ABI-encoded address values are left-padded to one 32-byte word.
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(&contractAddress);
        keccak256_hash(&encoded).to_bytes()
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
        // Install the next trusted SHRINCS public-key commitment.
        self.currentShrincsPublicKey = nextCompositePublicKey;
        // Advance nonce and key epoch so old authorizations cannot be replayed.
        increment_u256_be(&mut self.nonce);
        increment_u256_be(&mut self.keyVersion);
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
    use crate::shrincs::signer::verifier::{
        PublicKey as SignerPublicKey, StatefulSignature as SignerStatefulSignature,
        StatelessSignature as SignerStatelessSignature,
    };
    use crate::shrincs::ShrincsSigner;
    use crate::shrincs::{ForsEntry, ForsSignature, HypertreeLayerSignature, WotsCSignature};
    use solana_program::keccak::hash as keccak256_hash;

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
                randomizer: input.fors.randomizer.clone(),
                counter: input.fors.counter,
                entries: input
                    .fors
                    .entries
                    .iter()
                    .map(|entry| ForsEntry {
                        secret_leaf: entry.secret_leaf.clone(),
                        auth_path: entry.auth_path.clone(),
                    })
                    .collect(),
            },
            hypertree: input
                .hypertree
                .iter()
                .map(|layer| HypertreeLayerSignature {
                    wots_c_pk_hash: layer.wots_c_pk_hash.clone(),
                    wots_c_signature: WotsCSignature {
                        randomizer: layer.wots_c_signature.randomizer.clone(),
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
        keccak256_hash(&packed).to_bytes()
    }

    fn expected_key(public_key: &PublicKey) -> [u8; HASH_LEN] {
        public_key.public_key_commitment.clone().try_into().unwrap()
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

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn raw_stateful_helper_verifies_message_without_advancing_nonce() {
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"account raw helper seed", 4).unwrap();
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

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateful_action_advances_nonce_and_leaf() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"account stateful action seed", 4).unwrap();
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account stateless action seed", 4).unwrap();
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [5u8; HASH_LEN];
        let payload_hash = [6u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateless_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        account
            .verifyStatelessAction(&public_key, action_type, payload_hash, &signature)
            .expect("valid stateless action verifies");
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 1);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn rotate_to_fresh_key_installs_next_stateful_commitment() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account rotate stateful current seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account rotate stateful next seed", 8).unwrap();
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
        let signature = to_stateless_signature(&signature);

        account
            .rotateToFreshKey(&public_key, &signature, &next_target)
            .expect("valid stateful rotation succeeds");
        assert_eq!(account.currentShrincsPublicKey(), next_commitment);
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account rotate full current seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account rotate full next seed", 8).unwrap();
        let public_key = to_public_key(&public_key);
        let next_public_key = to_public_key(&next_public_key);
        let expected = expected_key(&public_key);
        let next_commitment = expected_key(&next_public_key);
        let next_target = RotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_public_key.public_key_commitment.clone(),
            pk_seed: next_public_key.pk_seed.clone(),
            hypertree_root: next_public_key.hypertree_root.clone(),
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
            verifier.full_rotation_message_hash(expected, &public_key, &context, &next_target);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        account
            .rotateFullKey(&public_key, &signature, &next_target)
            .expect("valid full rotation succeeds");
        assert_eq!(account.currentShrincsPublicKey(), next_commitment);
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
                randomizer: Vec::new(),
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
            ShrincsSigner::keygen(b"account failed stateful freeze seed", 4).unwrap();
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
            ShrincsSigner::keygen(b"account recovery after use seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account recovery after use next seed", 8).unwrap();
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account boundary rotate seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account boundary rotate next seed", 8).unwrap();
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
        account.statelessSignaturesUsed = STATELESS_SIGNATURE_LIMIT - 1;
        let context = RotationContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
        };
        let message =
            verifier.stateful_rotation_message_hash(expected, &public_key, &context, &next_target);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        // The final budgeted stateless use may fund a stateful-only rotation...
        account
            .rotateToFreshKey(&public_key, &signature, &next_target)
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account same stateless rotate seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account same stateless rotate next seed", 8).unwrap();
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        // Rotation target that installs a fresh stateful subkey but reuses the current
        // stateless key material.
        let next_commitment = public_key_commitment(
            &next_public_key.stateful_public_key,
            &public_key.pk_seed,
            &public_key.hypertree_root,
        );
        let next_target = RotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_commitment.to_vec(),
            pk_seed: public_key.pk_seed.clone(),
            hypertree_root: public_key.hypertree_root.clone(),
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
            verifier.full_rotation_message_hash(expected, &public_key, &context, &next_target);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        account
            .rotateFullKey(&public_key, &signature, &next_target)
            .expect("full rotation with unchanged stateless key succeeds");
        assert_eq!(account.currentShrincsPublicKey(), next_commitment);
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

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn verify_stateful_action_rejects_wrong_public_key() {
        // Install key A, then present a different, fully valid key B (with a
        // genuine B-signed action over the account's canonical message). The
        // account must reject it because B's commitment != the installed key,
        // and no freshness state may advance.
        let verifier = ShrincsVerifier::new();
        let (_, key_a) = ShrincsSigner::keygen(b"account wrong-key installed A", 4).unwrap();
        let (mut signing_b, key_b) =
            ShrincsSigner::keygen(b"account wrong-key attacker B", 4).unwrap();
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account rotate tamper current seed", 4).unwrap();
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"account rotate tamper next seed", 8).unwrap();
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
        let mut signature = to_stateless_signature(&signature);
        // Corrupt the recovery signature so FORS-C verification fails.
        signature.fors.randomizer[0] ^= 0xff;

        assert_eq!(
            account.rotateToFreshKey(&public_key, &signature, &next_target),
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
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"account stateless tamper seed", 4).unwrap();
        let public_key = to_public_key(&public_key);
        let expected = expected_key(&public_key);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected);
        let action_type = [5u8; HASH_LEN];
        let payload_hash = [6u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        let message = verifier.stateless_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let mut signature = to_stateless_signature(&signature);
        // Corrupt the FORS randomizer so verification fails after the policy gates pass.
        signature.fors.randomizer[0] ^= 0xff;

        assert_eq!(
            account.verifyStatelessAction(&public_key, action_type, payload_hash, &signature),
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
        let verifier = ShrincsVerifier::new();
        let (_, key_a) = ShrincsSigner::keygen(b"account stateless wrong-key A", 4).unwrap();
        let (signing_b, key_b) =
            ShrincsSigner::keygen(b"account stateless wrong-key B", 4).unwrap();
        let key_a = to_public_key(&key_a);
        let key_b = to_public_key(&key_b);
        let expected_a = expected_key(&key_a);
        let mut account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), expected_a);
        let action_type = [5u8; HASH_LEN];
        let payload_hash = [6u8; HASH_LEN];
        let context = ActionContext {
            domain_separator: account.domainSeparator(),
            nonce: account.nonce(),
            key_version: account.keyVersion(),
            action_type,
            payload_hash,
        };
        // Sign the account's canonical message with B's key: valid under B, but B is
        // not the installed key.
        let message = verifier.stateless_action_message_hash(expected_a, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_b, &message).unwrap();
        let signature = to_stateless_signature(&signature);

        assert_eq!(
            account.verifyStatelessAction(&key_b, action_type, payload_hash, &signature),
            Err(AccountError::InvalidSignature)
        );
        assert_eq!(account.currentShrincsPublicKey(), expected_a);
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }
}
