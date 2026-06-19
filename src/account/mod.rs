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

#![allow(non_snake_case)]

use std::collections::HashMap;

use solana_program::keccak::hash as keccak256_hash;

use crate::shrincs::{
    ActionContext, ParameterSetId, PublicKey, RotationContext, RotationTarget, ShrincsVerifier,
    StatefulRotationTarget, StatefulSignature, StatelessSignature, HASH_LEN,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    OnlyOwner,
    RecoveryPolicyRequired,
    StatefulIndexRollback,
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
    // Active SHRINCS parameter profile for the installed key bundle.
    parameterSetId: ParameterSetId,
    // Canonical action/rotation nonce consumed on successful wrapper operations.
    nonce: [u8; HASH_LEN],
    // Installed-key epoch incremented whenever a fresh key bundle is installed.
    keyVersion: [u8; HASH_LEN],
    // Number of stateless signatures consumed under the current installed key.
    statelessSignaturesUsed: u64,
    // Current stateful leaf-tracking / recovery policy enforced by the wrapper.
    statefulPolicy: StatefulPolicy,
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
    // 3. Select the default parameter profile for the example wrapper.
    // 4. Start with monotonic stateful leaf tracking.
    // 5. Expect the first stateful signature to use leaf 1.
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
            // Start the example wrapper on its default SHRINCS parameter profile.
            parameterSetId: ParameterSetId::Sphincs256sKeccakQ20,
            nonce: [0u8; HASH_LEN],
            keyVersion: [0u8; HASH_LEN],
            statelessSignaturesUsed: 0,
            // Default to ordered stateful signing under monotonic leaf tracking.
            statefulPolicy: StatefulPolicy::MonotonicIndex,
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

    pub fn parameterSetId(&self) -> ParameterSetId {
        self.parameterSetId
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

    pub fn recoveryMode(&self) -> bool {
        self.recoveryMode
    }

    // verifyStatefulUncheckedMessage: Internal raw stateful verification for tests and support harnesses only.
    // 1. Recover the stateful leaf index from the auth-path length.
    // 2. Check the active leaf-tracking policy before any cryptographic work.
    // 3. Verify the caller-supplied message directly without building canonical action context.
    // 4. Commit the consumed leaf only after signature verification succeeds.
    // 5. Emit the usual stateful verification event without advancing the wrapper nonce.
    pub(crate) fn verifyStatefulUncheckedMessage(
        &mut self,
        publicKey: &PublicKey,
        message: &[u8],
        signature: &StatefulSignature,
    ) -> bool {
        // This path bypasses canonical wrapper message construction and therefore remains internal-only.
        // Recover the consumed stateful leaf from the signature layout.
        let leafIndex = signature.auth_path.len() as u32;
        // Stop early if the active policy disallows this leaf.
        if !self.precheckStatefulLeafUse(leafIndex) {
            return false;
        }

        // Verify the caller-supplied message directly against the current installed key.
        let ok = ShrincsVerifier::new().verify_stateful_unsafe_raw(
            self.parameterSetId,
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
    ) -> bool {
        // Recover the consumed stateful leaf from the signature layout.
        let leafIndex = signature.auth_path.len() as u32;
        // Stop early if the active policy disallows this leaf.
        if !self.precheckStatefulLeafUse(leafIndex) {
            return false;
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
        let ok = ShrincsVerifier::new().verify_stateful(
            self.parameterSetId,
            self.currentShrincsPublicKey,
            publicKey,
            &context,
            signature,
        );
        if !ok {
            return false;
        }

        // Consume the leaf only after the action signature verifies.
        self.commitStatefulLeafUse(leafIndex);
        // Solidity emits before nonce advancement so observers see the consumed nonce value.
        // Advance freshness state after a successful action.
        increment_u256_be(&mut self.nonce);
        true
    }

    // verifyStatelessAction: Canonical stateless account-action verification path.
    // 1. Reject stateless actions when recovery mode gating forbids them.
    // 2. Enforce the profile's stateless usage budget for the current key epoch.
    // 3. Build the canonical typed action context from wrapper-owned freshness state.
    // 4. Verify the stateless signature against that canonical action message.
    // 5. Advance nonce and stateless-usage counters only after success.
    pub fn verifyStatelessAction(
        &mut self,
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        // Recovery-only policy forbids stateless actions until recovery mode is explicitly entered.
        if self.statefulPolicy == StatefulPolicy::RecoveryRotation && !self.recoveryMode {
            return false;
        }
        // Enforce the per-key stateless usage budget from the active parameter profile.
        let limit =
            ShrincsVerifier::default_params_view(self.parameterSetId).stateless_signature_limit;
        if self.statelessSignaturesUsed >= limit {
            return false;
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
            self.parameterSetId,
            self.currentShrincsPublicKey,
            publicKey,
            &context,
            signature,
        );
        if !ok {
            return false;
        }

        // Advance wrapper freshness and stateless usage state after success.
        increment_u256_be(&mut self.nonce);
        self.statelessSignaturesUsed += 1;
        // Solidity emits the consumed nonce value from the pre-increment state.
        true
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
    ) -> bool {
        // Fresh-key rotation is available only in the dedicated recovery policy.
        if self.statefulPolicy != StatefulPolicy::RecoveryRotation {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if !self.recoveryMode {
            return false;
        }
        // Enforce the per-key stateless usage budget from the active parameter profile.
        let limit =
            ShrincsVerifier::default_params_view(self.parameterSetId).stateless_signature_limit;
        if self.statelessSignaturesUsed >= limit {
            return false;
        }

        // Bind the rotation to this contract instance, nonce, and key epoch.
        let context = RotationContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
        };

        // Verify the stateless recovery signature and derive the next installed commitment.
        let Some(nextCompositePublicKey) = ShrincsVerifier::new().rotate_stateful_via_stateless(
            self.parameterSetId,
            self.currentShrincsPublicKey,
            currentPublicKey,
            &context,
            recoverySignature,
            nextKey,
        ) else {
            return false;
        };

        // Install the next key bundle and reset wrapper state for the new epoch.
        self.installFreshKey(nextCompositePublicKey, nextKey.parameter_set_id);
        true
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
    ) -> bool {
        // Full-key rotation is available only in the dedicated recovery policy.
        if self.statefulPolicy != StatefulPolicy::RecoveryRotation {
            return false;
        }
        // The owner must explicitly arm recovery mode before stateless recovery is accepted.
        if !self.recoveryMode {
            return false;
        }
        // Enforce the per-key stateless usage budget from the active parameter profile.
        let limit =
            ShrincsVerifier::default_params_view(self.parameterSetId).stateless_signature_limit;
        if self.statelessSignaturesUsed >= limit {
            return false;
        }

        // Bind the rotation to this contract instance, nonce, and key epoch.
        let context = RotationContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
        };

        // Verify the stateless recovery signature and derive the next installed commitment.
        let Some(nextCompositePublicKey) = ShrincsVerifier::new().stateless_rotate(
            self.parameterSetId,
            self.currentShrincsPublicKey,
            currentPublicKey,
            &context,
            recoverySignature,
            nextKey,
        ) else {
            return false;
        };

        // Install the next key bundle and reset wrapper state for the new epoch.
        self.installFreshKey(nextCompositePublicKey, nextKey.parameter_set_id);
        true
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
    // 2. Prevent rollback to an earlier expected leaf index.
    // 3. Install monotonic tracking with the supplied next expected leaf.
    // 4. Exit recovery mode because the wrapper is returning to normal operation.
    // 5. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyMonotonicIndex(
        &mut self,
        caller: [u8; HASH_LEN],
        initialLeafIndex: u32,
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
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
    // 2. Preserve or initialize the stateful leaf cursor for later normal operation.
    // 3. Require an explicit enterRecoveryMode() call before stateless recovery is accepted.
    // 4. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyRecoveryRotation(
        &mut self,
        caller: [u8; HASH_LEN],
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
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
    // 2. Preserve or initialize the stateful leaf cursor for future monotonic use.
    // 3. Exit recovery mode because the wrapper is returning to normal operation.
    // 4. Emit the policy update for off-chain observers.
    pub fn setStatefulPolicyLeafBitmap(
        &mut self,
        caller: [u8; HASH_LEN],
    ) -> Result<(), AccountError> {
        self.onlyOwner(caller)?;
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

    // precheckStatefulLeafUse: Check whether the active policy allows a stateful leaf before verification.
    // 1. Reject stateful signatures while recovery mode is actively using stateless authority.
    // 2. Under monotonic tracking, accept only the next expected leaf.
    // 3. Under bitmap tracking, accept only leaves that have not yet been marked used.
    // 4. Return true for any remaining policy branch.
    pub fn precheckStatefulLeafUse(&self, leafIndex: u32) -> bool {
        // While recovery mode is active, block all stateful signatures.
        if self.statefulPolicy == StatefulPolicy::RecoveryRotation && self.recoveryMode {
            return false;
        }
        // Ordered tracking accepts exactly one next leaf.
        if self.statefulPolicy == StatefulPolicy::MonotonicIndex {
            return leafIndex == self.nextStatefulLeafIndex;
        }
        // Bitmap tracking accepts any leaf that has not already been marked used.
        if self.statefulPolicy == StatefulPolicy::LeafBitmap {
            return !self.isLeafUsed(leafIndex);
        }
        true
    }

    // commitStatefulLeafUse: Record a successfully verified stateful leaf under the active policy.
    // 1. Under monotonic tracking, advance the next expected leaf by one.
    // 2. Under bitmap tracking, mark the corresponding bit for this leaf as used.
    // 3. Leave recovery-only mode unchanged because stateful signatures are blocked there.
    pub fn commitStatefulLeafUse(&mut self, leafIndex: u32) {
        if self.statefulPolicy == StatefulPolicy::MonotonicIndex {
            // Move the expected cursor forward after one successful monotonic use.
            self.nextStatefulLeafIndex += 1;
            return;
        }
        if self.statefulPolicy == StatefulPolicy::LeafBitmap {
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

    // installFreshKey: Install a fresh key bundle and reset wrapper state for the new key epoch.
    // 1. Preserve the previous installed key commitment for the rotation event.
    // 2. Install the next SHRINCS public-key commitment and parameter profile.
    // 3. Advance nonce and key version to close the old authorization epoch.
    // 4. Reset stateless usage and stateful leaf tracking for the new key.
    // 5. Return the wrapper to the default monotonic non-recovery policy.
    // 6. Emit rotation and policy-reset events for off-chain observers.
    fn installFreshKey(
        &mut self,
        nextCompositePublicKey: [u8; HASH_LEN],
        nextParameterSetId: ParameterSetId,
    ) {
        // Preserve the previous key commitment for the rotation event payload.
        let _previousShrincsPublicKey = self.currentShrincsPublicKey;
        // Install the next trusted SHRINCS public-key commitment.
        self.currentShrincsPublicKey = nextCompositePublicKey;
        // Switch to the next key bundle's parameter profile.
        self.parameterSetId = nextParameterSetId;
        // Advance nonce and key epoch so old authorizations cannot be replayed.
        increment_u256_be(&mut self.nonce);
        increment_u256_be(&mut self.keyVersion);
        // Reset per-key stateless usage accounting.
        self.statelessSignaturesUsed = 0;
        // Reset stateful signing to the first leaf of the new key epoch.
        self.nextStatefulLeafIndex = INITIAL_STATEFUL_LEAF_INDEX;
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
        let limb = (bitIndex / 64) as usize;
        let offset = bitIndex % 64;
        (self.0[limb] & (1u64 << offset)) != 0
    }

    fn set_bit(&mut self, bitIndex: u32) {
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

    fn id(byte: u8) -> [u8; HASH_LEN] {
        [byte; HASH_LEN]
    }

    fn address(byte: u8) -> [u8; 20] {
        [byte; 20]
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
        assert_eq!(account.parameterSetId(), ParameterSetId::Sphincs256sKeccakQ20);
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
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
        assert!(!account.precheckStatefulLeafUse(9));

        account.installFreshKey(id(4), ParameterSetId::Sphincs256sKeccakQ20);
        assert!(!account.isLeafUsed(9));
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

        account.installFreshKey(id(4), ParameterSetId::Sphincs256sKeccakQ20);

        assert_eq!(account.currentShrincsPublicKey(), id(4));
        assert_eq!(account.nonce()[HASH_LEN - 1], 1);
        assert_eq!(account.keyVersion()[HASH_LEN - 1], 1);
        assert_eq!(account.statelessSignaturesUsed(), 0);
        assert_eq!(account.statefulPolicy(), StatefulPolicy::MonotonicIndex);
        assert_eq!(account.nextStatefulLeafIndex(), INITIAL_STATEFUL_LEAF_INDEX);
        assert!(!account.recoveryMode());
    }
}
