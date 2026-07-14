// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(non_snake_case)]

use std::collections::HashMap;

use solana_program::keccak::hash as keccak256_hash;

use crate::shrincs::verifier::STATELESS_SIGNATURE_LIMIT;
use crate::shrincs::{
    ActionContext, PublicKey, RotationContext, RotationTarget, ShrincsVerifier, StatelessSignature,
    HASH_LEN,
};

pub const DOMAIN_TAG_MESSAGE: &[u8] = b"shrincs-account-v1";
pub const COMPACT_SIGNATURE_BYTES: usize = 10053;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    OnlyOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShrincsAccountVerifierExample {
    currentPkSeed: [u8; HASH_LEN],
    currentHypertreeRoot: [u8; HASH_LEN],
    owner: [u8; HASH_LEN],
    chainId: [u8; HASH_LEN],
    contractAddress: [u8; 20],
    nonce: [u8; HASH_LEN],
    keyVersion: [u8; HASH_LEN],
    statelessSignaturesUsed: u64,
    compactSlots: HashMap<[u8; HASH_LEN], bool>,
}

impl ShrincsAccountVerifierExample {
    pub fn new(
        owner: [u8; HASH_LEN],
        chainId: [u8; HASH_LEN],
        contractAddress: [u8; 20],
        initialPkSeed: [u8; HASH_LEN],
        initialHypertreeRoot: [u8; HASH_LEN],
    ) -> Self {
        Self {
            owner,
            chainId,
            contractAddress,
            currentPkSeed: initialPkSeed,
            currentHypertreeRoot: initialHypertreeRoot,
            nonce: [0u8; HASH_LEN],
            keyVersion: [0u8; HASH_LEN],
            statelessSignaturesUsed: 0,
            compactSlots: HashMap::new(),
        }
    }

    pub fn currentPkSeed(&self) -> [u8; HASH_LEN] {
        self.currentPkSeed
    }

    pub fn currentHypertreeRoot(&self) -> [u8; HASH_LEN] {
        self.currentHypertreeRoot
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

    pub fn compactSlots(&self, slotId: &[u8; HASH_LEN]) -> bool {
        self.compactSlots.get(slotId).copied().unwrap_or(false)
    }

    pub fn compactSlotId(
        &self,
        subPkSeed: &[u8; HASH_LEN],
        subPkRoot: &[u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        ShrincsVerifier::new().compact_slot_id(subPkSeed, subPkRoot)
    }

    pub fn verifyStatelessAction(
        &mut self,
        publicKey: &PublicKey,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> bool {
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return false;
        }
        let context = self.actionContext(actionType, payloadHash);
        let ok = ShrincsVerifier::new().verify_stateless(
            self.currentPkSeed,
            self.currentHypertreeRoot,
            publicKey,
            &context,
            signature,
        );
        if !ok {
            return false;
        }
        increment_u256_be(&mut self.nonce);
        self.statelessSignaturesUsed += 1;
        true
    }

    pub fn verifyCompactAction(
        &mut self,
        subPkSeed: [u8; HASH_LEN],
        subPkRoot: [u8; HASH_LEN],
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
        signature: &[u8],
    ) -> bool {
        let slotId = self.compactSlotId(&subPkSeed, &subPkRoot);
        if !self.compactSlots(&slotId) {
            return false;
        }
        if actionType == [0u8; HASH_LEN] || payloadHash == [0u8; HASH_LEN] {
            return false;
        }
        if signature.len() != COMPACT_SIGNATURE_BYTES {
            return false;
        }
        increment_u256_be(&mut self.nonce);
        true
    }

    pub fn registerCompactSlot(
        &mut self,
        publicKey: &PublicKey,
        signature: &StatelessSignature,
        subPkSeed: [u8; HASH_LEN],
        subPkRoot: [u8; HASH_LEN],
    ) -> bool {
        self.updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, true)
    }

    pub fn revokeCompactSlot(
        &mut self,
        publicKey: &PublicKey,
        signature: &StatelessSignature,
        subPkSeed: [u8; HASH_LEN],
        subPkRoot: [u8; HASH_LEN],
    ) -> bool {
        self.updateCompactSlot(publicKey, signature, subPkSeed, subPkRoot, false)
    }

    pub fn rotateFullKey(
        &mut self,
        currentPublicKey: &PublicKey,
        recoverySignature: &StatelessSignature,
        nextKey: &RotationTarget,
    ) -> bool {
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return false;
        }
        let context = self.rotationContext();
        let ok = ShrincsVerifier::new().stateless_rotate(
            self.currentPkSeed,
            self.currentHypertreeRoot,
            currentPublicKey,
            &context,
            recoverySignature,
            nextKey,
        );
        if !ok {
            return false;
        }
        let Some(nextPkSeed) = word32(&nextKey.pk_seed) else {
            return false;
        };
        let Some(nextHypertreeRoot) = word32(&nextKey.hypertree_root) else {
            return false;
        };
        self.statelessSignaturesUsed += 1;
        self.installFreshFullKey(nextPkSeed, nextHypertreeRoot);
        true
    }

    pub fn domainSeparator(&self) -> [u8; HASH_LEN] {
        Self::computeDomainSeparator(self.chainId, self.contractAddress)
    }

    pub fn computeDomainSeparator(
        chainId: [u8; HASH_LEN],
        contractAddress: [u8; 20],
    ) -> [u8; HASH_LEN] {
        let domain_tag = keccak256_hash(DOMAIN_TAG_MESSAGE).to_bytes();
        let mut encoded = Vec::with_capacity(HASH_LEN * 3);
        encoded.extend_from_slice(&domain_tag);
        encoded.extend_from_slice(&chainId);
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(&contractAddress);
        keccak256_hash(&encoded).to_bytes()
    }

    fn actionContext(
        &self,
        actionType: [u8; HASH_LEN],
        payloadHash: [u8; HASH_LEN],
    ) -> ActionContext {
        ActionContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
            action_type: actionType,
            payload_hash: payloadHash,
        }
    }

    fn rotationContext(&self) -> RotationContext {
        RotationContext {
            domain_separator: self.domainSeparator(),
            nonce: self.nonce,
            key_version: self.keyVersion,
        }
    }

    fn updateCompactSlot(
        &mut self,
        publicKey: &PublicKey,
        signature: &StatelessSignature,
        subPkSeed: [u8; HASH_LEN],
        subPkRoot: [u8; HASH_LEN],
        registered: bool,
    ) -> bool {
        if self.statelessSignaturesUsed >= STATELESS_SIGNATURE_LIMIT {
            return false;
        }
        let slotId = self.compactSlotId(&subPkSeed, &subPkRoot);
        if self.compactSlots(&slotId) == registered {
            return false;
        }

        let verifier = ShrincsVerifier::new();
        let context = self.rotationContext();
        let message = if registered {
            verifier.compact_slot_registration_message_hash(&context, &subPkSeed, &subPkRoot)
        } else {
            verifier.compact_slot_revocation_message_hash(&context, &subPkSeed, &subPkRoot)
        };

        let ok = verifier.verify_stateless_unsafe_raw(
            self.currentPkSeed,
            self.currentHypertreeRoot,
            publicKey,
            &message,
            signature,
        );
        if !ok {
            return false;
        }

        self.compactSlots.insert(slotId, registered);
        self.statelessSignaturesUsed += 1;
        increment_u256_be(&mut self.nonce);
        true
    }

    fn installFreshFullKey(
        &mut self,
        nextPkSeed: [u8; HASH_LEN],
        nextHypertreeRoot: [u8; HASH_LEN],
    ) {
        self.currentPkSeed = nextPkSeed;
        self.currentHypertreeRoot = nextHypertreeRoot;
        increment_u256_be(&mut self.nonce);
        increment_u256_be(&mut self.keyVersion);
        self.statelessSignaturesUsed = 0;
    }

    fn onlyOwner(&self, caller: [u8; HASH_LEN]) -> Result<(), AccountError> {
        if caller != self.owner {
            return Err(AccountError::OnlyOwner);
        }
        Ok(())
    }
}

fn word32(input: &[u8]) -> Option<[u8; HASH_LEN]> {
    input.try_into().ok()
}

fn increment_u256_be(value: &mut [u8; HASH_LEN]) {
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
    use crate::shrincs::ShrincsSigner;

    fn id(byte: u8) -> [u8; HASH_LEN] {
        [byte; HASH_LEN]
    }

    fn address(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn public_key_words(public_key: &PublicKey) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
        (
            public_key.pk_seed.clone().try_into().unwrap(),
            public_key.hypertree_root.clone().try_into().unwrap(),
        )
    }

    fn account_for(public_key: &PublicKey) -> ShrincsAccountVerifierExample {
        let (pk_seed, hypertree_root) = public_key_words(public_key);
        ShrincsAccountVerifierExample::new(id(1), id(2), address(7), pk_seed, hypertree_root)
    }

    #[test]
    fn initializes_with_direct_stateless_key_storage() {
        let account = ShrincsAccountVerifierExample::new(id(1), id(2), address(7), id(3), id(4));
        assert_eq!(account.currentPkSeed(), id(3));
        assert_eq!(account.currentHypertreeRoot(), id(4));
        assert_eq!(account.nonce(), [0u8; HASH_LEN]);
        assert_eq!(account.keyVersion(), [0u8; HASH_LEN]);
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }

    #[test]
    fn compact_slot_registration_enables_compact_action_and_revocation_disables_it() {
        let (signing_key, public_key) = ShrincsSigner::keygen(b"compact slot account", 4).unwrap();
        let mut account = account_for(&public_key);
        let master = id(9);
        let randomness = id(10);
        let compact = ShrincsSigner::compact_keygen(&master, &randomness, 7).unwrap();
        let slot_id = account.compactSlotId(&compact.sub_pk_seed, &compact.sub_pk_root);

        assert!(!account.verifyCompactAction(
            compact.sub_pk_seed,
            compact.sub_pk_root,
            id(11),
            id(12),
            &[0u8; COMPACT_SIGNATURE_BYTES]
        ));

        let register_context = account.rotationContext();
        let register_message = ShrincsVerifier::new().compact_slot_registration_message_hash(
            &register_context,
            &compact.sub_pk_seed,
            &compact.sub_pk_root,
        );
        let register_sig =
            ShrincsSigner::sign_stateless_raw(&signing_key, &register_message).unwrap();
        assert!(account.registerCompactSlot(
            &public_key,
            &register_sig,
            compact.sub_pk_seed,
            compact.sub_pk_root
        ));
        assert!(account.compactSlots(&slot_id));
        assert_eq!(account.nonce()[31], 1);

        let action_context = account.actionContext(id(11), id(12));
        let compact_sig = ShrincsSigner::sign_compact_action(&compact, &action_context).unwrap();
        assert!(account.verifyCompactAction(
            compact.sub_pk_seed,
            compact.sub_pk_root,
            id(11),
            id(12),
            &compact_sig.raw_signature
        ));
        assert_eq!(account.nonce()[31], 2);
        assert_eq!(account.statelessSignaturesUsed(), 1);

        let revoke_context = account.rotationContext();
        let revoke_message = ShrincsVerifier::new().compact_slot_revocation_message_hash(
            &revoke_context,
            &compact.sub_pk_seed,
            &compact.sub_pk_root,
        );
        let revoke_sig = ShrincsSigner::sign_stateless_raw(&signing_key, &revoke_message).unwrap();
        assert!(account.revokeCompactSlot(
            &public_key,
            &revoke_sig,
            compact.sub_pk_seed,
            compact.sub_pk_root
        ));
        assert!(!account.compactSlots(&slot_id));
    }

    #[test]
    fn full_rotation_replaces_direct_stateless_key_words() {
        let (current_signing_key, current_public_key) =
            ShrincsSigner::keygen(b"current account key", 4).unwrap();
        let (_, next_public_key) = ShrincsSigner::keygen(b"next account key", 4).unwrap();
        let mut account = account_for(&current_public_key);
        let next_key = RotationTarget {
            pk_seed: next_public_key.pk_seed.clone(),
            hypertree_root: next_public_key.hypertree_root.clone(),
        };

        let context = account.rotationContext();
        let (current_pk_seed, current_root) = public_key_words(&current_public_key);
        let message = ShrincsVerifier::new().full_rotation_message_hash(
            current_pk_seed,
            current_root,
            &current_public_key,
            &context,
            &next_key,
        );
        let signature = ShrincsSigner::sign_stateless_raw(&current_signing_key, &message).unwrap();

        assert!(account.rotateFullKey(&current_public_key, &signature, &next_key));
        let (next_pk_seed, next_root) = public_key_words(&next_public_key);
        assert_eq!(account.currentPkSeed(), next_pk_seed);
        assert_eq!(account.currentHypertreeRoot(), next_root);
        assert_eq!(account.keyVersion()[31], 1);
        assert_eq!(account.statelessSignaturesUsed(), 0);
    }
}
