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

use std::fs;
use std::path::PathBuf;

use hashsigs_rs::shrincs::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, RotationContext,
    RotationTarget, ShrincsVerifier, StatefulRotationTarget, StatefulSignature, StatelessSignature,
    WotsCSignature, HASH_LEN,
};
use serde_json::Value;

struct AbiDecoder<'a> {
    data: &'a [u8],
}

#[derive(Debug)]
struct StatefulActionVector {
    current_shrincs_public_key: [u8; HASH_LEN],
    public_key: PublicKey,
    context: ActionContext,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    signature: StatefulSignature,
    message: Vec<u8>,
}

#[derive(Debug)]
struct StatelessActionVector {
    current_shrincs_public_key: [u8; HASH_LEN],
    public_key: PublicKey,
    context: ActionContext,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    signature: StatelessSignature,
    message: Vec<u8>,
}

#[derive(Debug)]
struct StatefulOnlyRotationVector {
    current_shrincs_public_key: [u8; HASH_LEN],
    current_public_key: PublicKey,
    context: RotationContext,
    next_key: StatefulRotationTarget,
    recovery_signature: StatelessSignature,
    message: Vec<u8>,
}

#[derive(Debug)]
struct FullRotationVector {
    current_shrincs_public_key: [u8; HASH_LEN],
    current_public_key: PublicKey,
    context: RotationContext,
    next_key: RotationTarget,
    recovery_signature: StatelessSignature,
    message: Vec<u8>,
}

impl<'a> AbiDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn decode_root_stateful_action_vector(&self) -> StatefulActionVector {
        let start = self.read_usize(0);
        self.decode_stateful_action_vector(start)
    }

    fn decode_root_stateless_action_vector(&self) -> StatelessActionVector {
        let start = self.read_usize(0);
        self.decode_stateless_action_vector(start)
    }

    fn decode_root_stateful_only_rotation_vector(&self) -> StatefulOnlyRotationVector {
        let start = self.read_usize(0);
        self.decode_stateful_only_rotation_vector(start)
    }

    fn decode_root_full_rotation_vector(&self) -> FullRotationVector {
        let start = self.read_usize(0);
        self.decode_full_rotation_vector(start)
    }

    fn decode_stateful_action_vector(&self, start: usize) -> StatefulActionVector {
        StatefulActionVector {
            current_shrincs_public_key: self.read_bytes32(start),
            public_key: self.decode_public_key(start, start + 32),
            context: self.decode_action_context(start + 64),
            action_type: self.read_bytes32(start + 224),
            payload_hash: self.read_bytes32(start + 256),
            signature: self.decode_stateful_signature(start, start + 288),
            message: self.decode_bytes(start, start + 320),
        }
    }

    fn decode_stateless_action_vector(&self, start: usize) -> StatelessActionVector {
        StatelessActionVector {
            current_shrincs_public_key: self.read_bytes32(start),
            public_key: self.decode_public_key(start, start + 32),
            context: self.decode_action_context(start + 64),
            action_type: self.read_bytes32(start + 224),
            payload_hash: self.read_bytes32(start + 256),
            signature: self.decode_stateless_signature(start, start + 288),
            message: self.decode_bytes(start, start + 320),
        }
    }

    fn decode_stateful_only_rotation_vector(&self, start: usize) -> StatefulOnlyRotationVector {
        StatefulOnlyRotationVector {
            current_shrincs_public_key: self.read_bytes32(start),
            current_public_key: self.decode_public_key(start, start + 32),
            context: self.decode_rotation_context(start + 64),
            next_key: self.decode_stateful_rotation_target(start, start + 160),
            recovery_signature: self.decode_stateless_signature(start, start + 192),
            message: self.decode_bytes(start, start + 224),
        }
    }

    fn decode_full_rotation_vector(&self, start: usize) -> FullRotationVector {
        FullRotationVector {
            current_shrincs_public_key: self.read_bytes32(start),
            current_public_key: self.decode_public_key(start, start + 32),
            context: self.decode_rotation_context(start + 64),
            next_key: self.decode_rotation_target(start, start + 160),
            recovery_signature: self.decode_stateless_signature(start, start + 192),
            message: self.decode_bytes(start, start + 224),
        }
    }

    fn decode_public_key(&self, base: usize, head: usize) -> PublicKey {
        let start = base + self.read_usize(head);
        PublicKey {
            stateful_public_key: self.decode_bytes(start, start),
            public_key_commitment: self.decode_bytes(start, start + 32),
            pk_seed: self.decode_bytes(start, start + 64),
            hypertree_root: self.decode_bytes(start, start + 96),
        }
    }

    fn decode_action_context(&self, start: usize) -> ActionContext {
        ActionContext {
            domain_separator: self.read_bytes32(start),
            nonce: self.read_bytes32(start + 32),
            key_version: self.read_bytes32(start + 64),
            action_type: self.read_bytes32(start + 96),
            payload_hash: self.read_bytes32(start + 128),
        }
    }

    fn decode_rotation_context(&self, start: usize) -> RotationContext {
        RotationContext {
            domain_separator: self.read_bytes32(start),
            nonce: self.read_bytes32(start + 32),
            key_version: self.read_bytes32(start + 64),
        }
    }

    fn decode_stateful_signature(&self, base: usize, head: usize) -> StatefulSignature {
        let start = base + self.read_usize(head);
        StatefulSignature {
            randomizer: self.read_bytes32(start),
            counter: self.read_u32(start + 32),
            chains: self.decode_array_bytes32(start, start + 64),
            auth_path: self.decode_array_bytes32(start, start + 96),
        }
    }

    fn decode_stateless_signature(&self, base: usize, head: usize) -> StatelessSignature {
        let start = base + self.read_usize(head);
        StatelessSignature {
            fors: self.decode_fors_signature(start, start),
            hypertree: self.decode_dynamic_array(start, start + 32, |decoder, element_start| {
                decoder.decode_hypertree_layer_signature(element_start)
            }),
        }
    }

    fn decode_fors_signature(&self, base: usize, head: usize) -> ForsSignature {
        let start = base + self.read_usize(head);
        ForsSignature {
            randomizer: self.decode_bytes(start, start),
            counter: self.read_u32(start + 32),
            entries: self.decode_dynamic_array(start, start + 64, |decoder, element_start| {
                decoder.decode_fors_entry(element_start)
            }),
        }
    }

    fn decode_fors_entry(&self, start: usize) -> ForsEntry {
        ForsEntry {
            secret_leaf: self.decode_bytes(start, start),
            auth_path: self.decode_array_bytes(start, start + 32),
        }
    }

    fn decode_hypertree_layer_signature(&self, start: usize) -> HypertreeLayerSignature {
        // The layer tuple dropped its leading (uint64 treeIndex, uint32
        // leafIndex): the head now begins with the wotsCPkHash offset, so every
        // remaining head slot shifts down by two 32-byte words.
        HypertreeLayerSignature {
            wots_c_pk_hash: self.decode_bytes(start, start),
            wots_c_signature: self.decode_wots_c_signature(start, start + 32),
            auth_path: self.decode_array_bytes(start, start + 64),
        }
    }

    fn decode_wots_c_signature(&self, base: usize, head: usize) -> WotsCSignature {
        let start = base + self.read_usize(head);
        WotsCSignature {
            randomizer: self.decode_bytes(start, start),
            counter: self.read_u32(start + 32),
            chains: self.decode_array_bytes(start, start + 64),
        }
    }

    fn decode_stateful_rotation_target(&self, base: usize, head: usize) -> StatefulRotationTarget {
        let start = base + self.read_usize(head);
        StatefulRotationTarget {
            stateful_public_key: self.decode_bytes(start, start),
            public_key_commitment: self.decode_bytes(start, start + 32),
        }
    }

    fn decode_rotation_target(&self, base: usize, head: usize) -> RotationTarget {
        let start = base + self.read_usize(head);
        RotationTarget {
            stateful_public_key: self.decode_bytes(start, start),
            public_key_commitment: self.decode_bytes(start, start + 32),
            pk_seed: self.decode_bytes(start, start + 64),
            hypertree_root: self.decode_bytes(start, start + 96),
        }
    }

    fn decode_bytes(&self, base: usize, head: usize) -> Vec<u8> {
        let start = base + self.read_usize(head);
        let len = self.read_usize(start);
        self.slice(start + 32, len).to_vec()
    }

    fn decode_array_bytes32(&self, base: usize, head: usize) -> Vec<[u8; HASH_LEN]> {
        let start = base + self.read_usize(head);
        let len = self.read_usize(start);
        (0..len)
            .map(|index| self.read_bytes32(start + 32 + index * 32))
            .collect()
    }

    fn decode_array_bytes(&self, base: usize, head: usize) -> Vec<Vec<u8>> {
        self.decode_dynamic_array(base, head, |decoder, element_start| {
            let len = decoder.read_usize(element_start);
            decoder.slice(element_start + 32, len).to_vec()
        })
    }

    fn decode_dynamic_array<T, F>(&self, base: usize, head: usize, decode_element: F) -> Vec<T>
    where
        F: Fn(&AbiDecoder<'a>, usize) -> T,
    {
        let start = base + self.read_usize(head);
        let len = self.read_usize(start);
        let elements_base = start + 32;
        (0..len)
            .map(|index| {
                let element_head = elements_base + index * 32;
                let element_start = elements_base + self.read_usize(element_head);
                decode_element(self, element_start)
            })
            .collect()
    }

    fn read_bytes32(&self, pos: usize) -> [u8; HASH_LEN] {
        self.slice(pos, HASH_LEN)
            .try_into()
            .expect("bytes32 slice length must be 32 bytes")
    }

    fn read_u32(&self, pos: usize) -> u32 {
        let word = self.slice(pos, 32);
        assert!(
            word[..28].iter().all(|byte| *byte == 0),
            "u32 word contains non-zero high bytes at offset {pos}",
        );
        u32::from_be_bytes(word[28..32].try_into().unwrap())
    }

    fn read_usize(&self, pos: usize) -> usize {
        let word = self.slice(pos, 32);
        assert!(
            word[..24].iter().all(|byte| *byte == 0),
            "offset/length exceeds supported usize width at offset {pos}",
        );
        usize::try_from(u64::from_be_bytes(word[24..32].try_into().unwrap()))
            .expect("offset/length must fit into usize")
    }

    fn slice(&self, pos: usize, len: usize) -> &'a [u8] {
        self.data
            .get(pos..pos + len)
            .expect("ABI blob ended unexpectedly")
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/test_vectors/shrincs_account_wrapper_vectors.json")
}

fn load_vectors() -> Value {
    let path = vectors_path();
    let encoded = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read Solidity account vectors at {}: {error}. \
             Generate them in hashsigs-solidity and copy the JSON here manually.",
            path.display()
        )
    });
    serde_json::from_str(&encoded).expect("failed to parse Solidity account vectors JSON")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let trimmed = hex.trim_start_matches("0x");
    assert!(trimmed.len() % 2 == 0, "hex string must have even length");
    (0..trimmed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&trimmed[index..index + 2], 16).unwrap())
        .collect()
}

fn bytes32_from_vec(bytes: &[u8]) -> [u8; HASH_LEN] {
    bytes.try_into().expect("value must be exactly 32 bytes")
}

#[test]
fn solidity_exported_stateful_action_vector_verifies_in_rust() {
    let vectors = load_vectors();
    let encoded = vectors["testExportStatefulActionBundle"]["stateful_vector_abi"]
        .as_str()
        .expect("missing stateful action vector blob");
    let mut vector = AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_stateful_action_vector();
    let verifier = ShrincsVerifier::new();

    assert_eq!(vector.action_type, vector.context.action_type);
    assert_eq!(vector.payload_hash, vector.context.payload_hash);
    assert_eq!(
        vector.message,
        verifier
            .stateful_action_message_hash(vector.current_shrincs_public_key, &vector.context)
            .to_vec(),
    );
    assert!(verifier.verify_stateful(
        vector.current_shrincs_public_key,
        &vector.public_key,
        &vector.context,
        &vector.signature,
    ));

    // A tampered Solidity-shaped signature must be rejected through the same
    // decode-then-verify path.
    vector.signature.chains[0][0] ^= 0x01;
    assert!(!verifier.verify_stateful(
        vector.current_shrincs_public_key,
        &vector.public_key,
        &vector.context,
        &vector.signature,
    ));
}

#[test]
fn solidity_exported_stateless_action_vector_verifies_in_rust() {
    let vectors = load_vectors();
    let encoded = vectors["testExportStatelessActionBundle"]["stateless_vector_abi"]
        .as_str()
        .expect("missing stateless action vector blob");
    let mut vector = AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_stateless_action_vector();
    let verifier = ShrincsVerifier::new();

    assert_eq!(vector.action_type, vector.context.action_type);
    assert_eq!(vector.payload_hash, vector.context.payload_hash);
    assert_eq!(
        vector.message,
        verifier
            .stateless_action_message_hash(vector.current_shrincs_public_key, &vector.context)
            .to_vec(),
    );
    assert!(verifier.verify_stateless(
        vector.current_shrincs_public_key,
        &vector.public_key,
        &vector.context,
        &vector.signature,
    ));

    // A tampered Solidity-shaped signature must be rejected through the same
    // decode-then-verify path.
    vector.signature.fors.randomizer[0] ^= 0x01;
    assert!(!verifier.verify_stateless(
        vector.current_shrincs_public_key,
        &vector.public_key,
        &vector.context,
        &vector.signature,
    ));
}

#[test]
fn solidity_exported_stateful_only_rotation_vector_verifies_in_rust() {
    let vectors = load_vectors();
    let encoded = vectors["testExportStatefulOnlyRotationBundle"]["stateful_rotation_vector_abi"]
        .as_str()
        .expect("missing stateful-only rotation vector blob");
    let mut vector =
        AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_stateful_only_rotation_vector();
    let verifier = ShrincsVerifier::new();

    assert_eq!(
        vector.message,
        verifier
            .stateful_rotation_message_hash(
                vector.current_shrincs_public_key,
                &vector.current_public_key,
                &vector.context,
                &vector.next_key,
            )
            .to_vec(),
    );
    let next_commitment = verifier
        .rotate_stateful_via_stateless(
            vector.current_shrincs_public_key,
            &vector.current_public_key,
            &vector.context,
            &vector.recovery_signature,
            &vector.next_key,
        )
        .expect("stateful-only rotation vector must verify in Rust");
    assert_eq!(
        next_commitment,
        bytes32_from_vec(&vector.next_key.public_key_commitment),
    );

    // A tampered recovery signature must fail the cryptographic verification,
    // not just the structural commitment checks.
    vector.recovery_signature.fors.randomizer[0] ^= 0x01;
    assert!(verifier
        .rotate_stateful_via_stateless(
            vector.current_shrincs_public_key,
            &vector.current_public_key,
            &vector.context,
            &vector.recovery_signature,
            &vector.next_key,
        )
        .is_none());
}

#[test]
fn solidity_exported_full_rotation_vector_verifies_in_rust() {
    let vectors = load_vectors();
    let encoded = vectors["testExportFullRotationBundle"]["full_rotation_vector_abi"]
        .as_str()
        .expect("missing full rotation vector blob");
    let mut vector = AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_full_rotation_vector();
    let verifier = ShrincsVerifier::new();

    assert_eq!(
        vector.message,
        verifier
            .full_rotation_message_hash(
                vector.current_shrincs_public_key,
                &vector.current_public_key,
                &vector.context,
                &vector.next_key,
            )
            .to_vec(),
    );
    let next_commitment = verifier
        .stateless_rotate(
            vector.current_shrincs_public_key,
            &vector.current_public_key,
            &vector.context,
            &vector.recovery_signature,
            &vector.next_key,
        )
        .expect("full rotation vector must verify in Rust");
    assert_eq!(
        next_commitment,
        bytes32_from_vec(&vector.next_key.public_key_commitment),
    );

    // A tampered recovery signature must fail the cryptographic verification,
    // not just the structural commitment checks.
    vector.recovery_signature.fors.randomizer[0] ^= 0x01;
    assert!(verifier
        .stateless_rotate(
            vector.current_shrincs_public_key,
            &vector.current_public_key,
            &vector.context,
            &vector.recovery_signature,
            &vector.next_key,
        )
        .is_none());
}
