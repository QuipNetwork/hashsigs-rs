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

mod common;

use common::{hex_to_bytes, load_vectors, AbiDecoder};
use hashsigs_rs::shrincs::ShrincsVerifier;

fn bytes32_from_vec(bytes: &[u8]) -> [u8; hashsigs_rs::shrincs::HASH_LEN] {
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
