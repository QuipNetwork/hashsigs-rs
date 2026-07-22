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

//! BYTE-PIN tests: `hashsigs_rs::shrincs::envelope` against the committed
//! Solidity-exported vectors (`tests/test_vectors/shrincs_account_wrapper_vectors*`).
//!
//! `common::AbiDecoder` (the same independent `abi.decode` oracle
//! `solidity_account_vectors.rs` uses for crypto-level verification) decodes
//! each root test-vector struct; this file cross-checks the envelope
//! codec's decode against that oracle's fields, re-encodes and asserts
//! byte-identity with the original committed blob, and for the ERC-1271
//! envelopes additionally runs the decoded signature through
//! `ShrincsVerifier` against the bundle's installed commitment/context.

mod common;

use common::{hex_to_bytes, load_vectors, AbiDecoder};
use hashsigs_rs::shrincs::envelope::{
    decode_1271_envelope, decode_stateful_action_envelope, decode_stateless_action_envelope,
    encode_stateful_1271_envelope, encode_stateful_envelope, encode_stateless_1271_envelope,
    encode_stateless_envelope, prepare_stateless_delegation, Erc1271Envelope,
};
use hashsigs_rs::shrincs::{VerifyOutcome, ShrincsVerifier, ShrincsGenericVerifier};

#[test]
fn stateful_1271_envelope_byte_pins_against_solidity_vector() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportStatefulActionBundle"];
    let vector_abi = hex_to_bytes(
        bundle["stateful_vector_abi"]
            .as_str()
            .expect("missing stateful action vector blob"),
    );
    let oracle = AbiDecoder::new(&vector_abi).decode_root_stateful_action_vector();

    // Decode the mode-prefixed ERC-1271 envelope through the codec's
    // mode-dispatch decoder and cross-check every field against the
    // independent AbiDecoder oracle.
    let envelope_bytes = hex_to_bytes(
        bundle["stateful_1271_envelope"]
            .as_str()
            .expect("missing stateful 1271 envelope blob"),
    );
    let decoded =
        decode_1271_envelope(&envelope_bytes).expect("valid 1271 envelope must decode");
    let Erc1271Envelope::Stateful {
        public_key,
        action_type,
        payload_hash,
        signature,
    } = decoded
    else {
        panic!("expected Stateful envelope variant for mode 1");
    };
    assert_eq!(public_key, oracle.public_key);
    assert_eq!(action_type, oracle.action_type);
    assert_eq!(payload_hash, oracle.payload_hash);
    assert_eq!(signature, oracle.signature);

    // The embedded signature must verify against the bundle's installed
    // commitment and canonical action context (SHRINCS.verifyStateful's
    // wire-level counterpart).
    let verifier = ShrincsVerifier::new();
    assert!(verifier.verify_stateful(
        oracle.current_shrincs_public_key,
        &public_key,
        &oracle.context,
        &signature,
    ));

    // Re-encoding the decoded fields must reproduce the original blob
    // byte-for-byte: the Solidity exporter's `abi.encodePacked(bytes1(mode),
    // abi.encode(...))` is canonical, so there is no offset-aliasing or
    // padding slack to "flag rather than force" here.
    let reencoded =
        encode_stateful_1271_envelope(&public_key, action_type, payload_hash, &signature);
    assert_eq!(reencoded, envelope_bytes);

    // `stateful_verify_calldata` is `abi.encodeCall(verifyStatefulAction,
    // (publicKey, actionType, payloadHash, signature))`: a 4-byte selector
    // followed by the exact same 4-tuple body as the 1271 envelope (minus
    // its 1-byte mode prefix). Confirm the codec decodes that body
    // identically and re-encodes it byte-identical too.
    let calldata = hex_to_bytes(
        bundle["stateful_verify_calldata"]
            .as_str()
            .expect("missing stateful verify calldata blob"),
    );
    assert_eq!(&calldata[4..], &envelope_bytes[1..]);
    let (calldata_key, calldata_action, calldata_payload, calldata_signature) =
        decode_stateful_action_envelope(&calldata[4..])
            .expect("valid verify-calldata body must decode");
    assert_eq!(calldata_key, public_key);
    assert_eq!(calldata_action, action_type);
    assert_eq!(calldata_payload, payload_hash);
    assert_eq!(calldata_signature, signature);
}

#[test]
fn stateless_1271_envelope_byte_pins_against_solidity_vector() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportStatelessActionBundle"];
    let vector_abi = hex_to_bytes(
        bundle["stateless_vector_abi"]
            .as_str()
            .expect("missing stateless action vector blob"),
    );
    let oracle = AbiDecoder::new(&vector_abi).decode_root_stateless_action_vector();

    let envelope_bytes = hex_to_bytes(
        bundle["stateless_1271_envelope"]
            .as_str()
            .expect("missing stateless 1271 envelope blob"),
    );
    let decoded =
        decode_1271_envelope(&envelope_bytes).expect("valid 1271 envelope must decode");
    let Erc1271Envelope::Stateless {
        public_key,
        action_type,
        payload_hash,
        signature,
    } = decoded
    else {
        panic!("expected Stateless envelope variant for mode 2");
    };
    assert_eq!(public_key, oracle.public_key);
    assert_eq!(action_type, oracle.action_type);
    assert_eq!(payload_hash, oracle.payload_hash);
    assert_eq!(signature, oracle.signature);

    let verifier = ShrincsVerifier::new();
    assert!(verifier.verify_stateless(
        oracle.current_shrincs_public_key,
        &public_key,
        &oracle.context,
        &signature,
    ));

    let reencoded =
        encode_stateless_1271_envelope(&public_key, action_type, payload_hash, &signature);
    assert_eq!(reencoded, envelope_bytes);

    let calldata = hex_to_bytes(
        bundle["stateless_verify_calldata"]
            .as_str()
            .expect("missing stateless verify calldata blob"),
    );
    assert_eq!(&calldata[4..], &envelope_bytes[1..]);
    let (calldata_key, calldata_action, calldata_payload, calldata_signature) =
        decode_stateless_action_envelope(&calldata[4..])
            .expect("valid verify-calldata body must decode");
    assert_eq!(calldata_key, public_key);
    assert_eq!(calldata_action, action_type);
    assert_eq!(calldata_payload, payload_hash);
    assert_eq!(calldata_signature, signature);
}

#[test]
fn stateful_only_rotation_bundle_feeds_prepare_stateless_delegation() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportStatefulOnlyRotationBundle"];
    let encoded = bundle["stateful_rotation_vector_abi"]
        .as_str()
        .expect("missing stateful-only rotation vector blob");
    let oracle =
        AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_stateful_only_rotation_vector();

    // `SHRINCS.prepareStatelessDelegation` is not itself one of the exported
    // vector shapes (there is no raw stateless-envelope blob for a rotation
    // bundle), so build the envelope our own encoder would produce from the
    // oracle-decoded (currentPublicKey, recoverySignature) pair and confirm
    // `prepare_stateless_delegation` extracts the expected pinned-sibling
    // shapes: this exercises the function's commitment-check and shape-check
    // semantics against real cryptographic material from the vector.
    let envelope =
        encode_stateless_envelope(&oracle.current_public_key, &oracle.recovery_signature);
    let (delegate_key, delegate_signature) =
        prepare_stateless_delegation(oracle.current_shrincs_public_key, &envelope)
            .expect("matching installed commitment must delegate");

    let mut expected_key = [0u8; 64];
    expected_key[..32].copy_from_slice(&oracle.current_public_key.pk_seed);
    expected_key[32..].copy_from_slice(&oracle.current_public_key.hypertree_root);
    assert_eq!(delegate_key, expected_key);

    let decoded_delegate_signature =
        hashsigs_rs::shrincs::envelope::decode_stateless_signature_envelope(&delegate_signature)
            .expect("delegate signature envelope must decode");
    assert_eq!(decoded_delegate_signature, oracle.recovery_signature);

    // A wrong expected commitment must fail closed even with a
    // structurally valid envelope.
    let mut wrong_commitment = oracle.current_shrincs_public_key;
    wrong_commitment[0] ^= 0x01;
    assert!(prepare_stateless_delegation(wrong_commitment, &envelope).is_none());
}

#[test]
fn stateful_erc7913_adapter_byte_pins_against_solidity_vector() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportStatefulActionBundle"];
    let vector_abi = hex_to_bytes(
        bundle["stateful_vector_abi"]
            .as_str()
            .expect("missing stateful action vector blob"),
    );
    let oracle = AbiDecoder::new(&vector_abi).decode_root_stateful_action_vector();

    // The ERC-7913 raw-hash `verify` entrypoint is not itself one of the
    // exported Solidity vector shapes (only the mode-prefixed ERC-1271
    // action envelope and the `verifyStatefulAction` calldata are exported);
    // build the plain `abi.encode(PublicKey, SHRINCS.Signature)` envelope
    // the codec's own encoder produces from the oracle-decoded fields —
    // the same pattern `stateful_only_rotation_bundle_feeds_prepare_stateless_delegation`
    // uses below for `prepare_stateless_delegation`. `oracle.message` is
    // already proven (in `solidity_account_vectors.rs`) to equal the
    // canonical stateful action hash, which is exactly the `hash` this
    // adapter's raw-hash path expects.
    let hash: [u8; 32] = oracle
        .message
        .clone()
        .try_into()
        .expect("stateful action message must be exactly 32 bytes");
    let envelope_bytes = encode_stateful_envelope(&oracle.public_key, &oracle.signature);

    let outcome = ShrincsGenericVerifier::new().verify(
        &oracle.current_shrincs_public_key,
        &hash,
        &envelope_bytes,
    );
    assert_eq!(outcome, VerifyOutcome::Valid);

    // A key of the wrong length is reported Invalid (Solidity: 0xffffffff),
    // never Malformed.
    let mut short_key = oracle.current_shrincs_public_key.to_vec();
    short_key.pop();
    assert_eq!(
        ShrincsGenericVerifier::new().verify(&short_key, &hash, &envelope_bytes),
        VerifyOutcome::Invalid
    );

    // A truncated envelope is reported Malformed (Solidity: revert).
    assert_eq!(
        ShrincsGenericVerifier::new().verify(
            &oracle.current_shrincs_public_key,
            &hash,
            &envelope_bytes[..envelope_bytes.len() - 1],
        ),
        VerifyOutcome::Malformed
    );
}

#[test]
fn stateless_erc7913_adapter_byte_pins_against_solidity_vector() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportStatelessActionBundle"];
    let vector_abi = hex_to_bytes(
        bundle["stateless_vector_abi"]
            .as_str()
            .expect("missing stateless action vector blob"),
    );
    let oracle = AbiDecoder::new(&vector_abi).decode_root_stateless_action_vector();

    // Same reasoning as the stateful adapter test above: build the plain
    // stateless envelope `SHRINCSVerifier.verifyStateless` expects from the
    // oracle-decoded fields, and reuse `oracle.message` (proven equal to the
    // canonical stateless action hash) as the ERC-7913 `hash` argument.
    let hash: [u8; 32] = oracle
        .message
        .clone()
        .try_into()
        .expect("stateless action message must be exactly 32 bytes");
    let envelope_bytes = encode_stateless_envelope(&oracle.public_key, &oracle.signature);

    let outcome = ShrincsGenericVerifier::new().verify_stateless(
        &oracle.current_shrincs_public_key,
        &hash,
        &envelope_bytes,
    );
    assert_eq!(outcome, VerifyOutcome::Valid);

    let mut short_key = oracle.current_shrincs_public_key.to_vec();
    short_key.pop();
    assert_eq!(
        ShrincsGenericVerifier::new().verify_stateless(&short_key, &hash, &envelope_bytes),
        VerifyOutcome::Invalid
    );

    assert_eq!(
        ShrincsGenericVerifier::new().verify_stateless(
            &oracle.current_shrincs_public_key,
            &hash,
            &envelope_bytes[..envelope_bytes.len() - 1],
        ),
        VerifyOutcome::Malformed
    );
}

#[test]
fn full_rotation_bundle_feeds_prepare_stateless_delegation() {
    let vectors = load_vectors();
    let bundle = &vectors["testExportFullRotationBundle"];
    let encoded = bundle["full_rotation_vector_abi"]
        .as_str()
        .expect("missing full rotation vector blob");
    let oracle = AbiDecoder::new(&hex_to_bytes(encoded)).decode_root_full_rotation_vector();

    let envelope =
        encode_stateless_envelope(&oracle.current_public_key, &oracle.recovery_signature);
    let (delegate_key, delegate_signature) =
        prepare_stateless_delegation(oracle.current_shrincs_public_key, &envelope)
            .expect("matching installed commitment must delegate");

    let mut expected_key = [0u8; 64];
    expected_key[..32].copy_from_slice(&oracle.current_public_key.pk_seed);
    expected_key[32..].copy_from_slice(&oracle.current_public_key.hypertree_root);
    assert_eq!(delegate_key, expected_key);

    let decoded_delegate_signature =
        hashsigs_rs::shrincs::envelope::decode_stateless_signature_envelope(&delegate_signature)
            .expect("delegate signature envelope must decode");
    assert_eq!(decoded_delegate_signature, oracle.recovery_signature);

    let mut wrong_commitment = oracle.current_shrincs_public_key;
    wrong_commitment[0] ^= 0x01;
    assert!(prepare_stateless_delegation(wrong_commitment, &envelope).is_none());
}
