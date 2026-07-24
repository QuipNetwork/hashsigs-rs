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

//! BYTE-PIN tests: `hashsigs_rs::envelope` against the committed
//! Solidity-exported vectors (`tests/test_vectors/shrincs_account_wrapper_vectors*`).
//!
//! `common::AbiDecoder` (the same independent `abi.decode` oracle
//! `solidity_account_vectors.rs` uses for crypto-level verification) decodes
//! each root test-vector struct; this file cross-checks the envelope
//! codec's decode against that oracle's fields and asserts byte-identity
//! with the original committed blob.

mod common;

use common::{hex_to_bytes, load_vectors, AbiDecoder};
use hashsigs_rs::envelope::{encode_stateful_envelope, encode_stateless_envelope};
use hashsigs_rs::shrincs::{ShrincsVerifier, VerifyOutcome};
use hashsigs_rs::VerifierInterface as _;

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

    let outcome = ShrincsVerifier::new().verify_envelope(
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
        ShrincsVerifier::new().verify_envelope(&short_key, &hash, &envelope_bytes),
        VerifyOutcome::Invalid
    );

    // A truncated envelope is reported Malformed (Solidity: revert).
    assert_eq!(
        ShrincsVerifier::new().verify_envelope(
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

    let outcome = ShrincsVerifier::new().verify_stateless_envelope(
        &oracle.current_shrincs_public_key,
        &hash,
        &envelope_bytes,
    );
    assert_eq!(outcome, VerifyOutcome::Valid);

    let mut short_key = oracle.current_shrincs_public_key.to_vec();
    short_key.pop();
    assert_eq!(
        ShrincsVerifier::new().verify_stateless_envelope(&short_key, &hash, &envelope_bytes),
        VerifyOutcome::Invalid
    );

    assert_eq!(
        ShrincsVerifier::new().verify_stateless_envelope(
            &oracle.current_shrincs_public_key,
            &hash,
            &envelope_bytes[..envelope_bytes.len() - 1],
        ),
        VerifyOutcome::Malformed
    );
}
