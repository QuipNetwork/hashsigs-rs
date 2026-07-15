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

use hashsigs_rs::shrincs::{
    ActionContext, PublicKey, ShrincsSigner, ShrincsVerifier, StatefulSignature, HASH_LEN,
};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUT_PATH: &str = "tests/test_vectors/shrincs_stateful_k_gas_vector.json";
const TARGET_SIGNATURE_NUMBER: u32 = 128;
const CHAIN_ID: u64 = 31337;
const ACCOUNT_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xca, 0xfe,
];

#[test]
#[ignore = "run explicitly to refresh Solidity kth stateful gas vector"]
fn generate_stateful_k_gas_vector() {
    let (mut signing_key, public_key) = ShrincsSigner::keygen(
        b"shrincs stateful kth gas vector seed",
        TARGET_SIGNATURE_NUMBER,
    )
    .expect("stateful keygen");
    let message = hash_word(b"shrincs stateful kth gas vector message").to_vec();
    let action_type = hash_word(b"measure");
    let payload_hash = hash_word(b"measurement payload");
    let expected_public_key_commitment = public_key_commitment_word(&public_key);
    let context = ActionContext {
        domain_separator: account_domain_separator(),
        nonce: uint256_word(0),
        key_version: uint256_word(0),
        action_type,
        payload_hash,
    };
    let canonical_hash = ShrincsVerifier::new()
        .stateful_action_message_hash(expected_public_key_commitment, &context);
    let canonical_message = canonical_hash.to_vec();

    let mut signature = None;
    for _ in 0..TARGET_SIGNATURE_NUMBER {
        signature = Some(
            ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context)
                .expect("stateful signature"),
        );
    }
    let signature = signature.expect("kth signature");
    assert_eq!(signature.auth_path.len(), TARGET_SIGNATURE_NUMBER as usize);
    assert!(
        ShrincsVerifier::new().verify_stateful(
            expected_public_key_commitment,
            &public_key,
            &context,
            &signature,
        ),
        "exported kth stateful signature must verify before it is written",
    );

    let vector = json!({
        "statefulRawK": {
            "k": TARGET_SIGNATURE_NUMBER,
            "publicKey": public_key_json(&public_key),
            "message": hex(&message),
            "canonicalMessage": hex(&canonical_message),
            "canonicalHash": hex(canonical_hash),
            "actionType": hex(action_type),
            "payloadHash": hex(payload_hash),
            "account": hex(ACCOUNT_ADDRESS),
            "signature": stateful_signature_json(&signature),
            "calldata": stateful_raw_calldata(&public_key, &canonical_message, &signature),
            "canonicalCalldata": stateful_canonical_calldata(
                &public_key,
                action_type,
                payload_hash,
                &signature,
            )
        }
    });

    let out = serde_json::to_string_pretty(&vector).expect("serialize vector");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write stateful gas vector");
    println!("wrote {OUT_PATH}");
}

fn hash_word(label: &[u8]) -> [u8; HASH_LEN] {
    solana_program::keccak::hash(label).to_bytes()
}

fn stateful_canonical_calldata(
    public_key: &PublicKey,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    signature: &StatefulSignature,
) -> String {
    let public_key_arg = public_key_cast(public_key);
    let signature_arg = stateful_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes,bytes),bytes32,bytes32,(bytes32,uint32,bytes32[],bytes32[]))",
        &[
            public_key_arg,
            hex(action_type),
            hex(payload_hash),
            signature_arg,
        ],
    )
}

fn stateful_raw_calldata(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> String {
    let public_key_arg = public_key_cast(public_key);
    let signature_arg = stateful_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes,bytes),bytes,(bytes32,uint32,bytes32[],bytes32[]))",
        &[public_key_arg, hex(message), signature_arg],
    )
}

fn public_key_cast(public_key: &PublicKey) -> String {
    format!(
        "({},{},{},{})",
        hex(&public_key.stateful_public_key),
        hex(&public_key.public_key_commitment),
        hex(&public_key.pk_seed),
        hex(&public_key.hypertree_root)
    )
}

fn stateful_signature_cast(signature: &StatefulSignature) -> String {
    format!(
        "({},{},{},{})",
        hex(signature.randomizer),
        signature.counter,
        fixed_array(signature.chains.iter().map(hex)),
        fixed_array(signature.auth_path.iter().map(hex))
    )
}

fn fixed_array(values: impl Iterator<Item = String>) -> String {
    format!("[{}]", values.collect::<Vec<_>>().join(","))
}

fn cast_calldata(signature: &str, args: &[String]) -> String {
    let output = Command::new("cast")
        .arg("abi-encode")
        .arg(signature)
        .args(args)
        .output()
        .expect("run cast abi-encode");
    assert!(
        output.status.success(),
        "cast abi-encode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let encoded = String::from_utf8(output.stdout).expect("cast output");
    format!("0x00000000{}", encoded.trim().trim_start_matches("0x"))
}

fn public_key_json(public_key: &PublicKey) -> Value {
    json!({
        "statefulPublicKey": hex(&public_key.stateful_public_key),
        "publicKeyCommitment": hex(&public_key.public_key_commitment),
        "pkSeed": hex(&public_key.pk_seed),
        "hypertreeRoot": hex(&public_key.hypertree_root)
    })
}

fn public_key_commitment_word(public_key: &PublicKey) -> [u8; HASH_LEN] {
    public_key
        .public_key_commitment
        .as_slice()
        .try_into()
        .expect("32-byte public key commitment")
}

fn account_domain_separator() -> [u8; HASH_LEN] {
    let domain_tag = solana_program::keccak::hash(b"shrincs-account-v1").to_bytes();
    let chain_id = uint256_word(CHAIN_ID);
    let mut account = [0u8; HASH_LEN];
    account[12..32].copy_from_slice(&ACCOUNT_ADDRESS);
    solana_program::keccak::hashv(&[&domain_tag, &chain_id, &account]).to_bytes()
}

fn uint256_word(value: u64) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn stateful_signature_json(signature: &StatefulSignature) -> Value {
    json!({
        "randomizer": hex(signature.randomizer),
        "counter": signature.counter,
        "chains": signature.chains.iter().map(hex).collect::<Vec<_>>(),
        "authPath": signature.auth_path.iter().map(hex).collect::<Vec<_>>()
    })
}

fn hex<T: AsRef<[u8]>>(bytes: T) -> String {
    let mut out = String::with_capacity(2 + bytes.as_ref().len() * 2);
    out.push_str("0x");
    for byte in bytes.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
