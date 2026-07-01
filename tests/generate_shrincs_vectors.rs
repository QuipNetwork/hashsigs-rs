// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hashsigs_rs::account::ShrincsAccountVerifierExample;
use hashsigs_rs::shrincs::{
    ActionContext, PublicKey, ShrincsSigner, ShrincsVerifier, StatefulSignature,
    StatelessSignature, HASH_LEN,
};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_256s_keccak.json";
const MEASUREMENT_ACTION_TYPE: &[u8] = b"measure";
const MEASUREMENT_PAYLOAD: &[u8] = b"measurement payload";
const FOUNDRY_CHAIN_ID: u64 = 31337;
const STATEFUL_MEASUREMENT_ACCOUNT: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe,
];
const STATELESS_MEASUREMENT_ACCOUNT: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xff,
];

#[test]
#[ignore = "run explicitly to refresh Solidity SHRINCS vectors"]
fn generate_shrincs_sphincs_256s_keccak_vectors() {
    let (mut stateful_key, stateful_public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateful seed", 4)
            .expect("stateful keygen");
    let stateful_message = hash_word(b"shrincs solidity stateful message").to_vec();
    let stateful_signature = ShrincsSigner::sign_stateful_raw(&mut stateful_key, &stateful_message)
        .expect("stateful signature");

    let (stateless_key, stateless_public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 128)
            .expect("stateless keygen");
    let stateless_message = hash_word(b"shrincs solidity stateless message").to_vec();
    let stateless_signature = ShrincsSigner::sign_stateless_raw(&stateless_key, &stateless_message)
        .expect("stateless signature");
    let measurement_vectors = measurement_vectors();

    let mut wrong_stateful_message = stateful_message.clone();
    wrong_stateful_message[0] ^= 1;
    let mut wrong_stateless_message = stateless_message.clone();
    wrong_stateless_message[0] ^= 1;

    let mut wrong_stateful_public_key = stateful_public_key.clone();
    wrong_stateful_public_key.stateful_public_key[32] ^= 1;

    let mut corrupted_stateful_signature = stateful_signature.clone();
    corrupted_stateful_signature.fors_entries[0].secret_leaf[0] ^= 1;

    let mut tampered_fors = stateless_signature.clone();
    tampered_fors.fors.entries[0].secret_leaf[0] ^= 1;

    let mut tampered_wots_pk_hash = stateless_signature.clone();
    tampered_wots_pk_hash.hypertree[0].wots_c_pk_hash[0] ^= 1;

    let mut tampered_auth = stateless_signature.clone();
    tampered_auth.hypertree[0].auth_path[0][0] ^= 1;

    let mut wrong_public_root = stateless_public_key.clone();
    wrong_public_root.hypertree_root[0] ^= 1;

    let mut tampered_component_public_key = stateless_public_key.clone();
    tampered_component_public_key.stateful_public_key[0] ^= 1;

    let vectors = json!({
        "stateful": {
            "publicKey": stateful_public_key_json(&stateful_public_key),
            "message": hex(&stateful_message),
            "signature": stateful_signature_json(&stateful_signature),
            "cases": {
                "valid": stateful_case(&stateful_public_key, &stateful_message, &stateful_signature),
                "wrongMessage": stateful_case(&stateful_public_key, &wrong_stateful_message, &stateful_signature),
                "wrongPublicKey": stateful_case(&wrong_stateful_public_key, &stateful_message, &stateful_signature),
                "corruptedSignature": stateful_case(&stateful_public_key, &stateful_message, &corrupted_stateful_signature)
            }
        },
        "stateless": {
            "publicKey": public_key_json(&stateless_public_key),
            "message": hex(&stateless_message),
            "signature": stateless_signature_json(&stateless_signature),
            "cases": {
                "valid": stateless_case(&stateless_public_key, &stateless_message, &stateless_signature),
                "wrongMessage": stateless_case(&stateless_public_key, &wrong_stateless_message, &stateless_signature),
                "tamperedFors": stateless_case(&stateless_public_key, &stateless_message, &tampered_fors),
                "tamperedHypertreeWotsPkHash": stateless_case(&stateless_public_key, &stateless_message, &tampered_wots_pk_hash),
                "tamperedHypertreeAuth": stateless_case(&stateless_public_key, &stateless_message, &tampered_auth),
                "wrongPublicRoot": stateless_case(&wrong_public_root, &stateless_message, &stateless_signature),
                "tamperedComponentPublicKey": stateless_case(&tampered_component_public_key, &stateless_message, &stateless_signature)
            }
        },
        "measurements": measurement_vectors
    });

    let out = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write SHRINCS Solidity vectors");
    println!("wrote {OUT_PATH}");
}

fn measurement_vectors() -> Value {
    let action_type = hash_word(MEASUREMENT_ACTION_TYPE);
    let payload_hash = hash_word(MEASUREMENT_PAYLOAD);
    let chain_id = chain_id_word(FOUNDRY_CHAIN_ID);

    let (mut stateful_key, stateful_public_key) =
        ShrincsSigner::keygen(b"shrincs measurement vector stateful seed", 128)
            .expect("measurement stateful keygen");
    let stateful_context = measurement_context(
        chain_id,
        STATEFUL_MEASUREMENT_ACCOUNT,
        action_type,
        payload_hash,
    );
    let stateful_signature = ShrincsSigner::sign_stateful_action(
        &mut stateful_key,
        &stateful_public_key,
        &stateful_context,
    )
    .expect("measurement stateful signature");
    let verifier = ShrincsVerifier::new();
    let stateful_expected = word32(&stateful_public_key.public_key_commitment);
    let stateful_message =
        verifier.stateful_action_message_hash(stateful_expected, &stateful_context);

    let (stateless_key, stateless_public_key) =
        ShrincsSigner::keygen(b"shrincs measurement vector stateless seed", 128)
            .expect("measurement stateless keygen");
    let stateless_context = measurement_context(
        chain_id,
        STATELESS_MEASUREMENT_ACCOUNT,
        action_type,
        payload_hash,
    );
    let stateless_expected = word32(&stateless_public_key.public_key_commitment);
    let stateless_message =
        verifier.stateless_action_message_hash(stateless_expected, &stateless_context);
    let stateless_signature = ShrincsSigner::sign_stateless_raw(&stateless_key, &stateless_message)
        .expect("measurement stateless signature");

    json!({
        "chainId": FOUNDRY_CHAIN_ID,
        "actionType": hex(action_type),
        "payloadHash": hex(payload_hash),
        "stateful": {
            "account": hex(STATEFUL_MEASUREMENT_ACCOUNT),
            "publicKey": public_key_json(&stateful_public_key),
            "message": hex(stateful_message),
            "signature": stateful_signature_json(&stateful_signature),
            "canonicalCalldata": account_stateful_calldata(&stateful_public_key, action_type, payload_hash, &stateful_signature)
        },
        "stateless": {
            "account": hex(STATELESS_MEASUREMENT_ACCOUNT),
            "publicKey": public_key_json(&stateless_public_key),
            "message": hex(stateless_message),
            "signature": stateless_signature_json(&stateless_signature),
            "canonicalCalldata": account_stateless_calldata(&stateless_public_key, action_type, payload_hash, &stateless_signature)
        }
    })
}

fn measurement_context(
    chain_id: [u8; HASH_LEN],
    account: [u8; 20],
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
) -> ActionContext {
    ActionContext {
        domain_separator: ShrincsAccountVerifierExample::computeDomainSeparator(chain_id, account),
        nonce: [0u8; HASH_LEN],
        key_version: [0u8; HASH_LEN],
        action_type,
        payload_hash,
    }
}

fn hash_word(label: &[u8]) -> [u8; HASH_LEN] {
    solana_program::keccak::hash(label).to_bytes()
}

fn chain_id_word(chain_id: u64) -> [u8; HASH_LEN] {
    let mut word = [0u8; HASH_LEN];
    word[24..32].copy_from_slice(&chain_id.to_be_bytes());
    word
}

fn word32(bytes: &[u8]) -> [u8; HASH_LEN] {
    bytes.try_into().expect("32-byte word")
}

fn stateful_case(public_key: &PublicKey, message: &[u8], signature: &StatefulSignature) -> Value {
    json!({
        "publicKey": stateful_public_key_json(public_key),
        "message": hex(message),
        "signature": stateful_signature_json(signature),
        "calldata": stateful_calldata(public_key, message, signature)
    })
}

fn stateless_case(public_key: &PublicKey, message: &[u8], signature: &StatelessSignature) -> Value {
    json!({
        "publicKey": public_key_json(public_key),
        "message": hex(message),
        "signature": stateless_signature_json(signature),
        "calldata": stateless_calldata(public_key, message, signature)
    })
}

fn stateful_calldata(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> String {
    let key = public_key_cast(public_key);
    let sig = stateful_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes,bytes),bytes,(uint8,bytes32,uint32,(bytes,bytes[])[],bytes32[]))",
        &[key, hex(message), sig],
    )
}

fn stateless_calldata(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> String {
    let public_key = format!(
        "({},{},{})",
        hex(&public_key.stateful_public_key),
        hex(&public_key.pk_seed),
        hex(&public_key.hypertree_root)
    );
    let sig = stateless_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key, hex(message), sig],
    )
}

fn account_stateful_calldata(
    public_key: &PublicKey,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    signature: &StatefulSignature,
) -> String {
    let public_key = public_key_cast(public_key);
    let sig = stateful_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes,bytes),bytes32,bytes32,(uint8,bytes32,uint32,(bytes,bytes[])[],bytes32[]))",
        &[public_key, hex(action_type), hex(payload_hash), sig],
    )
}

fn account_stateless_calldata(
    public_key: &PublicKey,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    signature: &StatelessSignature,
) -> String {
    let public_key = public_key_cast(public_key);
    let sig = stateless_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes,bytes,bytes),bytes32,bytes32,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key, hex(action_type), hex(payload_hash), sig],
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
        "({},{},{},{},{})",
        signature.q,
        hex(signature.randomizer),
        signature.counter,
        fixed_array(signature.fors_entries.iter().map(fors_entry_tuple)),
        fixed_array(signature.auth_path.iter().map(hex))
    )
}

fn stateless_signature_cast(signature: &StatelessSignature) -> String {
    let fors_entries = signature.fors.entries.iter().map(|entry| {
        format!(
            "({},{})",
            hex(&entry.secret_leaf),
            fixed_array(entry.auth_path.iter().map(hex))
        )
    });
    let fors = format!(
        "({},{},{})",
        hex(&signature.fors.randomizer),
        signature.fors.counter,
        fixed_array(fors_entries)
    );
    let layers = signature.hypertree.iter().map(|layer| {
        let wots = format!(
            "({},{},{})",
            hex(&layer.wots_c_signature.randomizer),
            layer.wots_c_signature.counter,
            fixed_array(layer.wots_c_signature.chains.iter().map(hex))
        );
        format!(
            "({},{},{},{},{})",
            layer.tree_index,
            layer.leaf_index,
            hex(&layer.wots_c_pk_hash),
            wots,
            fixed_array(layer.auth_path.iter().map(hex))
        )
    });
    format!("({},{})", fors, fixed_array(layers))
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

fn stateful_public_key_json(public_key: &PublicKey) -> Value {
    let encoded = &public_key.stateful_public_key;
    json!({
        "pkSeed": hex(&encoded[0..32]),
        "root": hex(&encoded[32..64]),
        "maxSignatures": u32::from_be_bytes(encoded[64..68].try_into().expect("max signatures"))
    })
}

fn public_key_json(public_key: &PublicKey) -> Value {
    json!({
        "statefulPublicKey": hex(&public_key.stateful_public_key),
        "publicKeyCommitment": hex(&public_key.public_key_commitment),
        "pkSeed": hex(&public_key.pk_seed),
        "hypertreeRoot": hex(&public_key.hypertree_root)
    })
}

fn stateful_signature_json(signature: &StatefulSignature) -> Value {
    json!({
        "q": signature.q,
        "randomizer": hex(signature.randomizer),
        "counter": signature.counter,
        "forsEntries": signature.fors_entries.iter().map(fors_entry_json).collect::<Vec<_>>(),
        "authPath": signature.auth_path.iter().map(hex).collect::<Vec<_>>()
    })
}

fn fors_entry_json(entry: &hashsigs_rs::shrincs::ForsEntry) -> Value {
    json!({
        "secretLeaf": hex(&entry.secret_leaf),
        "authPath": entry.auth_path.iter().map(hex).collect::<Vec<_>>()
    })
}

fn fors_entry_tuple(entry: &hashsigs_rs::shrincs::ForsEntry) -> String {
    format!(
        "({},{})",
        hex(&entry.secret_leaf),
        fixed_array(entry.auth_path.iter().map(hex))
    )
}

fn stateless_signature_json(signature: &StatelessSignature) -> Value {
    json!({
        "fors": {
            "randomizer": hex(&signature.fors.randomizer),
            "counter": signature.fors.counter,
            "entries": signature.fors.entries.iter().map(|entry| json!({
                "secretLeaf": hex(&entry.secret_leaf),
                "sk": hex(&entry.secret_leaf),
                "authPath": entry.auth_path.iter().map(hex).collect::<Vec<_>>(),
                "auth": entry.auth_path.iter().map(hex).collect::<Vec<_>>()
            })).collect::<Vec<_>>()
        },
        "hypertree": signature.hypertree.iter().map(|layer| json!({
            "treeIndex": layer.tree_index,
            "leafIndex": layer.leaf_index,
            "wotsCPkHash": hex(&layer.wots_c_pk_hash),
            "wotsCSignature": {
                "randomizer": hex(&layer.wots_c_signature.randomizer),
                "counter": layer.wots_c_signature.counter,
                "chains": layer.wots_c_signature.chains.iter().map(hex).collect::<Vec<_>>()
            },
            "authPath": layer.auth_path.iter().map(hex).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
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
