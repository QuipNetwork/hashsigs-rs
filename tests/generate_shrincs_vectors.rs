// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hashsigs_rs::shrincs::{
    ActionContext, CompactSignature, CompactSigningKey, PublicKey, ShrincsSigner,
    StatelessSignature, HASH_LEN,
};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_256s_keccak.json";

#[test]
#[ignore = "run explicitly to refresh Solidity SHRINCS vectors"]
fn generate_shrincs_sphincs_256s_keccak_vectors() {
    let (stateless_key, stateless_public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256)
            .expect("stateless keygen");
    let stateless_message = hash_word(b"shrincs solidity stateless message").to_vec();
    let stateless_signature = ShrincsSigner::sign_stateless_raw(&stateless_key, &stateless_message)
        .expect("stateless signature");

    let compact_master_sk_seed = hash_word(b"shrincs solidity vector compact master seed");
    let compact_slot_randomness = hash_word(b"shrincs solidity vector compact slot r");
    let compact_key =
        ShrincsSigner::compact_keygen(&compact_master_sk_seed, &compact_slot_randomness, 11)
            .expect("compact keygen");
    let compact_message = hash_word(b"shrincs solidity compact message").to_vec();
    let compact_signature =
        ShrincsSigner::sign_compact_raw(&compact_key, &compact_message).expect("compact signature");
    let compact_first_context = compact_action_context(
        b"shrincs solidity compact domain",
        1,
        1,
        b"execute",
        b"shrincs solidity compact payload one",
    );
    let compact_second_context = compact_action_context(
        b"shrincs solidity compact domain",
        2,
        1,
        b"execute",
        b"shrincs solidity compact payload two",
    );

    let mut wrong_stateless_message = stateless_message.clone();
    wrong_stateless_message[0] ^= 1;

    let mut tampered_fors = stateless_signature.clone();
    tampered_fors.fors.entries[0].secret_leaf[0] ^= 1;

    let mut tampered_wots_pk_hash = stateless_signature.clone();
    tampered_wots_pk_hash.hypertree[0].wots_c_pk_hash[0] ^= 1;

    let mut tampered_auth = stateless_signature.clone();
    tampered_auth.hypertree[0].auth_path[0][0] ^= 1;

    let mut wrong_public_root = stateless_public_key.clone();
    wrong_public_root.hypertree_root[0] ^= 1;

    let mut tampered_component_public_key = stateless_public_key.clone();
    tampered_component_public_key.pk_seed[0] ^= 1;

    let vectors = json!({
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
        "compact": {
            "masterSkSeed": hex(compact_master_sk_seed),
            "slotRandomness": hex(compact_slot_randomness),
            "subPkSeed": hex(compact_signature.sub_pk_seed),
            "subPkRoot": hex(compact_signature.sub_pk_root),
            "q": compact_signature.q().expect("compact signature encodes q"),
            "message": hex(&compact_message),
            "signature": hex(&compact_signature.raw_signature),
            "slotId": hex(ShrincsSigner::compact_slot_id(
                &compact_signature.sub_pk_seed,
                &compact_signature.sub_pk_root
            )),
            "cases": {
                "valid": compact_case(&compact_message, &compact_signature)
            },
            "actionCases": {
                "first": compact_action_case(
                    &compact_key,
                    compact_first_context,
                    1,
                    1
                ),
                "sameQSecond": compact_action_case(
                    &compact_key,
                    compact_second_context,
                    2,
                    1
                )
            }
        }
    });

    let out = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write SHRINCS Solidity vectors");
    println!("wrote {OUT_PATH}");
}

fn hash_word(label: &[u8]) -> [u8; HASH_LEN] {
    solana_program::keccak::hash(label).to_bytes()
}

fn stateless_case(public_key: &PublicKey, message: &[u8], signature: &StatelessSignature) -> Value {
    json!({
        "publicKey": public_key_json(public_key),
        "message": hex(message),
        "signature": stateless_signature_json(signature),
        "calldata": stateless_calldata(public_key, message, signature)
    })
}

fn compact_case(message: &[u8], signature: &CompactSignature) -> Value {
    json!({
        "subPkSeed": hex(signature.sub_pk_seed),
        "subPkRoot": hex(signature.sub_pk_root),
        "q": signature.q().expect("compact signature encodes q"),
        "message": hex(message),
        "signature": hex(&signature.raw_signature),
        "calldata": compact_calldata(message, signature)
    })
}

fn compact_action_case(
    key: &CompactSigningKey,
    context: ActionContext,
    nonce: u64,
    key_version: u64,
) -> Value {
    let signature =
        ShrincsSigner::sign_compact_action(key, &context).expect("compact action signature");
    let message = ShrincsSigner::compact_action_message_hash(&context);
    json!({
        "subPkSeed": hex(signature.sub_pk_seed),
        "subPkRoot": hex(signature.sub_pk_root),
        "q": signature.q().expect("compact signature encodes q"),
        "context": compact_action_context_json(&context, nonce, key_version),
        "message": hex(message),
        "signature": hex(&signature.raw_signature),
        "calldata": compact_action_calldata(&context, nonce, key_version, &signature)
    })
}

fn compact_action_context(
    domain_label: &[u8],
    nonce: u64,
    key_version: u64,
    action_label: &[u8],
    payload_label: &[u8],
) -> ActionContext {
    ActionContext {
        domain_separator: hash_word(domain_label),
        nonce: uint_word(nonce),
        key_version: uint_word(key_version),
        action_type: hash_word(action_label),
        payload_hash: hash_word(payload_label),
    }
}

fn compact_action_context_json(context: &ActionContext, nonce: u64, key_version: u64) -> Value {
    json!({
        "domainSeparator": hex(context.domain_separator),
        "nonce": nonce,
        "keyVersion": key_version,
        "actionType": hex(context.action_type),
        "payloadHash": hex(context.payload_hash)
    })
}

fn uint_word(value: u64) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn stateless_calldata(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> String {
    let public_key = format!(
        "({},{})",
        hex(&public_key.pk_seed),
        hex(&public_key.hypertree_root)
    );
    let sig = stateless_signature_cast(signature);
    cast_calldata(
        "f((bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key, hex(message), sig],
    )
}

fn compact_calldata(message: &[u8], signature: &CompactSignature) -> String {
    cast_calldata(
        "f(bytes32,bytes32,bytes32,bytes)",
        &[
            hex(signature.sub_pk_seed),
            hex(signature.sub_pk_root),
            hex(message),
            hex(&signature.raw_signature),
        ],
    )
}

fn compact_action_calldata(
    context: &ActionContext,
    nonce: u64,
    key_version: u64,
    signature: &CompactSignature,
) -> String {
    let context_arg = format!(
        "({},{},{},{},{})",
        hex(context.domain_separator),
        nonce,
        key_version,
        hex(context.action_type),
        hex(context.payload_hash)
    );
    cast_calldata(
        "f(bytes32,bytes32,(bytes32,uint256,uint256,bytes32,bytes32),bytes)",
        &[
            hex(signature.sub_pk_seed),
            hex(signature.sub_pk_root),
            context_arg,
            hex(&signature.raw_signature),
        ],
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

fn public_key_json(public_key: &PublicKey) -> Value {
    json!({
        "pkSeed": hex(&public_key.pk_seed),
        "hypertreeRoot": hex(&public_key.hypertree_root)
    })
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
