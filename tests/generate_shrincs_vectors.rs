// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hashsigs_rs::shrincs::{
    CompactSignature, PublicKey, ShrincsSigner, StatefulSignature, StatelessSignature, HASH_LEN,
};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_256s_keccak.json";

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

    let mut wrong_stateful_message = stateful_message.clone();
    wrong_stateful_message[0] ^= 1;
    let mut wrong_stateless_message = stateless_message.clone();
    wrong_stateless_message[0] ^= 1;

    let mut wrong_stateful_public_key = stateful_public_key.clone();
    wrong_stateful_public_key.stateful_public_key[32] ^= 1;

    let mut corrupted_stateful_signature = stateful_signature.clone();
    corrupted_stateful_signature.chains[0][0] ^= 1;

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

fn stateful_calldata(
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> String {
    let encoded = &public_key.stateful_public_key;
    let key = format!(
        "({},{},{})",
        hex(&encoded[0..32]),
        hex(&encoded[32..64]),
        u32::from_be_bytes(encoded[64..68].try_into().expect("max signatures"))
    );
    let sig = format!(
        "({},{},{},{})",
        hex(signature.randomizer),
        signature.counter,
        fixed_array(signature.chains.iter().map(hex)),
        fixed_array(signature.auth_path.iter().map(hex))
    );
    cast_calldata(
        "f((bytes32,bytes32,uint32),bytes,(bytes32,uint32,bytes32[64],bytes32[]))",
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
        "randomizer": hex(signature.randomizer),
        "counter": signature.counter,
        "chains": signature.chains.iter().map(hex).collect::<Vec<_>>(),
        "authPath": signature.auth_path.iter().map(hex).collect::<Vec<_>>()
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
