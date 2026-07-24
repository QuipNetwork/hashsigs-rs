// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use flate2::write::GzEncoder;
use flate2::Compression;
use hashsigs_rs::shrincs::{
    PublicKey, ShrincsSigner, StatefulSignature, StatelessSignature, HASH_LEN,
};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

// Output path per compiled profile, mirroring the profile the crate was built
// with. The default build keeps the original filename. Emitting the
// non-default profiles requires building this test crate with
// `--features <profile>`; note that 128s stateless generation is
// the heavy, cache-backed regeneration event (2^24-leaf FORS trees, 2^18-leaf
// hypertree) rather than an in-line run.
#[cfg(shrincs_profile_256s)]
const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_256s_keccak.json.gz";
#[cfg(shrincs_profile_128s_q18)]
const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_128s_q18_keccak.json.gz";
#[cfg(shrincs_profile_128s_q20)]
const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_128s_q20_keccak.json.gz";
#[cfg(shrincs_profile_256s_sha2)]
const OUT_PATH: &str = "tests/test_vectors/shrincs_sphincs_256s_sha2.json.gz";

#[test]
#[ignore = "run explicitly to refresh Solidity SHRINCS vectors"]
fn generate_shrincs_sphincs_vectors() {
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
        }
    });

    let out = serde_json::to_vec_pretty(&vectors).expect("serialize vectors");
    write_gzip_json(Path::new(OUT_PATH), &out);
    println!("wrote {OUT_PATH}");
}

fn write_gzip_json(path: &Path, json: &[u8]) {
    let file = fs::File::create(path).expect("create SHRINCS Solidity vectors");
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder
        .write_all(json)
        .expect("write compressed SHRINCS Solidity vectors");
    encoder
        .write_all(b"\n")
        .expect("terminate compressed SHRINCS Solidity vectors");
    encoder
        .finish()
        .expect("finish compressed SHRINCS Solidity vectors");
}

// Emit the SHRINCSSignerKeygen.t.sol `EXPECTED_*` anchors for the active
// compile-time profile. The Solidity test drives keygen("solidity public key
// seed", 4); this reproduces the same call so the printed constants can be
// pasted directly into the per-profile golden block. Run once per profile
// feature (`--features profile-128s-q18` / `-q20`);
// under a 128s profile this performs the heavy 2^18-leaf hypertree keygen.
#[test]
#[ignore = "run explicitly to refresh SHRINCSSignerKeygen anchors"]
fn emit_keygen_goldens() {
    let profile = hashsigs_rs::shrincs::PROFILE_NAME;
    let (signing_key, public_key) =
        ShrincsSigner::keygen(b"solidity public key seed", 4).expect("keygen");

    let sol_bytes32 = |label: &str, bytes: &[u8]| {
        println!(
            "    bytes32 internal constant {label} =\n        {};",
            hex(bytes)
        );
    };

    println!("// ==== SHRINCSSignerKeygen goldens for profile {profile} ====");
    sol_bytes32(
        "EXPECTED_STATEFUL_SK_SEED",
        signing_key.stateful.secret.sk_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_STATEFUL_PRF_SEED",
        signing_key.stateful.secret.prf_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_STATEFUL_PK_SEED",
        signing_key.stateful.public_key.pk_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_STATEFUL_ROOT",
        signing_key.stateful.public_key.root.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_STATELESS_SK_SEED",
        signing_key.stateless.secret.sk_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_STATELESS_PRF_SEED",
        signing_key.stateless.secret.prf_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_PK_SEED",
        signing_key.stateless.public_key.pk_seed.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_HYPERTREE_ROOT",
        signing_key.stateless.public_key.root.as_bytes(),
    );
    sol_bytes32(
        "EXPECTED_PUBLIC_KEY_COMMITMENT",
        &public_key.public_key_commitment,
    );
    println!(
        "    bytes internal constant EXPECTED_STATEFUL_PUBLIC_KEY =\n        hex\"{}\";",
        hex(&public_key.stateful_public_key).trim_start_matches("0x")
    );
    println!("// ==== end goldens for profile {profile} ====");
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
    // The stateful WOTS-C chain array is a fixed-size `bytes32[NUM_WOTS_CHAINS]`
    // in the per-profile Solidity struct (64 for 256s, 32 for the 128s
    // profiles), so the ABI type must track the active profile's chain count.
    let stateful_type = format!(
        "f((bytes32,bytes32,uint32),bytes,(bytes32,uint32,bytes32[{}],bytes32[]))",
        signature.chains.len()
    );
    cast_calldata(&stateful_type, &[key, hex(message), sig])
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
        "f((bytes,bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key, hex(message), sig],
    )
}

fn stateless_signature_cast(signature: &StatelessSignature) -> String {
    let fors_entries = signature.fors.entries.iter().map(|entry| {
        format!(
            "({},{})",
            hex(entry.secret_leaf),
            fixed_array(entry.auth_path.iter().map(hex))
        )
    });
    let fors = format!(
        "({},{},{})",
        hex(signature.fors.randomizer),
        signature.fors.counter,
        fixed_array(fors_entries)
    );
    let layers = signature.hypertree.iter().map(|layer| {
        let wots = format!(
            "({},{},{})",
            hex(layer.wots_c_signature.randomizer),
            layer.wots_c_signature.counter,
            fixed_array(layer.wots_c_signature.chains.iter().map(hex))
        );
        format!(
            "({},{},{})",
            hex(layer.wots_c_pk_hash),
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
            "randomizer": hex(signature.fors.randomizer),
            "counter": signature.fors.counter,
            "entries": signature.fors.entries.iter().map(|entry| json!({
                "secretLeaf": hex(entry.secret_leaf),
                "sk": hex(entry.secret_leaf),
                "authPath": entry.auth_path.iter().map(hex).collect::<Vec<_>>(),
                "auth": entry.auth_path.iter().map(hex).collect::<Vec<_>>()
            })).collect::<Vec<_>>()
        },
        "hypertree": signature.hypertree.iter().map(|layer| json!({
            "wotsCPkHash": hex(layer.wots_c_pk_hash),
            "wotsCSignature": {
                "randomizer": hex(layer.wots_c_signature.randomizer),
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

