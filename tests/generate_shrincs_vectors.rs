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

// Output path for the 128s account-wrapper vector fixture (bead
// hashsigs-rs-qxr); see the `account_wrapper_vectors` module at the bottom
// of this file. `tests/common/mod.rs:358-366` selects these same filenames
// per profile.
#[cfg(shrincs_profile_128s_q18)]
const ACCOUNT_VECTORS_OUT_PATH: &str =
    "tests/test_vectors/shrincs_account_wrapper_vectors_128s_q18_keccak.json.gz";
#[cfg(shrincs_profile_128s_q20)]
const ACCOUNT_VECTORS_OUT_PATH: &str =
    "tests/test_vectors/shrincs_account_wrapper_vectors_128s_q20_keccak.json.gz";
// `tests/common/mod.rs` is the shared decode-side oracle
// (`solidity_account_vectors.rs`/`envelope_vectors.rs` also `mod common;`
// it); only the account-wrapper generator below needs it.
#[cfg(any(shrincs_profile_128s_q18, shrincs_profile_128s_q20))]
mod common;

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
    sol_bytes32("EXPECTED_STATEFUL_SK_SEED", &signing_key.stateful_sk_seed);
    sol_bytes32("EXPECTED_STATEFUL_PRF_SEED", &signing_key.stateful_prf_seed);
    sol_bytes32("EXPECTED_STATEFUL_PK_SEED", &signing_key.stateful_pk_seed);
    sol_bytes32("EXPECTED_STATEFUL_ROOT", &signing_key.stateful_root);
    sol_bytes32("EXPECTED_STATELESS_SK_SEED", &signing_key.stateless_sk_seed);
    sol_bytes32(
        "EXPECTED_STATELESS_PRF_SEED",
        &signing_key.stateless_prf_seed,
    );
    sol_bytes32("EXPECTED_PK_SEED", &signing_key.pk_seed);
    sol_bytes32("EXPECTED_HYPERTREE_ROOT", &signing_key.hypertree_root);
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

// =====================================================================
// 128s account-wrapper vector generator (bead hashsigs-rs-qxr)
// =====================================================================
//
// hashsigs-solidity cannot produce the 128s-q18/q20 account-wrapper
// vectors: in-EVM stateless signing at 128s is compute-infeasible, and
// `test/SHRINCSAccountVectorExport.t.sol` is in the 128s foundry.toml skip
// lists. This crate's vectors are Rust-anchored by convention (see
// `docs/solidity-parity.md`), so this generator builds the same four
// bundles `SHRINCSAccountVectorExport.sol` exports in Solidity, encodes
// them with the exact ABI layout `tests/common/mod.rs`'s `AbiDecoder`
// expects, and writes the profile-selected fixture
// `tests/common/mod.rs:358-366` already looks for.
//
// Only the top-level `StatefulActionVector` / `StatelessActionVector` /
// `StatefulOnlyRotationVector` / `FullRotationVector` wrapper structs need
// a dedicated encoder here: `hashsigs_rs::envelope` already
// covers the `verifyStatefulAction`/`verifyStatelessAction` calldata body
// and the ERC-1271 mode-prefixed envelopes (`encode_stateful_action_envelope`
// / `encode_stateless_action_envelope` / `encode_stateful_1271_envelope` /
// `encode_stateless_1271_envelope`), reused directly below. The wrapper
// structs themselves (`currentSHRINCSPublicKey` + inline context + the
// envelope fields + `message`/calldata blobs) have no `src/` consumer, so
// their head/tail ABI encoding lives here rather than being promoted to
// `envelope.rs` (mirrors that module's private primitives; see the
// `AbiField`/`abi_tuple` helpers below).
#[cfg(any(shrincs_profile_128s_q18, shrincs_profile_128s_q20))]
mod account_wrapper_vectors {
    use crate::common::{hex_to_bytes, load_vectors, AbiDecoder};
    use crate::{hash_word, hex, write_gzip_json, ACCOUNT_VECTORS_OUT_PATH};
    use hashsigs_rs::envelope;
    use hashsigs_rs::shrincs::{
        ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey,
        RotationContext, RotationTarget, ShrincsSigner, ShrincsVerifier, StatefulRotationTarget,
        StatefulSignature, StatelessSignature, WotsCSignature, HASH_LEN,
    };
    use serde_json::{json, Value};
    use std::path::Path;

    fn word32(bytes: &[u8]) -> [u8; HASH_LEN] {
        bytes.try_into().expect("value must be exactly 32 bytes")
    }

    // --- minimal head/tail ABI tuple encoder ----------------------------

    enum AbiField {
        Static([u8; HASH_LEN]),
        Dynamic(Vec<u8>),
    }

    fn pad_len(len: usize) -> usize {
        (HASH_LEN - len % HASH_LEN) % HASH_LEN
    }

    fn word_usize(value: usize) -> [u8; HASH_LEN] {
        let mut word = [0u8; HASH_LEN];
        word[24..].copy_from_slice(&(value as u64).to_be_bytes());
        word
    }

    fn word_u32(value: u32) -> [u8; HASH_LEN] {
        let mut word = [0u8; HASH_LEN];
        word[28..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn abi_bytes(data: &[u8]) -> Vec<u8> {
        let pad = pad_len(data.len());
        let mut out = Vec::with_capacity(HASH_LEN + data.len() + pad);
        out.extend_from_slice(&word_usize(data.len()));
        out.extend_from_slice(data);
        out.resize(out.len() + pad, 0);
        out
    }

    fn abi_bytes32_array(items: &[[u8; HASH_LEN]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HASH_LEN + items.len() * HASH_LEN);
        out.extend_from_slice(&word_usize(items.len()));
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn abi_dynamic_array(elements: Vec<Vec<u8>>) -> Vec<u8> {
        let head_len = elements.len() * HASH_LEN;
        let mut out = Vec::with_capacity(HASH_LEN + head_len);
        out.extend_from_slice(&word_usize(elements.len()));
        let mut running = 0usize;
        for element in &elements {
            out.extend_from_slice(&word_usize(head_len + running));
            running += element.len();
        }
        for element in elements {
            out.extend_from_slice(&element);
        }
        out
    }

    fn abi_tuple(fields: Vec<AbiField>) -> Vec<u8> {
        let head_len = fields.len() * HASH_LEN;
        let mut head = Vec::with_capacity(head_len);
        let mut tail = Vec::new();
        let mut running = 0usize;
        for field in fields {
            match field {
                AbiField::Static(word) => head.extend_from_slice(&word),
                AbiField::Dynamic(bytes) => {
                    head.extend_from_slice(&word_usize(head_len + running));
                    running += bytes.len();
                    tail.push(bytes);
                }
            }
        }
        let mut out = head;
        for bytes in tail {
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// `abi.encode(x)` for a single dynamic top-level value: one offset word
    /// plus `x`'s own head/tail body.
    fn abi_encode_root(body: Vec<u8>) -> Vec<u8> {
        abi_tuple(vec![AbiField::Dynamic(body)])
    }

    fn selector(signature: &str) -> [u8; 4] {
        let hash = solana_program::keccak::hash(signature.as_bytes()).to_bytes();
        [hash[0], hash[1], hash[2], hash[3]]
    }

    // --- struct body encoders (mirror envelope.rs's private primitives) -

    fn four_bytes_fields_body(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(a)),
            AbiField::Dynamic(abi_bytes(b)),
            AbiField::Dynamic(abi_bytes(c)),
            AbiField::Dynamic(abi_bytes(d)),
        ])
    }

    fn public_key_body(pk: &PublicKey) -> Vec<u8> {
        four_bytes_fields_body(
            &pk.stateful_public_key,
            &pk.public_key_commitment,
            &pk.pk_seed,
            &pk.hypertree_root,
        )
    }

    fn rotation_target_body(target: &RotationTarget) -> Vec<u8> {
        four_bytes_fields_body(
            &target.stateful_public_key,
            &target.public_key_commitment,
            &target.pk_seed,
            &target.hypertree_root,
        )
    }

    fn stateful_rotation_target_body(target: &StatefulRotationTarget) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(&target.stateful_public_key)),
            AbiField::Dynamic(abi_bytes(&target.public_key_commitment)),
        ])
    }

    fn stateful_signature_body(sig: &StatefulSignature) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Static(sig.randomizer),
            AbiField::Static(word_u32(sig.counter)),
            AbiField::Dynamic(abi_bytes32_array(&sig.chains)),
            AbiField::Dynamic(abi_bytes32_array(&sig.auth_path)),
        ])
    }

    fn fors_entry_body(entry: &ForsEntry) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(&entry.secret_leaf)),
            AbiField::Dynamic(abi_dynamic_array(
                entry.auth_path.iter().map(|node| abi_bytes(node)).collect(),
            )),
        ])
    }

    fn fors_signature_body(sig: &ForsSignature) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(&sig.randomizer)),
            AbiField::Static(word_u32(sig.counter)),
            AbiField::Dynamic(abi_dynamic_array(
                sig.entries.iter().map(fors_entry_body).collect(),
            )),
        ])
    }

    fn wots_c_signature_body(sig: &WotsCSignature) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(&sig.randomizer)),
            AbiField::Static(word_u32(sig.counter)),
            AbiField::Dynamic(abi_dynamic_array(
                sig.chains.iter().map(|node| abi_bytes(node)).collect(),
            )),
        ])
    }

    fn hypertree_layer_body(layer: &HypertreeLayerSignature) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(abi_bytes(&layer.wots_c_pk_hash)),
            AbiField::Dynamic(wots_c_signature_body(&layer.wots_c_signature)),
            AbiField::Dynamic(abi_dynamic_array(
                layer.auth_path.iter().map(|node| abi_bytes(node)).collect(),
            )),
        ])
    }

    fn stateless_signature_body(sig: &StatelessSignature) -> Vec<u8> {
        abi_tuple(vec![
            AbiField::Dynamic(fors_signature_body(&sig.fors)),
            AbiField::Dynamic(abi_dynamic_array(
                sig.hypertree.iter().map(hypertree_layer_body).collect(),
            )),
        ])
    }

    fn action_context_words(ctx: &ActionContext) -> Vec<AbiField> {
        vec![
            AbiField::Static(ctx.domain_separator),
            AbiField::Static(ctx.nonce),
            AbiField::Static(ctx.key_version),
            AbiField::Static(ctx.action_type),
            AbiField::Static(ctx.payload_hash),
        ]
    }

    fn rotation_context_words(ctx: &RotationContext) -> Vec<AbiField> {
        vec![
            AbiField::Static(ctx.domain_separator),
            AbiField::Static(ctx.nonce),
            AbiField::Static(ctx.key_version),
        ]
    }

    // --- vector-wrapper struct encoders ----------------------------------
    // Field order/shape mirrors `SHRINCSAccountVectorExport.sol`'s four
    // structs exactly (verified against `tests/common/mod.rs`'s
    // `AbiDecoder::decode_*_vector` offsets).

    struct StatefulActionParts<'a> {
        current: [u8; HASH_LEN],
        public_key: &'a PublicKey,
        context: &'a ActionContext,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: &'a StatefulSignature,
        message: &'a [u8],
        verify_calldata: &'a [u8],
        erc1271_envelope: &'a [u8],
    }

    fn encode_stateful_action_vector(parts: &StatefulActionParts) -> Vec<u8> {
        let mut fields = vec![
            AbiField::Static(parts.current),
            AbiField::Dynamic(public_key_body(parts.public_key)),
        ];
        fields.extend(action_context_words(parts.context));
        fields.push(AbiField::Static(parts.action_type));
        fields.push(AbiField::Static(parts.payload_hash));
        fields.push(AbiField::Dynamic(stateful_signature_body(parts.signature)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.message)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.verify_calldata)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.erc1271_envelope)));
        abi_encode_root(abi_tuple(fields))
    }

    struct StatelessActionParts<'a> {
        current: [u8; HASH_LEN],
        public_key: &'a PublicKey,
        context: &'a ActionContext,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: &'a StatelessSignature,
        message: &'a [u8],
        verify_calldata: &'a [u8],
        erc1271_envelope: &'a [u8],
    }

    fn encode_stateless_action_vector(parts: &StatelessActionParts) -> Vec<u8> {
        let mut fields = vec![
            AbiField::Static(parts.current),
            AbiField::Dynamic(public_key_body(parts.public_key)),
        ];
        fields.extend(action_context_words(parts.context));
        fields.push(AbiField::Static(parts.action_type));
        fields.push(AbiField::Static(parts.payload_hash));
        fields.push(AbiField::Dynamic(stateless_signature_body(parts.signature)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.message)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.verify_calldata)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.erc1271_envelope)));
        abi_encode_root(abi_tuple(fields))
    }

    struct StatefulOnlyRotationParts<'a> {
        current: [u8; HASH_LEN],
        current_public_key: &'a PublicKey,
        context: &'a RotationContext,
        next_key: &'a StatefulRotationTarget,
        recovery_signature: &'a StatelessSignature,
        message: &'a [u8],
        rotate_calldata: &'a [u8],
    }

    fn encode_stateful_only_rotation_vector(parts: &StatefulOnlyRotationParts) -> Vec<u8> {
        let mut fields = vec![
            AbiField::Static(parts.current),
            AbiField::Dynamic(public_key_body(parts.current_public_key)),
        ];
        fields.extend(rotation_context_words(parts.context));
        fields.push(AbiField::Dynamic(stateful_rotation_target_body(
            parts.next_key,
        )));
        fields.push(AbiField::Dynamic(stateless_signature_body(
            parts.recovery_signature,
        )));
        fields.push(AbiField::Dynamic(abi_bytes(parts.message)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.rotate_calldata)));
        abi_encode_root(abi_tuple(fields))
    }

    struct FullRotationParts<'a> {
        current: [u8; HASH_LEN],
        current_public_key: &'a PublicKey,
        context: &'a RotationContext,
        next_key: &'a RotationTarget,
        recovery_signature: &'a StatelessSignature,
        message: &'a [u8],
        rotate_calldata: &'a [u8],
    }

    fn encode_full_rotation_vector(parts: &FullRotationParts) -> Vec<u8> {
        let mut fields = vec![
            AbiField::Static(parts.current),
            AbiField::Dynamic(public_key_body(parts.current_public_key)),
        ];
        fields.extend(rotation_context_words(parts.context));
        fields.push(AbiField::Dynamic(rotation_target_body(parts.next_key)));
        fields.push(AbiField::Dynamic(stateless_signature_body(
            parts.recovery_signature,
        )));
        fields.push(AbiField::Dynamic(abi_bytes(parts.message)));
        fields.push(AbiField::Dynamic(abi_bytes(parts.rotate_calldata)));
        abi_encode_root(abi_tuple(fields))
    }

    // --- verify/rotate calldata (selector || envelope body) --------------
    // Canonical parameter-type strings taken directly from
    // `SHRINCSAccountVerifierExample.sol` and the `SHRINCS`/`SPHINCSPlusC`
    // struct definitions it calldata-decodes.

    fn verify_stateful_action_calldata(
        public_key: &PublicKey,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: &StatefulSignature,
    ) -> Vec<u8> {
        let mut out = selector(
            "verifyStatefulAction((bytes,bytes,bytes,bytes),bytes32,bytes32,\
             (bytes32,uint32,bytes32[],bytes32[]))",
        )
        .to_vec();
        out.extend_from_slice(&envelope::encode_stateful_action_envelope(
            public_key,
            action_type,
            payload_hash,
            signature,
        ));
        out
    }

    fn verify_stateless_action_calldata(
        public_key: &PublicKey,
        action_type: [u8; HASH_LEN],
        payload_hash: [u8; HASH_LEN],
        signature: &StatelessSignature,
    ) -> Vec<u8> {
        let mut out = selector(
            "verifyStatelessAction((bytes,bytes,bytes,bytes),bytes32,bytes32,\
             ((bytes,uint32,(bytes,bytes[])[]),(bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        )
        .to_vec();
        out.extend_from_slice(&envelope::encode_stateless_action_envelope(
            public_key,
            action_type,
            payload_hash,
            signature,
        ));
        out
    }

    fn rotate_to_fresh_key_calldata(
        current_public_key: &PublicKey,
        recovery_signature: &StatelessSignature,
        next_key: &StatefulRotationTarget,
    ) -> Vec<u8> {
        let mut out = selector(
            "rotateToFreshKey((bytes,bytes,bytes,bytes),\
             ((bytes,uint32,(bytes,bytes[])[]),(bytes,(bytes,uint32,bytes[]),bytes[])[]),\
             (bytes,bytes))",
        )
        .to_vec();
        out.extend_from_slice(&abi_tuple(vec![
            AbiField::Dynamic(public_key_body(current_public_key)),
            AbiField::Dynamic(stateless_signature_body(recovery_signature)),
            AbiField::Dynamic(stateful_rotation_target_body(next_key)),
        ]));
        out
    }

    fn rotate_full_key_calldata(
        current_public_key: &PublicKey,
        recovery_signature: &StatelessSignature,
        next_key: &RotationTarget,
    ) -> Vec<u8> {
        let mut out = selector(
            "rotateFullKey((bytes,bytes,bytes,bytes),\
             ((bytes,uint32,(bytes,bytes[])[]),(bytes,(bytes,uint32,bytes[]),bytes[])[]),\
             (bytes,bytes,bytes,bytes))",
        )
        .to_vec();
        out.extend_from_slice(&abi_tuple(vec![
            AbiField::Dynamic(public_key_body(current_public_key)),
            AbiField::Dynamic(stateless_signature_body(recovery_signature)),
            AbiField::Dynamic(rotation_target_body(next_key)),
        ]));
        out
    }

    // --- bundle builders ---------------------------------------------------

    fn build_stateful_action_bundle() -> Value {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) =
            ShrincsSigner::keygen(b"128s account vectors: stateful action current key", 4)
                .expect("stateful action current keygen");
        let current = word32(&public_key.public_key_commitment);
        let context = ActionContext {
            domain_separator: hash_word(b"128s account vectors: stateful action domain"),
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
            action_type: hash_word(b"execute"),
            payload_hash: hash_word(b"payload"),
        };
        let signature =
            ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context)
                .expect("stateful action signing");
        let message = verifier.stateful_action_message_hash(current, &context);
        assert!(
            verifier.verify_stateful(current, &public_key, &context, &signature),
            "freshly generated stateful action signature must verify"
        );

        let verify_calldata = verify_stateful_action_calldata(
            &public_key,
            context.action_type,
            context.payload_hash,
            &signature,
        );
        let erc1271_envelope = envelope::encode_stateful_1271_envelope(
            &public_key,
            context.action_type,
            context.payload_hash,
            &signature,
        );
        let vector_abi = encode_stateful_action_vector(&StatefulActionParts {
            current,
            public_key: &public_key,
            context: &context,
            action_type: context.action_type,
            payload_hash: context.payload_hash,
            signature: &signature,
            message: &message,
            verify_calldata: &verify_calldata,
            erc1271_envelope: &erc1271_envelope,
        });

        json!({
            "stateful_vector_abi": hex(&vector_abi),
            "stateful_verify_calldata": hex(&verify_calldata),
            "stateful_1271_envelope": hex(&erc1271_envelope),
        })
    }

    fn build_stateless_action_bundle() -> Value {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"128s account vectors: stateless action current key", 4)
                .expect("stateless action current keygen");
        let current = word32(&public_key.public_key_commitment);
        let context = ActionContext {
            domain_separator: hash_word(b"128s account vectors: stateless action domain"),
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
            action_type: hash_word(b"execute"),
            payload_hash: hash_word(b"payload"),
        };
        let message = verifier.stateless_action_message_hash(current, &context);
        let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message)
            .expect("stateless action signing");
        assert!(
            verifier.verify_stateless(current, &public_key, &context, &signature),
            "freshly generated stateless action signature must verify"
        );

        let verify_calldata = verify_stateless_action_calldata(
            &public_key,
            context.action_type,
            context.payload_hash,
            &signature,
        );
        let erc1271_envelope = envelope::encode_stateless_1271_envelope(
            &public_key,
            context.action_type,
            context.payload_hash,
            &signature,
        );
        let vector_abi = encode_stateless_action_vector(&StatelessActionParts {
            current,
            public_key: &public_key,
            context: &context,
            action_type: context.action_type,
            payload_hash: context.payload_hash,
            signature: &signature,
            message: &message,
            verify_calldata: &verify_calldata,
            erc1271_envelope: &erc1271_envelope,
        });

        json!({
            "stateless_vector_abi": hex(&vector_abi),
            "stateless_verify_calldata": hex(&verify_calldata),
            "stateless_1271_envelope": hex(&erc1271_envelope),
        })
    }

    fn build_stateful_only_rotation_bundle() -> Value {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = ShrincsSigner::keygen(
            b"128s account vectors: stateful-only rotation current key",
            4,
        )
        .expect("stateful-only rotation current keygen");
        let current = word32(&public_key.public_key_commitment);
        let (_, next_source_key) =
            ShrincsSigner::keygen(b"128s account vectors: stateful-only rotation next key", 4)
                .expect("stateful-only rotation next keygen");
        // The next stateful-only commitment mixes the replacement stateful
        // key with the *current* key's stateless pk_seed/hypertree_root
        // (`SHRINCSAccountSigningFacade.statefulRotationTarget`): a
        // stateful-only rotation keeps the stateless component pinned.
        let next_commitment = verifier.public_key_commitment(
            &next_source_key.stateful_public_key,
            word32(&public_key.pk_seed),
            word32(&public_key.hypertree_root),
        );
        let next_key = StatefulRotationTarget {
            stateful_public_key: next_source_key.stateful_public_key.clone(),
            public_key_commitment: next_commitment.to_vec(),
        };
        let context = RotationContext {
            domain_separator: hash_word(b"128s account vectors: stateful-only rotation domain"),
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
        };
        let message =
            verifier.stateful_rotation_message_hash(current, &public_key, &context, &next_key);
        let recovery_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message)
            .expect("stateful-only rotation recovery signing");
        let rotated = verifier
            .rotate_stateful_via_stateless(
                current,
                &public_key,
                &context,
                &recovery_signature,
                &next_key,
            )
            .expect("freshly generated stateful-only rotation vector must verify");
        assert_eq!(rotated, next_commitment);

        let rotate_calldata =
            rotate_to_fresh_key_calldata(&public_key, &recovery_signature, &next_key);
        let vector_abi = encode_stateful_only_rotation_vector(&StatefulOnlyRotationParts {
            current,
            current_public_key: &public_key,
            context: &context,
            next_key: &next_key,
            recovery_signature: &recovery_signature,
            message: &message,
            rotate_calldata: &rotate_calldata,
        });

        json!({
            "stateful_rotation_vector_abi": hex(&vector_abi),
            "stateful_rotation_calldata": hex(&rotate_calldata),
        })
    }

    fn build_full_rotation_bundle() -> Value {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) =
            ShrincsSigner::keygen(b"128s account vectors: full rotation current key", 4)
                .expect("full rotation current keygen");
        let current = word32(&public_key.public_key_commitment);
        let (_, next_public_key) =
            ShrincsSigner::keygen(b"128s account vectors: full rotation next key", 4)
                .expect("full rotation next keygen");
        // A full rotation replaces the stateless component too, so the next
        // commitment is simply the replacement key's own natural commitment
        // (`SHRINCSAccountSigningFacade.fullRotationTarget`).
        let next_key = RotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_public_key.public_key_commitment.clone(),
            pk_seed: next_public_key.pk_seed.clone(),
            hypertree_root: next_public_key.hypertree_root.clone(),
        };
        let context = RotationContext {
            domain_separator: hash_word(b"128s account vectors: full rotation domain"),
            nonce: [0u8; HASH_LEN],
            key_version: [0u8; HASH_LEN],
        };
        let message =
            verifier.full_rotation_message_hash(current, &public_key, &context, &next_key);
        let recovery_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message)
            .expect("full rotation recovery signing");
        let rotated = verifier
            .stateless_rotate(
                current,
                &public_key,
                &context,
                &recovery_signature,
                &next_key,
            )
            .expect("freshly generated full rotation vector must verify");
        assert_eq!(rotated, word32(&next_key.public_key_commitment));

        let rotate_calldata = rotate_full_key_calldata(&public_key, &recovery_signature, &next_key);
        let vector_abi = encode_full_rotation_vector(&FullRotationParts {
            current,
            current_public_key: &public_key,
            context: &context,
            next_key: &next_key,
            recovery_signature: &recovery_signature,
            message: &message,
            rotate_calldata: &rotate_calldata,
        });

        json!({
            "full_rotation_vector_abi": hex(&vector_abi),
            "full_rotation_calldata": hex(&rotate_calldata),
        })
    }

    // --- self-check: reload the written fixture and re-verify ------------

    fn self_check_account_vectors() {
        let verifier = ShrincsVerifier::new();
        let vectors = load_vectors();

        let stateful = &vectors["testExportStatefulActionBundle"];
        let stateful_vector = AbiDecoder::new(&hex_to_bytes(
            stateful["stateful_vector_abi"]
                .as_str()
                .expect("stateful_vector_abi"),
        ))
        .decode_root_stateful_action_vector();
        assert!(verifier.verify_stateful(
            stateful_vector.current_shrincs_public_key,
            &stateful_vector.public_key,
            &stateful_vector.context,
            &stateful_vector.signature,
        ));
        assert!(matches!(
            envelope::decode_1271_envelope(&hex_to_bytes(
                stateful["stateful_1271_envelope"]
                    .as_str()
                    .expect("stateful_1271_envelope"),
            )),
            Some(envelope::Erc1271Envelope::Stateful { .. })
        ));

        let stateless = &vectors["testExportStatelessActionBundle"];
        let stateless_vector = AbiDecoder::new(&hex_to_bytes(
            stateless["stateless_vector_abi"]
                .as_str()
                .expect("stateless_vector_abi"),
        ))
        .decode_root_stateless_action_vector();
        assert!(verifier.verify_stateless(
            stateless_vector.current_shrincs_public_key,
            &stateless_vector.public_key,
            &stateless_vector.context,
            &stateless_vector.signature,
        ));
        assert!(matches!(
            envelope::decode_1271_envelope(&hex_to_bytes(
                stateless["stateless_1271_envelope"]
                    .as_str()
                    .expect("stateless_1271_envelope"),
            )),
            Some(envelope::Erc1271Envelope::Stateless { .. })
        ));

        let stateful_rotation = &vectors["testExportStatefulOnlyRotationBundle"];
        let stateful_rotation_vector = AbiDecoder::new(&hex_to_bytes(
            stateful_rotation["stateful_rotation_vector_abi"]
                .as_str()
                .expect("stateful_rotation_vector_abi"),
        ))
        .decode_root_stateful_only_rotation_vector();
        let next_commitment = verifier
            .rotate_stateful_via_stateless(
                stateful_rotation_vector.current_shrincs_public_key,
                &stateful_rotation_vector.current_public_key,
                &stateful_rotation_vector.context,
                &stateful_rotation_vector.recovery_signature,
                &stateful_rotation_vector.next_key,
            )
            .expect("reloaded stateful-only rotation vector must verify");
        assert_eq!(
            next_commitment,
            word32(&stateful_rotation_vector.next_key.public_key_commitment)
        );

        let full_rotation = &vectors["testExportFullRotationBundle"];
        let full_rotation_vector = AbiDecoder::new(&hex_to_bytes(
            full_rotation["full_rotation_vector_abi"]
                .as_str()
                .expect("full_rotation_vector_abi"),
        ))
        .decode_root_full_rotation_vector();
        let next_full_commitment = verifier
            .stateless_rotate(
                full_rotation_vector.current_shrincs_public_key,
                &full_rotation_vector.current_public_key,
                &full_rotation_vector.context,
                &full_rotation_vector.recovery_signature,
                &full_rotation_vector.next_key,
            )
            .expect("reloaded full rotation vector must verify");
        assert_eq!(
            next_full_commitment,
            word32(&full_rotation_vector.next_key.public_key_commitment)
        );

        println!("self-check passed: reloaded fixture verifies via ShrincsVerifier + AbiDecoder");
    }

    // Six full keygens (each a 2^18-leaf hypertree) plus three FORS-C
    // stateless grinds: run explicitly, not part of the default suite.
    #[test]
    #[ignore = "run explicitly to generate the 128s account-wrapper vector fixture (several minutes: six 2^18-leaf hypertree keygens plus three FORS-C stateless grinds)"]
    fn generate_shrincs_account_wrapper_vectors() {
        let vectors = json!({
            "testExportStatefulActionBundle": build_stateful_action_bundle(),
            "testExportStatelessActionBundle": build_stateless_action_bundle(),
            "testExportStatefulOnlyRotationBundle": build_stateful_only_rotation_bundle(),
            "testExportFullRotationBundle": build_full_rotation_bundle(),
        });

        let out = serde_json::to_vec_pretty(&vectors).expect("serialize account vectors");
        write_gzip_json(Path::new(ACCOUNT_VECTORS_OUT_PATH), &out);
        println!("wrote {ACCOUNT_VECTORS_OUT_PATH}");

        self_check_account_vectors();
    }
}
