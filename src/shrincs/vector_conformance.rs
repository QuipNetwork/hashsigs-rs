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

//! Regression guard over the committed SHRINCS golden vector.
//!
//! `tests/test_vectors/shrincs_sphincs_256s_keccak.json` is the cross-implementation
//! reference the Solidity verifier is also checked against. It is produced by the
//! (ignored) generator in `tests/generate_shrincs_vectors.rs`. Without a consuming
//! test, a signer change could silently emit a different — possibly unverifiable —
//! golden file with nothing failing. This test loads the committed file and asserts
//! the Rust verifier accepts the `valid` case and rejects every tampered case.
//!
//! Scope: the stateless section only. Its `publicKey` records the full public key
//! (stateful key, commitment, pk_seed, hypertree root), which is exactly what
//! `verify_stateless_unsafe_raw` needs. The stateful section stores only the 68-byte
//! stateful sub-key, so it cannot reconstruct the full `PublicKey` that the stateful
//! verify path requires — covering it needs a generator/schema change (see the
//! `review` bead).

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use super::verifier::{
    ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, ShrincsVerifier,
    StatelessSignature, WotsCSignature, HASH_LEN,
};

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/test_vectors/shrincs_sphincs_256s_keccak.json")
}

fn hex_to_vec(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex field must be a string");
    let body = text.strip_prefix("0x").unwrap_or(text);
    assert!(body.len() % 2 == 0, "hex string must have even length");
    (0..body.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&body[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn hex_to_hash(value: &Value) -> [u8; HASH_LEN] {
    hex_to_vec(value)
        .try_into()
        .expect("commitment must be exactly 32 bytes")
}

fn hex_list(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .expect("expected a JSON array of hex strings")
        .iter()
        .map(hex_to_vec)
        .collect()
}

fn u64_field(parent: &Value, key: &str) -> u64 {
    parent[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field {key} must be an unsigned integer"))
}

fn parse_public_key(value: &Value) -> PublicKey {
    PublicKey {
        stateful_public_key: hex_to_vec(&value["statefulPublicKey"]),
        public_key_commitment: hex_to_vec(&value["publicKeyCommitment"]),
        pk_seed: hex_to_vec(&value["pkSeed"]),
        hypertree_root: hex_to_vec(&value["hypertreeRoot"]),
    }
}

fn parse_stateless_signature(value: &Value) -> StatelessSignature {
    let fors_value = &value["fors"];
    let entries = fors_value["entries"]
        .as_array()
        .expect("fors.entries must be an array")
        .iter()
        .map(|entry| ForsEntry {
            secret_leaf: hex_to_vec(&entry["secretLeaf"]),
            auth_path: hex_list(&entry["authPath"]),
        })
        .collect();
    let fors = ForsSignature {
        randomizer: hex_to_vec(&fors_value["randomizer"]),
        counter: u64_field(fors_value, "counter") as u32,
        entries,
    };
    let hypertree = value["hypertree"]
        .as_array()
        .expect("hypertree must be an array")
        .iter()
        .map(|layer| {
            let wots = &layer["wotsCSignature"];
            HypertreeLayerSignature {
                tree_index: u64_field(layer, "treeIndex"),
                leaf_index: u64_field(layer, "leafIndex") as u32,
                wots_c_pk_hash: hex_to_vec(&layer["wotsCPkHash"]),
                wots_c_signature: WotsCSignature {
                    randomizer: hex_to_vec(&wots["randomizer"]),
                    counter: u64_field(wots, "counter") as u32,
                    chains: hex_list(&wots["chains"]),
                },
                auth_path: hex_list(&layer["authPath"]),
            }
        })
        .collect();
    StatelessSignature { fors, hypertree }
}

/// Verify one stateless case against the installed commitment recorded in its own
/// public key. Tampered-public-key cases keep the original commitment, so the
/// verifier's commitment recomputation catches the mutated components.
fn verify_stateless_case(case: &Value) -> bool {
    let public_key = parse_public_key(&case["publicKey"]);
    let expected_commitment = hex_to_hash(&case["publicKey"]["publicKeyCommitment"]);
    let message = hex_to_vec(&case["message"]);
    let signature = parse_stateless_signature(&case["signature"]);
    ShrincsVerifier::new().verify_stateless_unsafe_raw(
        expected_commitment,
        &public_key,
        &message,
        &signature,
    )
}

#[test]
fn stateless_golden_vector_accepts_valid_and_rejects_tampered() {
    let raw = fs::read_to_string(vector_path()).unwrap_or_else(|error| {
        panic!(
            "failed to read committed golden vector at {}: {error}",
            vector_path().display()
        )
    });
    let vectors: Value = serde_json::from_str(&raw).expect("golden vector must be valid JSON");
    let cases = &vectors["stateless"]["cases"];

    assert!(
        verify_stateless_case(&cases["valid"]),
        "the valid stateless golden case must verify; a signer regression broke the reference vector"
    );

    // Every negative case must be rejected. These mirror the mutations the generator
    // applies (wrong message, tampered FORS entry, tampered hypertree WOTS pk hash,
    // tampered hypertree auth path, wrong public root, tampered component public key).
    for name in [
        "wrongMessage",
        "tamperedFors",
        "tamperedHypertreeWotsPkHash",
        "tamperedHypertreeAuth",
        "wrongPublicRoot",
        "tamperedComponentPublicKey",
    ] {
        let case = &cases[name];
        assert!(
            !case.is_null(),
            "golden vector is missing expected stateless case '{name}'"
        );
        assert!(
            !verify_stateless_case(case),
            "tampered stateless golden case '{name}' must be rejected but verified true"
        );
    }
}
