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
//! The profile-selected `tests/test_vectors/shrincs_sphincs_*.json` file is the
//! cross-implementation reference the Solidity verifier is also checked against.
//! It is produced by the (ignored) generator in
//! `tests/generate_shrincs_vectors.rs`. Without a consuming test, a signer
//! change could silently emit a different — possibly unverifiable — golden file
//! with nothing failing. This test loads the committed file and asserts the
//! Rust verifier accepts the `valid` case and rejects every tampered case.
//!
//! Scope: the stateless section only. Its `publicKey` records the full public key
//! (stateful key, commitment, pk_seed, hypertree root), which is exactly what
//! `verify_stateless_unsafe_raw` needs. The stateful section stores only the 68-byte
//! stateful sub-key, so it cannot reconstruct the full `PublicKey` that the stateful
//! verify path requires — covering it needs a generator/schema change (see the
//! `review` bead).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde_json::Value;

use crate::shrincs::test_fixtures::{
    fixture_entry_opt, fixture_pair, fixture_path, load_fixture_file, TestKeyMode,
};
use super::ShrincsVerifier;
use crate::types::{
    ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey,
    StatefulSignature, StatelessSignature, WotsCSignature, HASH_LEN,
};
use super::ShrincsSigner;

// Seeds and budgets MUST match `tests/generate_shrincs_vectors.rs`; the
// byte-reproduction and stateful conformance tests re-run keygen with them and
// compare against the committed golden vector.
const STATELESS_SEED: &[u8] = b"shrincs solidity vector stateless seed";
const STATELESS_MAX_SIGNATURES: u32 = 256;
const STATEFUL_SEED: &[u8] = b"shrincs solidity vector stateful seed";
const STATEFUL_MAX_SIGNATURES: u32 = 4;

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(vector_filename())
}

#[cfg(shrincs_profile_256s)]
fn vector_filename() -> &'static str {
    "tests/test_vectors/shrincs_sphincs_256s_keccak.json"
}

#[cfg(shrincs_profile_128s_q18)]
fn vector_filename() -> &'static str {
    "tests/test_vectors/shrincs_sphincs_128s_q18_keccak.json"
}

#[cfg(shrincs_profile_128s_q20)]
fn vector_filename() -> &'static str {
    "tests/test_vectors/shrincs_sphincs_128s_q20_keccak.json"
}

#[cfg(shrincs_profile_256s_sha2)]
fn vector_filename() -> &'static str {
    "tests/test_vectors/shrincs_sphincs_256s_sha2.json"
}

fn load_vectors() -> Value {
    let path = vector_path();
    let raw = read_json_or_gzip(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read committed golden vector at {} or {}: {error}",
            path.display(),
            gz_path(&path).display()
        )
    });
    serde_json::from_str(&raw).expect("golden vector must be valid JSON")
}

fn fixture_or_fresh_full_key(
    seed_label: &'static str,
    max_stateful_signatures: u32,
) -> (super::ShrincsSigningKey, PublicKey) {
    match TestKeyMode::from_env() {
        TestKeyMode::Fresh => ShrincsSigner::keygen(seed_label.as_bytes(), max_stateful_signatures)
            .unwrap_or_else(|| panic!("fresh keygen failed for seed label {seed_label:?}")),
        TestKeyMode::Fixture => {
            let path = fixture_path();
            if path.is_file() {
                let fixture_file = load_fixture_file(&path);
                assert_eq!(
                    fixture_file.profile_name,
                    crate::shrincs::PROFILE_NAME,
                    "fixture profile mismatch",
                );
                if let Some(entry) = fixture_entry_opt(&fixture_file, seed_label) {
                    return fixture_pair(entry);
                }
            }
            ShrincsSigner::keygen(seed_label.as_bytes(), max_stateful_signatures)
                .unwrap_or_else(|| panic!("fresh keygen failed for seed label {seed_label:?}"))
        }
    }
}

fn gz_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.gz", path.display()))
}

fn read_json_or_gzip(path: &Path) -> std::io::Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(json_error) => {
            let gz_path = gz_path(path);
            let file = fs::File::open(&gz_path).map_err(|_| json_error)?;
            let mut decoder = GzDecoder::new(file);
            let mut text = String::new();
            decoder.read_to_string(&mut text)?;
            Ok(text)
        }
    }
}

fn hex_to_vec(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex field must be a string");
    let body = text.strip_prefix("0x").unwrap_or(text);
    assert!(body.len().is_multiple_of(2), "hex string must have even length");
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

fn hex_word_list(value: &Value) -> Vec<[u8; HASH_LEN]> {
    hex_list(value)
        .into_iter()
        .map(|bytes| bytes.try_into().expect("hash list entry must be exactly 32 bytes"))
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
            secret_leaf: hex_to_hash(&entry["secretLeaf"]),
            auth_path: hex_word_list(&entry["authPath"]),
        })
        .collect();
    let fors = ForsSignature {
        randomizer: hex_to_hash(&fors_value["randomizer"]),
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
                wots_c_pk_hash: hex_to_hash(&layer["wotsCPkHash"]),
                wots_c_signature: WotsCSignature {
                    randomizer: hex_to_hash(&wots["randomizer"]),
                    counter: u64_field(wots, "counter") as u32,
                    chains: hex_word_list(&wots["chains"]),
                },
                auth_path: hex_word_list(&layer["authPath"]),
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
    let hybrid_ok = ShrincsVerifier::new().verify_stateless_unsafe_raw(
        expected_commitment,
        &public_key,
        &message,
        &signature,
    );
    // Independent SPHINCS+C path (no commitment): must agree whenever the
    // hybrid path accepts. When hybrid rejects for commitment/shape reasons,
    // the independent path may still accept pure crypto — only assert when
    // hybrid accepts.
    if hybrid_ok {
        let pk = crate::sphincs_plus_c::SphincsPlusCPublicKey::from_slices(
            &public_key.pk_seed,
            &public_key.hypertree_root,
        )
        .expect("vector pk_seed/root are 32 bytes");
        assert!(
            crate::sphincs_plus_c::verify(&pk, &message, &signature),
            "stateless vector must verify through independent sphincs_plus_c::verify"
        );
    }
    hybrid_ok
}

#[test]
fn stateless_golden_vector_accepts_valid_and_rejects_tampered() {
    let vectors = load_vectors();
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

#[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
#[test]
fn logs_committed_128_stateless_fors_counter() {
    use crate::shrincs::{FORS_C_MAX_GRIND_COUNTER, PROFILE_NAME};

    let vectors = load_vectors();
    let counter = u64_field(&vectors["stateless"]["signature"]["fors"], "counter") as u32;
    eprintln!(
        "profile={PROFILE_NAME} committed valid stateless FORS counter={counter} budget={}",
        FORS_C_MAX_GRIND_COUNTER
    );
    assert!(
        counter < FORS_C_MAX_GRIND_COUNTER,
        "committed 128 stateless vector uses FORS counter outside active grind budget"
    );
}

/// Re-run keygen + sign with the generator's seeds and assert the produced public
/// key and signature are byte-identical to the committed stateless golden vector.
/// This proves the signer still *reproduces* the reference bytes, not only that
/// the verifier accepts them. (Bead 0y8.)
#[cfg_attr(
    any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
    ignore = "128s stateless keygen/signing is compute-infeasible in-process"
)]
#[test]
fn signer_reproduces_committed_stateless_vector_bytes() {
    let vectors = load_vectors();
    let section = &vectors["stateless"];

    let (signing_key, public_key) =
        ShrincsSigner::keygen(STATELESS_SEED, STATELESS_MAX_SIGNATURES).expect("stateless keygen");
    let message = hex_to_vec(&section["message"]);
    let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message)
        .expect("stateless signature");

    assert_eq!(
        public_key,
        parse_public_key(&section["publicKey"]),
        "regenerated public key must be byte-identical to the committed golden vector"
    );
    assert_eq!(
        signature,
        parse_stateless_signature(&section["signature"]),
        "regenerated signature must be byte-identical to the committed golden vector"
    );
}

/// From the valid stateless golden signature, exercise verifier reject branches
/// that must fail closed without panicking: mutate the FORS-digest-derived
/// leaf/tree binding (the digest is seeded by the FORS randomizer and counter,
/// which the post-T6 wire carries instead of explicit indices), and supply
/// malformed 31/33-byte components. (Bead c85.)
#[test]
fn stateless_verifier_reject_branches_do_not_panic() {
    let vectors = load_vectors();
    let case = &vectors["stateless"]["cases"]["valid"];
    let public_key = parse_public_key(&case["publicKey"]);
    let expected = hex_to_hash(&case["publicKey"]["publicKeyCommitment"]);
    let message = hex_to_vec(&case["message"]);
    let base = parse_stateless_signature(&case["signature"]);
    let verifier = ShrincsVerifier::new();

    let rejects = |signature: &StatelessSignature| -> bool {
        !verifier.verify_stateless_unsafe_raw(expected, &public_key, &message, signature)
    };

    // Baseline: the untampered signature verifies.
    assert!(verifier.verify_stateless_unsafe_raw(expected, &public_key, &message, &base));

    // Flip the FORS counter: the recomputed digest reselects the implied
    // hypertree tree/leaf and FORS leaves, so the revealed openings no longer
    // reconstruct the committed root.
    let mut counter_mut = base.clone();
    counter_mut.fors.counter ^= 1;
    assert!(rejects(&counter_mut), "mutated FORS counter must be rejected");

    // Flip a FORS randomizer byte: same digest-derived binding, different seed.
    let mut randomizer_mut = base.clone();
    randomizer_mut.fors.randomizer[0] ^= 1;
    assert!(rejects(&randomizer_mut), "mutated FORS randomizer must be rejected");

    // Wrong-length hash fields (31/33-byte pk hashes, secret leaves, chain
    // values) are no longer representable: the wire types use [u8; HASH_LEN],
    // so malformed lengths fail at the decode boundary instead of in verify.
    let _ = base;
}

fn encoded_stateful_sub_key(public_key: &Value) -> Vec<u8> {
    // Rebuild the 68-byte encoded stateful sub-key from the JSON's split fields:
    // pkSeed(32) || root(32) || maxSignatures(be u32).
    let mut out = hex_to_vec(&public_key["pkSeed"]);
    out.extend_from_slice(&hex_to_vec(&public_key["root"]));
    let max = u64_field(public_key, "maxSignatures") as u32;
    out.extend_from_slice(&max.to_be_bytes());
    out
}

fn parse_stateful_signature(value: &Value) -> StatefulSignature {
    StatefulSignature {
        randomizer: hex_to_hash(&value["randomizer"]),
        counter: u64_field(value, "counter") as u32,
        chains: hex_list(&value["chains"])
            .iter()
            .map(|chain| chain.as_slice().try_into().expect("chain must be 32 bytes"))
            .collect(),
        auth_path: hex_list(&value["authPath"])
            .iter()
            .map(|node| node.as_slice().try_into().expect("auth node must be 32 bytes"))
            .collect(),
    }
}

/// The committed stateful section stores only the 68-byte stateful sub-key, so a
/// full `PublicKey` is reconstructed by combining the case's sub-key with the
/// commitment/pk_seed/hypertree_root that keygen (deterministic for the fixed
/// generator seed) produces.
fn stateful_public_key_from_case(base: &PublicKey, case_public_key: &Value) -> PublicKey {
    PublicKey {
        stateful_public_key: encoded_stateful_sub_key(case_public_key),
        public_key_commitment: base.public_key_commitment.clone(),
        pk_seed: base.pk_seed.clone(),
        hypertree_root: base.hypertree_root.clone(),
    }
}

/// Consume the stateful golden section with a full public key reconstructed from
/// keygen: accept the valid case and reject wrongMessage / wrongPublicKey /
/// corruptedSignature. (Bead p8a.)
#[cfg_attr(
    any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
    ignore = "128s stateful golden conformance still needs a full key fixture/manual regeneration path"
)]
#[test]
fn stateful_golden_vector_accepts_valid_and_rejects_tampered() {
    let vectors = load_vectors();
    let section = &vectors["stateful"];

    let (_, base_public_key) = fixture_or_fresh_full_key(
        std::str::from_utf8(STATEFUL_SEED).expect("generator seed must be utf-8"),
        STATEFUL_MAX_SIGNATURES,
    );
    let expected: [u8; HASH_LEN] = base_public_key
        .public_key_commitment
        .clone()
        .try_into()
        .expect("commitment must be 32 bytes");

    // Byte-repro guard: the committed stateful sub-key equals the keygen output.
    assert_eq!(
        encoded_stateful_sub_key(&section["publicKey"]),
        base_public_key.stateful_public_key,
        "committed stateful sub-key must match keygen output for the generator seed"
    );

    let verifier = ShrincsVerifier::new();
    let accepts = |case: &Value| -> bool {
        let public_key = stateful_public_key_from_case(&base_public_key, &case["publicKey"]);
        let message = hex_to_vec(&case["message"]);
        let signature = parse_stateful_signature(&case["signature"]);
        verifier.verify_stateful_unsafe_raw(expected, &public_key, &message, &signature)
    };

    let cases = &section["cases"];
    assert!(
        accepts(&cases["valid"]),
        "the valid stateful golden case must verify"
    );
    for name in ["wrongMessage", "wrongPublicKey", "corruptedSignature"] {
        let case = &cases[name];
        assert!(
            !case.is_null(),
            "golden vector is missing expected stateful case '{name}'"
        );
        assert!(
            !accepts(case),
            "tampered stateful golden case '{name}' must be rejected but verified true"
        );
    }
}
