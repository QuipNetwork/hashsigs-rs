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

// Regenerates the two ROTATION bundles inside the 128s account-wrapper
// fixtures (`testExportStatefulOnlyRotationBundle` and
// `testExportFullRotationBundle`). The action bundles are refreshed by
// `regenerate_profile_bound_stateless_account_vector` in
// solidity_account_vectors.rs; the rotation bundles could not be, because the
// account subsystem (RotationContext/RotationTarget and the rotation message
// hashes) was removed from the library. This test carries local copies of
// those removed pieces, byte-matched to `SHRINCS.sol`'s
// statefulRotationMessageHash/fullRotationMessageHash, and rebuilds the
// bundles with the same deterministic seeds the original Rust generator used.
//
// hashsigs-solidity's SHRINCSRustAccountVectors128s.t.sol is the verification
// oracle: copy the refreshed JSON there and run that suite under the
// matching 128s profile.

#![cfg(any(shrincs_default_profile_128s_q18, shrincs_default_profile_128s_q20))]

mod common;

use common::load_vectors;
use flate2::write::GzEncoder;
use flate2::Compression;
use hashsigs_rs::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};
use hashsigs_rs::shrincs::{ShrincsSigner, ShrincsVerifier, StatelessSignature, HASH_SUITE_ID};
use hashsigs_rs::HASH_LEN;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::io::Write;
use std::path::Path;

// --- removed account-subsystem types, kept local to this generator --------

struct RotationContext {
    domain_separator: [u8; HASH_LEN],
    nonce: [u8; HASH_LEN],
    key_version: [u8; HASH_LEN],
}

struct StatefulRotationTarget {
    stateful_public_key: Vec<u8>,
    public_key_commitment: Vec<u8>,
}

struct RotationTarget {
    stateful_public_key: Vec<u8>,
    public_key_commitment: Vec<u8>,
    pk_seed: Vec<u8>,
    hypertree_root: Vec<u8>,
}

// --- keccak helpers -------------------------------------------------------

fn keccak_concat(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hash_word(label: &[u8]) -> [u8; HASH_LEN] {
    keccak_concat(&[label])
}

// --- canonical rotation message hashes ------------------------------------
// Byte-for-byte mirrors of SHRINCS.sol's statefulRotationMessageHash and
// fullRotationMessageHash: keccak256(abi.encodePacked(op_tag,
// HashSuite.HASH_SUITE_ID, expected commitment, context.domainSeparator,
// context.nonce, context.keyVersion, current bundle commitment, next bundle
// commitment)). HASH_SUITE_ID packs as a 4-byte big-endian uint32.

fn stateful_rotation_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_commitment: &[u8],
    context: &RotationContext,
    next_commitment: &[u8],
) -> [u8; HASH_LEN] {
    keccak_concat(&[
        &hash_word(b"shrincs-rotate-stateful"),
        &HASH_SUITE_ID.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        current_commitment,
        next_commitment,
    ])
}

fn full_rotation_message_hash(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_commitment: &[u8],
    context: &RotationContext,
    next_commitment: &[u8],
) -> [u8; HASH_LEN] {
    keccak_concat(&[
        &hash_word(b"shrincs-rotate-full"),
        &HASH_SUITE_ID.to_be_bytes(),
        &expected_public_key_commitment,
        &context.domain_separator,
        &context.nonce,
        &context.key_version,
        current_commitment,
        next_commitment,
    ])
}

// --- minimal head/tail ABI tuple encoder ----------------------------------
// Same primitives the original generator carried; shapes verified against
// SHRINCSAccountVectorExport.sol's rotation vector structs.

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

fn abi_bytes(data: &[u8]) -> Vec<u8> {
    let pad = pad_len(data.len());
    let mut out = Vec::with_capacity(HASH_LEN + data.len() + pad);
    out.extend_from_slice(&word_usize(data.len()));
    out.extend_from_slice(data);
    out.resize(out.len() + pad, 0);
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

/// `abi.encode(x)` for a single dynamic top-level value: one offset word plus
/// `x`'s own head/tail body.
fn abi_encode_root(body: Vec<u8>) -> Vec<u8> {
    abi_tuple(vec![AbiField::Dynamic(body)])
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = hash_word(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

// --- struct body encoders -------------------------------------------------

fn four_bytes_fields_body(a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> Vec<u8> {
    abi_tuple(vec![
        AbiField::Dynamic(abi_bytes(a)),
        AbiField::Dynamic(abi_bytes(b)),
        AbiField::Dynamic(abi_bytes(c)),
        AbiField::Dynamic(abi_bytes(d)),
    ])
}

fn public_key_body(pk: &hashsigs_rs::shrincs::key::PublicKey) -> Vec<u8> {
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

/// The signature's own head/tail body: `to_bytes()` is `abi.encode(sig)`
/// (a root offset word plus the body), so strip the root offset.
fn stateless_signature_body(signature: &StatelessSignature) -> Vec<u8> {
    let encoded = signature.to_bytes();
    let mut offset = 0usize;
    for byte in &encoded[..HASH_LEN] {
        offset = offset * 256 + *byte as usize;
    }
    encoded[offset..].to_vec()
}

fn rotation_context_words(context: &RotationContext) -> Vec<AbiField> {
    vec![
        AbiField::Static(context.domain_separator),
        AbiField::Static(context.nonce),
        AbiField::Static(context.key_version),
    ]
}

// --- vector-wrapper struct encoders ---------------------------------------
// Field order/shape mirrors SHRINCSAccountVectorExport.sol's
// StatefulOnlyRotationVector and FullRotationVector.

struct StatefulOnlyRotationParts<'a> {
    current: [u8; HASH_LEN],
    current_public_key: &'a hashsigs_rs::shrincs::key::PublicKey,
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
    current_public_key: &'a hashsigs_rs::shrincs::key::PublicKey,
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

// --- rotate calldata (selector || envelope body) --------------------------

fn rotate_to_fresh_key_calldata(
    current_public_key: &hashsigs_rs::shrincs::key::PublicKey,
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
    current_public_key: &hashsigs_rs::shrincs::key::PublicKey,
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

// --- bundle builders ------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn word32(bytes: &[u8]) -> [u8; HASH_LEN] {
    bytes.try_into().expect("value must be exactly 32 bytes")
}

fn build_stateful_only_rotation_bundle() -> Value {
    let verifier = ShrincsVerifier::new();
    let (signing_key, public_key) =
        ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
            b"128s account vectors: stateful-only rotation current key",
            4,
        )
        .expect("stateful-only rotation current keygen");
    let current = word32(&public_key.public_key_commitment);
    let (_, next_source_key) = ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
        b"128s account vectors: stateful-only rotation next key",
        4,
    )
    .expect("stateful-only rotation next keygen");
    // The next stateful-only commitment mixes the replacement stateful key
    // with the *current* key's stateless pk_seed/hypertree_root: a
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
    let message = stateful_rotation_message_hash(
        current,
        &public_key.public_key_commitment,
        &context,
        &next_key.public_key_commitment,
    );
    let recovery_signature =
        ShrincsSigner::sign_stateless_raw::<SelectedProfile, NUM_LAYERS>(&signing_key, &message)
            .expect("stateful-only rotation recovery signing");

    let rotate_calldata = rotate_to_fresh_key_calldata(&public_key, &recovery_signature, &next_key);
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
        ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
            b"128s account vectors: full rotation current key",
            4,
        )
        .expect("full rotation current keygen");
    let current = word32(&public_key.public_key_commitment);
    let (_, next_public_key) = ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
        b"128s account vectors: full rotation next key",
        4,
    )
    .expect("full rotation next keygen");
    // A full rotation replaces the stateless component too, so the next
    // commitment is the replacement key's own natural commitment. Recompute
    // it explicitly to keep the target self-consistent under the current
    // commitment scheme.
    let next_commitment = verifier.public_key_commitment(
        &next_public_key.stateful_public_key,
        word32(&next_public_key.pk_seed),
        word32(&next_public_key.hypertree_root),
    );
    assert_eq!(
        next_commitment.to_vec(),
        next_public_key.public_key_commitment,
        "keygen commitment must match the verifier's commitment scheme"
    );
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
    let message = full_rotation_message_hash(
        current,
        &public_key.public_key_commitment,
        &context,
        &next_key.public_key_commitment,
    );
    let recovery_signature =
        ShrincsSigner::sign_stateless_raw::<SelectedProfile, NUM_LAYERS>(&signing_key, &message)
            .expect("full rotation recovery signing");

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

// --- output ---------------------------------------------------------------

fn account_vector_out_path() -> &'static str {
    #[cfg(shrincs_default_profile_128s_q18)]
    {
        "tests/test_vectors/shrincs_account_wrapper_vectors_128s_q18_keccak.json.gz"
    }
    #[cfg(shrincs_default_profile_128s_q20)]
    {
        "tests/test_vectors/shrincs_account_wrapper_vectors_128s_q20_keccak.json.gz"
    }
}

#[test]
#[ignore = "run explicitly to refresh the 128s rotation account vectors"]
fn regenerate_account_rotation_vectors() {
    let mut vectors = load_vectors();
    vectors["testExportStatefulOnlyRotationBundle"] = build_stateful_only_rotation_bundle();
    vectors["testExportFullRotationBundle"] = build_full_rotation_bundle();

    let out = serde_json::to_vec_pretty(&vectors).expect("serialize wrapper vectors");
    let file =
        std::fs::File::create(Path::new(account_vector_out_path())).expect("create wrapper vector");
    let mut gzip = GzEncoder::new(file, Compression::default());
    gzip.write_all(&out).expect("write wrapper vector");
    gzip.write_all(b"\n").expect("terminate wrapper vector");
    gzip.finish().expect("finish wrapper vector");
}
