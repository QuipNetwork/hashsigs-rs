// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates SHRINCS test vectors bound to the `ShrincsPaymaster` smart-account's canonical
// sponsorship-approval context (quip-solidity). The paymaster verifies a single GLOBAL stateful
// SHRINCS key over each sponsored userOp; anti-replay is a used-leaf bitmap, so the stateful
// `ActionContext.nonce` is ALWAYS 0 and sponsorships verify in any order.
//
// Every signature is produced over the paymaster's exact `statefulActionMessageHash`, computed for
// a FIXED paymaster address + chain id. The Solidity tests place the paymaster harness at
// `PAYMASTER` via `vm.etch` + `vm.chainId(CHAIN_ID)` so `_domainSeparator()` reproduces the
// `domainSeparator` baked into these vectors.
//
// The signed `payloadHash` is the paymaster's `_userOpBindingHash(userOp)`:
//   hash(sender, nonce, keccak(initCode), keccak(callData), accountGasLimits, preVerificationGas,
//        gasFees, keccak(paymasterAndData[:64]))
// where paymasterAndData[:64] = paymaster(20) ‖ verificationGasLimit(16) ‖ postOpGasLimit(16) ‖
// validUntil(6) ‖ validAfter(6). The signature region paymasterAndData[64:] is EXCLUDED from the
// hash, so the signature can be computed first and then embedded — no circular dependency.
//
// The fixed userOp / paymasterAndData-prefix field values below MUST match the constants in
// quip-solidity `test/ShrincsPaymaster/ShrincsPaymaster.t.sol`.
//
// Run: cargo test --test generate_shrincs_paymaster_vectors -- --ignored --nocapture
// Then copy tests/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json into
// quip-solidity/test/test_vectors/.

use hashsigs_rs::shrincs::{
    ActionContext, ParameterSetId, PublicKey, ShrincsSigner, ShrincsVerifier, StatefulSignature,
    HASH_LEN,
};
use serde_json::{json, Value};
use solana_program::keccak;
use std::fs;
use std::path::Path;

const OUT_PATH: &str = "tests/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json";

// Must match ShrincsPaymaster constants.
const DOMAIN_TAG_MESSAGE: &[u8] = b"quip-shrincs-paymaster-v1";
const CHAIN_ID: u64 = 31337;
// Fixed paymaster address the Solidity test etches the harness to.
const PAYMASTER: [u8; 20] = [
    0x5b, 0x38, 0xda, 0x6a, 0x70, 0x1c, 0x56, 0x85, 0x45, 0xdc, 0xfc, 0xb0, 0x3f, 0xcb, 0x87, 0x5f,
    0x56, 0xbe, 0xdd, 0xc4,
];
const PROFILE: ParameterSetId = ParameterSetId::Sphincs256sKeccakQ20;
const MAX_SIG: u32 = 8;

// Fixed userOp / paymasterAndData-prefix fields (must match ShrincsPaymasterTest).
const SENDER: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x11, 0xce, // 0xA11CE
];
const PM_VERIFICATION_GAS: u128 = 100_000;
const PM_POSTOP_GAS: u128 = 50_000;
const VALID_UNTIL: u64 = 0;
const VALID_AFTER: u64 = 0;
// A non-zero validity window for the dedicated packing test. The two values are DISTINCT (and
// non-transposable) so a swapped-shift / swapped-slice bug in `validatePaymasterUserOp` is caught.
const WINDOW_VALID_UNTIL: u64 = 0x00AA_AAAA; // uint48
const WINDOW_VALID_AFTER: u64 = 0x0055_5555; // uint48
const ACCOUNT_GAS_LO: u128 = 100_000; // callGasLimit
const ACCOUNT_GAS_HI: u128 = 100_000; // verificationGasLimit
const PRE_VERIFICATION_GAS: u64 = 21_000;
const GAS_FEES_HI: u128 = 1_000_000_000; // maxPriorityFeePerGas (1 gwei)
const GAS_FEES_LO: u128 = 10_000_000_000; // maxFeePerGas (10 gwei)

fn k(bytes: &[u8]) -> [u8; HASH_LEN] {
    keccak::hash(bytes).to_bytes()
}

fn packed(p: ParameterSetId) -> u8 {
    match p {
        ParameterSetId::Sphincs256sKeccakQ20 => 0,
        ParameterSetId::Unsupported => 1,
    }
}

/// keccak of the concatenation of 32-byte words — matches solady `EfficientHashLib.hash(...)`.
fn hash_words(words: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for w in words {
        buf.extend_from_slice(w);
    }
    k(&buf)
}

fn u256(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

fn addr32(a: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&a);
    out
}

/// Two uint128 packed into a 32-byte word (hi in [0:16], lo in [16:32]) — matches Solidity
/// `bytes32((uint256(hi) << 128) | uint256(lo))`.
fn packed_u128_pair(hi: u128, lo: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&hi.to_be_bytes());
    out[16..32].copy_from_slice(&lo.to_be_bytes());
    out
}

fn domain_separator() -> [u8; HASH_LEN] {
    hash_words(&[&k(DOMAIN_TAG_MESSAGE), &u256(CHAIN_ID), &addr32(PAYMASTER)])
}

fn commitment_word(pk: &PublicKey) -> [u8; HASH_LEN] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.public_key_commitment);
    out
}

fn action(name: &str) -> [u8; HASH_LEN] {
    k(name.as_bytes())
}

/// The 64-byte `paymasterAndData[:64]` prefix the binding hash commits to.
fn paymaster_prefix(valid_until: u64, valid_after: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&PAYMASTER); // 20
    p.extend_from_slice(&PM_VERIFICATION_GAS.to_be_bytes()); // 16
    p.extend_from_slice(&PM_POSTOP_GAS.to_be_bytes()); // 16
    p.extend_from_slice(&valid_until.to_be_bytes()[2..8]); // 6 (uint48)
    p.extend_from_slice(&valid_after.to_be_bytes()[2..8]); // 6 (uint48)
    debug_assert_eq!(p.len(), 64);
    p
}

/// Reproduces `ShrincsPaymaster._userOpBindingHash` for the fixed userOp with the given `nonce` and
/// validity window (the window is part of the committed `paymasterAndData[:64]` prefix).
fn user_op_binding_hash(nonce: u64, valid_until: u64, valid_after: u64) -> [u8; HASH_LEN] {
    hash_words(&[
        &addr32(SENDER),
        &u256(nonce),
        &k(&[]), // keccak(initCode), empty
        &k(&[]), // keccak(callData), empty
        &packed_u128_pair(ACCOUNT_GAS_HI, ACCOUNT_GAS_LO),
        &u256(PRE_VERIFICATION_GAS),
        &packed_u128_pair(GAS_FEES_HI, GAS_FEES_LO),
        &k(&paymaster_prefix(valid_until, valid_after)),
    ])
}

fn stateful_ctx(payload_hash: [u8; HASH_LEN]) -> ActionContext {
    ActionContext {
        domain_separator: domain_separator(),
        nonce: u256(0),
        key_version: u256(0),
        action_type: action("quip.shrincs.action.paymasterApprove"),
        payload_hash,
    }
}

#[test]
#[ignore = "run explicitly to refresh ShrincsPaymaster Solidity vectors"]
fn generate_shrincs_paymaster_vectors() {
    let verifier = ShrincsVerifier::new();

    // The single global sponsorship verifier key.
    let (verifier_key, verifier_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs paymaster verifier seed", MAX_SIG)
            .expect("verifier keygen");
    let verifier_commit = commitment_word(&verifier_pub);

    // Sponsorship sequence: leaves 1..3, each over its own userOp (nonce = leaf), all under
    // keyVersion 0. The Solidity out-of-order test submits leaf 3 then leaf 2 and expects both to
    // pass — proving the bitmap accepts out-of-order leaves.
    let mut sponsor = Vec::new();
    for leaf in 1u32..=3 {
        let nonce = leaf as u64;
        let binding = user_op_binding_hash(nonce, VALID_UNTIL, VALID_AFTER);
        let ctx = stateful_ctx(binding);
        let msg = verifier.stateful_action_message_hash(PROFILE, verifier_commit, &ctx);
        let sig = ShrincsSigner::sign_stateful_raw_at_leaf(&verifier_key, leaf, &msg)
            .expect("sponsor sign");
        sponsor.push(json!({
            "leaf": leaf,
            "nonce": nonce,
            "keyVersion": 0,
            "bindingHash": hex(binding),
            "message": hex(msg),
            "signature": stateful_sig_json(&sig),
        }));
    }

    // A sponsorship signed over a NON-ZERO validity window (leaf 4), so the Solidity test can assert
    // `validatePaymasterUserOp` packs `(validUntil << 160) | (validAfter << 208)` from the correct
    // byte slices. The window is baked into the signed prefix, so it cannot be faked at the call site.
    let window_leaf = 4u32;
    let window_nonce = window_leaf as u64;
    let window_binding = user_op_binding_hash(window_nonce, WINDOW_VALID_UNTIL, WINDOW_VALID_AFTER);
    let window_ctx = stateful_ctx(window_binding);
    let window_msg = verifier.stateful_action_message_hash(PROFILE, verifier_commit, &window_ctx);
    let window_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&verifier_key, window_leaf, &window_msg)
            .expect("sponsor-with-window sign");
    let sponsor_with_window = json!({
        "leaf": window_leaf,
        "nonce": window_nonce,
        "keyVersion": 0,
        "validUntil": WINDOW_VALID_UNTIL,
        "validAfter": WINDOW_VALID_AFTER,
        "bindingHash": hex(window_binding),
        "message": hex(window_msg),
        "signature": stateful_sig_json(&window_sig),
    });

    let vectors = json!({
        "paymaster": hex(PAYMASTER),
        "chainId": CHAIN_ID,
        "domainTag": String::from_utf8_lossy(DOMAIN_TAG_MESSAGE),
        "domainSeparator": hex(domain_separator()),
        "maxSignatures": MAX_SIG,
        "verifierKey": public_key_json(&verifier_pub),
        // The fixed userOp / paymasterAndData-prefix fields these signatures bind. The Solidity test
        // rebuilds the identical PackedUserOperation from these (nonce varies per case).
        "userOp": {
            "sender": hex(SENDER),
            "verificationGasLimit": PM_VERIFICATION_GAS as u64,
            "postOpGasLimit": PM_POSTOP_GAS as u64,
            "validUntil": VALID_UNTIL,
            "validAfter": VALID_AFTER,
            "accountGasLimits": hex(packed_u128_pair(ACCOUNT_GAS_HI, ACCOUNT_GAS_LO)),
            "preVerificationGas": PRE_VERIFICATION_GAS,
            "gasFees": hex(packed_u128_pair(GAS_FEES_HI, GAS_FEES_LO)),
            "initCode": "0x",
            "callData": "0x",
        },
        "cases": {
            "sponsor": sponsor,
            "sponsorWithWindow": sponsor_with_window,
        }
    });

    let out = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write paymaster vectors");
    println!("wrote {OUT_PATH}");
}

fn public_key_json(pk: &PublicKey) -> Value {
    json!({
        "parameterSetId": packed(pk.parameter_set_id),
        "statefulPublicKey": hex(&pk.stateful_public_key),
        "publicKeyCommitment": hex(&pk.public_key_commitment),
        "pkSeed": hex(&pk.pk_seed),
        "hypertreeRoot": hex(&pk.hypertree_root),
    })
}

fn stateful_sig_json(sig: &StatefulSignature) -> Value {
    json!({
        "randomizer": hex(sig.randomizer),
        "counter": sig.counter,
        "chains": sig.chains.iter().map(hex).collect::<Vec<_>>(),
        "authPath": sig.auth_path.iter().map(hex).collect::<Vec<_>>(),
    })
}

fn hex<T: AsRef<[u8]>>(bytes: T) -> String {
    let mut out = String::from("0x");
    for b in bytes.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
