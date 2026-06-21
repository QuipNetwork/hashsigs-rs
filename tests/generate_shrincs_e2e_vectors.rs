// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates COMBINED e2e SHRINCS vectors where a SINGLE ERC-4337 UserOperation is signed by BOTH a
// `ShrincsWallet` (its `validateUserOp` approval) AND a `ShrincsPaymaster` (its sponsorship). Unlike
// the per-contract generators, the wallet here signs the REAL EntryPoint v0.7 `userOpHash`, which
// commits to `keccak(paymasterAndData)` — so the paymaster signs FIRST, its signature is embedded in
// `paymasterAndData[64:]`, and only then is the canonical `userOpHash` computed and signed by the
// wallet. Reproducing that hash requires rebuilding the exact `paymasterAndData` bytes, including the
// `abi.encode(PublicKey, StatefulSignature)` tail — which this generator hand-rolls (no extra deps).
//
// The wallet and paymaster live at DISTINCT fixed addresses (each binds its own address into its
// domain separator). The Solidity e2e suite forks Base Sepolia for the real EntryPoint, overrides
// `block.chainid` to 31337, and `vm.etch`es both harnesses at these addresses.
//
// Run: cargo test --test generate_shrincs_e2e_vectors -- --ignored --nocapture
// Then copy tests/test_vectors/shrincs_e2e_sphincs_256s_keccak.json into quip-solidity/test/test_vectors/.

use hashsigs_rs::shrincs::{
    ActionContext, ParameterSetId, PublicKey, ShrincsSigner, ShrincsSigningKey, ShrincsVerifier,
    StatefulSignature, HASH_LEN,
};
use serde_json::{json, Value};
use solana_program::keccak;
use std::fs;
use std::path::Path;

const OUT_PATH: &str = "tests/test_vectors/shrincs_e2e_sphincs_256s_keccak.json";

const WALLET_DOMAIN_TAG: &[u8] = b"quip-shrincs-wallet-v1";
const PAYMASTER_DOMAIN_TAG: &[u8] = b"quip-shrincs-paymaster-v1";
const ACTION_ERC4337: &str = "quip.shrincs.action.erc4337Execute";
const ACTION_PAYMASTER_APPROVE: &str = "quip.shrincs.action.paymasterApprove";
const ACTION_ROTATE_KEY: &str = "quip.shrincs.action.rotateKey";

const CHAIN_ID: u64 = 31337;
const ENTRY_POINT: [u8; 20] = hex20c("0000000071727De22E5E9d8BAf0edAc6f37da032");
// Distinct fixed addresses (must match ShrincsE2EBase). Wallet reuses the canonical test address; the
// paymaster uses Remix default account #1 so the two never collide.
const WALLET: [u8; 20] = hex20c("5B38Da6a701c568545dCfcB03FcB875f56beddC4");
const PAYMASTER: [u8; 20] = hex20c("Ab8483F64d9C6d1EcF9b849Ae677dD3315835cb2");
// Fixed call targets the Solidity test uses verbatim (no makeAddr — these are bound into userOpHash).
const RECIPIENT: [u8; 20] = hex20c("000000000000000000000000000000000000b0b0");
const CALL_TARGET: [u8; 20] = hex20c("000000000000000000000000000000000000ca11");

const PROFILE: ParameterSetId = ParameterSetId::Sphincs256sKeccakQ20;
const MAX_SIG: u32 = 8;
const EXECUTE_FEE: u64 = 0;

// Shared gas fields baked into every signed userOp (SPHINCS verify is heavy → generous limits).
const VERIFICATION_GAS: u128 = 4_000_000;
const CALL_GAS: u128 = 1_000_000;
const PRE_VERIFICATION_GAS: u64 = 150_000;
const MAX_PRIORITY_FEE: u128 = 1_000_000_000; // 1 gwei
const MAX_FEE: u128 = 10_000_000_000; // 10 gwei
const PM_VERIFICATION_GAS: u128 = 4_000_000;
const PM_POSTOP_GAS: u128 = 100_000;

// Absolute (fork-independent) validity bounds for the AA32 rejection cases.
const WINDOW_NOT_DUE_VALID_AFTER: u64 = 4_000_000_000; // ~year 2096
const WINDOW_EXPIRED_VALID_UNTIL: u64 = 1_000_000_000; // ~year 2001

/*──────────────────────────── hashing primitives ────────────────────────────*/

fn k(bytes: &[u8]) -> [u8; HASH_LEN] {
    keccak::hash(bytes).to_bytes()
}

fn packed(p: ParameterSetId) -> u8 {
    match p {
        ParameterSetId::Sphincs256sKeccakQ20 => 0,
        ParameterSetId::Unsupported => 1,
    }
}

/// keccak of concatenated 32-byte words — matches solady `EfficientHashLib.hash(...)` AND
/// `abi.encode(...)` of an all-static tuple.
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

fn u256_u128(n: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&n.to_be_bytes());
    out
}

fn u256_usize(n: usize) -> [u8; 32] {
    u256_u128(n as u128)
}

fn addr32(a: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&a);
    out
}

/// Two uint128 packed hi||lo into one word — matches `bytes32((uint256(hi) << 128) | uint256(lo))`.
fn packed_u128_pair(hi: u128, lo: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&hi.to_be_bytes());
    out[16..32].copy_from_slice(&lo.to_be_bytes());
    out
}

fn account_gas_limits() -> [u8; 32] {
    packed_u128_pair(VERIFICATION_GAS, CALL_GAS)
}

fn gas_fees() -> [u8; 32] {
    packed_u128_pair(MAX_PRIORITY_FEE, MAX_FEE)
}

fn wallet_domain_separator() -> [u8; HASH_LEN] {
    hash_words(&[&k(WALLET_DOMAIN_TAG), &u256(CHAIN_ID), &addr32(WALLET)])
}

fn paymaster_domain_separator() -> [u8; HASH_LEN] {
    hash_words(&[
        &k(PAYMASTER_DOMAIN_TAG),
        &u256(CHAIN_ID),
        &addr32(PAYMASTER),
    ])
}

fn commitment_word(pk: &PublicKey) -> [u8; HASH_LEN] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.public_key_commitment);
    out
}

fn action(name: &str) -> [u8; HASH_LEN] {
    k(name.as_bytes())
}

/*──────────────────────── hand-rolled ABI encoding ────────────────────────*/

fn pad32(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % 32;
    if rem != 0 {
        out.extend(std::iter::repeat(0u8).take(32 - rem));
    }
    out
}

/// `abi.encode(bytes)` element: length word + right-padded data.
fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = u256_usize(data.len()).to_vec();
    out.extend_from_slice(&pad32(data));
    out
}

/// `abi.encode(bytes32[])` element: length word + each 32-byte entry.
fn abi_encode_bytes32_array(arr: &[[u8; HASH_LEN]]) -> Vec<u8> {
    let mut out = u256_usize(arr.len()).to_vec();
    for w in arr {
        out.extend_from_slice(w);
    }
    out
}

/// `abi.encode(PublicKey)` as the dynamic tuple `(uint8, bytes, bytes, bytes, bytes)`.
fn abi_encode_public_key(pk: &PublicKey) -> Vec<u8> {
    let dyn_parts: [&[u8]; 4] = [
        &pk.stateful_public_key,
        &pk.public_key_commitment,
        &pk.pk_seed,
        &pk.hypertree_root,
    ];
    let head_len = 5 * 32; // paramSetId + 4 offsets
    let mut head = Vec::new();
    head.extend_from_slice(&u256(packed(pk.parameter_set_id) as u64));
    let mut tail = Vec::new();
    let mut offset = head_len;
    for part in dyn_parts {
        head.extend_from_slice(&u256_usize(offset));
        let enc = abi_encode_bytes(part);
        offset += enc.len();
        tail.extend_from_slice(&enc);
    }
    [head, tail].concat()
}

/// `abi.encode(StatefulSignature)` as the dynamic tuple `(bytes32, uint32, bytes32[], bytes32[])`.
fn abi_encode_stateful_sig(sig: &StatefulSignature) -> Vec<u8> {
    let head_len = 4 * 32; // randomizer + counter + 2 offsets
    let enc_chains = abi_encode_bytes32_array(&sig.chains);
    let enc_auth = abi_encode_bytes32_array(&sig.auth_path);
    let mut head = Vec::new();
    head.extend_from_slice(&sig.randomizer);
    head.extend_from_slice(&u256(sig.counter as u64));
    head.extend_from_slice(&u256_usize(head_len));
    head.extend_from_slice(&u256_usize(head_len + enc_chains.len()));
    [head, enc_chains, enc_auth].concat()
}

/// `abi.encode(PublicKey, StatefulSignature)` — the on-chain `userOp.signature` /
/// `paymasterAndData[64:]` blob. Outer 2-tuple of dynamic structs.
fn abi_encode_blob(pk: &PublicKey, sig: &StatefulSignature) -> Vec<u8> {
    let enc_pk = abi_encode_public_key(pk);
    let enc_sig = abi_encode_stateful_sig(sig);
    let mut out = Vec::new();
    out.extend_from_slice(&u256_usize(0x40));
    out.extend_from_slice(&u256_usize(0x40 + enc_pk.len()));
    out.extend_from_slice(&enc_pk);
    out.extend_from_slice(&enc_sig);
    out
}

/// `abi.encodeWithSelector(execute.selector, target, value, data)`.
fn encode_execute_calldata(target: [u8; 20], value: u128, data: &[u8]) -> Vec<u8> {
    let selector = &k(b"execute(address,uint256,bytes)")[..4];
    let mut out = selector.to_vec();
    out.extend_from_slice(&addr32(target));
    out.extend_from_slice(&u256_u128(value));
    out.extend_from_slice(&u256_usize(0x60)); // offset to `data`
    out.extend_from_slice(&abi_encode_bytes(data));
    out
}

/*──────────────────────── userOp hashes ────────────────────────*/

/// The 64-byte `paymasterAndData[:64]` prefix the paymaster binding hash commits to.
fn paymaster_prefix(valid_until: u64, valid_after: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&PAYMASTER);
    p.extend_from_slice(&PM_VERIFICATION_GAS.to_be_bytes());
    p.extend_from_slice(&PM_POSTOP_GAS.to_be_bytes());
    p.extend_from_slice(&valid_until.to_be_bytes()[2..8]);
    p.extend_from_slice(&valid_after.to_be_bytes()[2..8]);
    debug_assert_eq!(p.len(), 64);
    p
}

/// Mirrors `ShrincsPaymaster._userOpBindingHash` (binds `paymasterAndData[:64]`, excludes the sig).
fn paymaster_binding_hash(nonce: u64, call_data: &[u8], prefix: &[u8]) -> [u8; HASH_LEN] {
    hash_words(&[
        &addr32(WALLET),
        &u256(nonce),
        &k(&[]), // keccak(initCode), empty
        &k(call_data),
        &account_gas_limits(),
        &u256(PRE_VERIFICATION_GAS),
        &gas_fees(),
        &k(prefix),
    ])
}

/// Canonical ERC-4337 v0.7 userOpHash for the assembled op.
fn canonical_user_op_hash(
    nonce: u64,
    call_data: &[u8],
    paymaster_and_data: &[u8],
) -> [u8; HASH_LEN] {
    let inner = hash_words(&[
        &addr32(WALLET),
        &u256(nonce),
        &k(&[]), // keccak(initCode)
        &k(call_data),
        &account_gas_limits(),
        &u256(PRE_VERIFICATION_GAS),
        &gas_fees(),
        &k(paymaster_and_data),
    ]);
    hash_words(&[&inner, &addr32(ENTRY_POINT), &u256(CHAIN_ID)])
}

/*──────────────────────── case builder ────────────────────────*/

struct Keys<'a> {
    wallet_key: &'a ShrincsSigningKey,
    wallet_commit: [u8; HASH_LEN],
    paymaster_key: &'a ShrincsSigningKey,
    paymaster_pub: &'a PublicKey,
    paymaster_commit: [u8; HASH_LEN],
}

struct CaseParams {
    nonce: u64,
    target: [u8; 20],
    value: u128,
    data: Vec<u8>,
    valid_until: u64,
    valid_after: u64,
    wallet_leaf: u32,
    paymaster_leaf: u32,
    wallet_key_version: u64,
    paymaster_key_version: u64,
    /// When true, the paymaster signs a corrupted binding hash so `verifyStateful` fails (AA34) while
    /// the wallet signature over the real userOpHash stays valid.
    bad_paymaster: bool,
}

/// Builds one fully-signed sponsored case: paymaster signs first, blob is embedded, the canonical
/// userOpHash is computed over the complete paymasterAndData, then the wallet signs that hash.
fn build_case(verifier: &ShrincsVerifier, keys: &Keys, p: &CaseParams) -> Value {
    let call_data = encode_execute_calldata(p.target, p.value, &p.data);
    let prefix = paymaster_prefix(p.valid_until, p.valid_after);

    // 1) Paymaster sponsorship signature over its binding hash.
    let mut binding = paymaster_binding_hash(p.nonce, &call_data, &prefix);
    if p.bad_paymaster {
        binding[0] ^= 0xff; // corrupt so verifyStateful fails — exercises the AA34 path
    }
    let pm_ctx = ActionContext {
        domain_separator: paymaster_domain_separator(),
        nonce: u256(0),
        key_version: u256(p.paymaster_key_version),
        action_type: action(ACTION_PAYMASTER_APPROVE),
        payload_hash: binding,
    };
    let pm_msg = verifier.stateful_action_message_hash(PROFILE, keys.paymaster_commit, &pm_ctx);
    let pm_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(keys.paymaster_key, p.paymaster_leaf, &pm_msg)
            .expect("paymaster sign");

    // 2) Embed the paymaster blob → full paymasterAndData.
    let blob = abi_encode_blob(keys.paymaster_pub, &pm_sig);
    let mut paymaster_and_data = prefix.clone();
    paymaster_and_data.extend_from_slice(&blob);

    // 3) Canonical userOpHash over the complete op.
    let user_op_hash = canonical_user_op_hash(p.nonce, &call_data, &paymaster_and_data);

    // 4) Wallet ERC-4337 approval over erc4337PayloadHash(userOpHash, fee).
    let payload_hash = hash_words(&[&user_op_hash, &u256(EXECUTE_FEE)]);
    let wallet_ctx = ActionContext {
        domain_separator: wallet_domain_separator(),
        nonce: u256(0),
        key_version: u256(p.wallet_key_version),
        action_type: action(ACTION_ERC4337),
        payload_hash,
    };
    let wallet_msg =
        verifier.stateful_action_message_hash(PROFILE, keys.wallet_commit, &wallet_ctx);
    let wallet_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(keys.wallet_key, p.wallet_leaf, &wallet_msg)
            .expect("wallet sign");

    json!({
        "nonce": p.nonce,
        "target": hex(p.target),
        "value": p.value.to_string(),
        "data": hex(&p.data),
        "validUntil": p.valid_until,
        "validAfter": p.valid_after,
        "walletLeaf": p.wallet_leaf,
        "paymasterLeaf": p.paymaster_leaf,
        "walletKeyVersion": p.wallet_key_version,
        "paymasterKeyVersion": p.paymaster_key_version,
        // cross-check fields (the Solidity base asserts getUserOpHash(op) == userOpHash).
        "callData": hex(&call_data),
        "paymasterAndData": hex(&paymaster_and_data),
        "userOpHash": hex(user_op_hash),
        "walletSignature": stateful_sig_json(&wallet_sig),
        "paymasterSignature": stateful_sig_json(&pm_sig),
    })
}

#[test]
#[ignore = "run explicitly to refresh ShrincsWallet+ShrincsPaymaster e2e vectors"]
fn generate_shrincs_e2e_vectors() {
    let verifier = ShrincsVerifier::new();

    let (wallet_key, wallet_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs e2e wallet main seed", MAX_SIG)
            .expect("wallet keygen");
    let wallet_commit = commitment_word(&wallet_pub);
    let (verifier_key, verifier_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs e2e paymaster verifier seed", MAX_SIG)
            .expect("verifier keygen");
    let verifier_commit = commitment_word(&verifier_pub);

    // Second paymaster verifier key for the rotation flow (keyVersion 1).
    let (verifier_key2, verifier_pub2) =
        ShrincsSigner::keygen(PROFILE, b"shrincs e2e paymaster verifier seed 2", MAX_SIG)
            .expect("verifier2 keygen");
    let verifier_commit2 = commitment_word(&verifier_pub2);

    let keys = Keys {
        wallet_key: &wallet_key,
        wallet_commit,
        paymaster_key: &verifier_key,
        paymaster_pub: &verifier_pub,
        paymaster_commit: verifier_commit,
    };
    let keys_rotated_pm = Keys {
        wallet_key: &wallet_key,
        wallet_commit,
        paymaster_key: &verifier_key2,
        paymaster_pub: &verifier_pub2,
        paymaster_commit: verifier_commit2,
    };

    let base = |nonce: u64,
                target: [u8; 20],
                value: u128,
                data: Vec<u8>,
                wallet_leaf: u32,
                paymaster_leaf: u32| CaseParams {
        nonce,
        target,
        value,
        data,
        valid_until: 0,
        valid_after: 0,
        wallet_leaf,
        paymaster_leaf,
        wallet_key_version: 0,
        paymaster_key_version: 0,
        bad_paymaster: false,
    };

    // Happy path.
    let sponsored_eth = build_case(
        &verifier,
        &keys,
        &base(0, RECIPIENT, 100_000_000_000_000_000, Vec::new(), 1, 1), // 0.1 ether
    );
    let sponsored_call = build_case(
        &verifier,
        &keys,
        &base(0, CALL_TARGET, 0, vec![0x12, 0x34], 1, 1),
    );

    // Multi-op out-of-order: nonces 0 then 1, but leaves 3 then 2.
    let out_of_order_a = build_case(
        &verifier,
        &keys,
        &base(0, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 3, 3),
    );
    let out_of_order_b = build_case(
        &verifier,
        &keys,
        &base(1, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 2, 2),
    );
    // Stale wallet leaf: nonce 2 reuses wallet leaf 3 (already consumed by out_of_order_a), fresh pm leaf.
    let stale_wallet_leaf = build_case(
        &verifier,
        &keys,
        &base(2, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 3, 4),
    );

    // Rejections.
    let mut bad_pm = base(0, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 1, 1);
    bad_pm.bad_paymaster = true;
    let bad_paymaster_context = build_case(&verifier, &keys, &bad_pm);

    let mut not_due = base(0, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 1, 1);
    not_due.valid_after = WINDOW_NOT_DUE_VALID_AFTER;
    let window_not_due = build_case(&verifier, &keys, &not_due);

    let mut expired = base(0, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 1, 1);
    expired.valid_until = WINDOW_EXPIRED_VALID_UNTIL;
    let window_expired = build_case(&verifier, &keys, &expired);

    // Paymaster rotation: signed with verifier key #2 under paymaster keyVersion 1.
    let mut rotated = base(0, RECIPIENT, 1_000_000_000_000_000, Vec::new(), 1, 1);
    rotated.paymaster_key_version = 1;
    let paymaster_rotation_new_key = build_case(&verifier, &keys_rotated_pm, &rotated);

    // Wallet main-key rotation (stateful `rotateKey`, leaf 5 under epoch 0): refresh the stateful
    // subkey, reuse the current stateless root. The on-chain `rotateKey` recomputes this commitment
    // and bumps the wallet epoch — after which an OLD-epoch sponsorship is rejected (the e2e test
    // does not sign a post-rotation op; the hybrid rotated key shares the old pkSeed).
    let (_wallet_next_stateful_key, wallet_next_stateful_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs e2e wallet rotateKey next seed", MAX_SIG)
            .expect("wallet rotateKey keygen");
    let mut rk_preimage: Vec<u8> = Vec::new();
    rk_preimage.extend_from_slice(b"shrincs-public-key");
    rk_preimage.push(packed(PROFILE));
    rk_preimage.extend_from_slice(&wallet_next_stateful_pub.stateful_public_key);
    rk_preimage.extend_from_slice(&wallet_pub.pk_seed);
    rk_preimage.extend_from_slice(&wallet_pub.hypertree_root);
    let rk_next_commit = k(&rk_preimage);
    let rk_payload = hash_words(&[&rk_next_commit, &u256(0)]);
    let rk_ctx = ActionContext {
        domain_separator: wallet_domain_separator(),
        nonce: u256(0),
        key_version: u256(0),
        action_type: action(ACTION_ROTATE_KEY),
        payload_hash: rk_payload,
    };
    let rk_leaf = 5u32;
    let rk_msg = verifier.stateful_action_message_hash(PROFILE, wallet_commit, &rk_ctx);
    let rk_sig = ShrincsSigner::sign_stateful_raw_at_leaf(&wallet_key, rk_leaf, &rk_msg)
        .expect("rotateKey sign");
    let wallet_rotate_key = json!({
        "leaf": rk_leaf,
        "nextParameterSetId": packed(PROFILE),
        "nextCommitment": hex(rk_next_commit),
        "nextStatefulKey": {
            "parameterSetId": packed(PROFILE),
            "statefulPublicKey": hex(&wallet_next_stateful_pub.stateful_public_key),
            "publicKeyCommitment": hex(rk_next_commit),
        },
        "signature": stateful_sig_json(&rk_sig),
    });

    let vectors = json!({
        "chainId": CHAIN_ID,
        "entryPoint": hex(ENTRY_POINT),
        "wallet": hex(WALLET),
        "paymaster": hex(PAYMASTER),
        "recipient": hex(RECIPIENT),
        "callTarget": hex(CALL_TARGET),
        "walletDomainSeparator": hex(wallet_domain_separator()),
        "paymasterDomainSeparator": hex(paymaster_domain_separator()),
        "maxSignatures": MAX_SIG,
        "executeFee": EXECUTE_FEE,
        "gas": {
            "accountGasLimits": hex(account_gas_limits()),
            "preVerificationGas": PRE_VERIFICATION_GAS,
            "gasFees": hex(gas_fees()),
            "paymasterVerificationGas": PM_VERIFICATION_GAS as u64,
            "paymasterPostOpGas": PM_POSTOP_GAS as u64,
        },
        "walletKey": public_key_json(&wallet_pub),
        "verifierKey": public_key_json(&verifier_pub),
        "verifierKey2": public_key_json(&verifier_pub2),
        "cases": {
            "sponsoredEthTransfer": sponsored_eth,
            "sponsoredContractCall": sponsored_call,
            "outOfOrderA": out_of_order_a,
            "outOfOrderB": out_of_order_b,
            "staleWalletLeafReplay": stale_wallet_leaf,
            "badPaymasterContext": bad_paymaster_context,
            "windowNotDue": window_not_due,
            "windowExpired": window_expired,
            "paymasterRotationNewKey": paymaster_rotation_new_key,
            "walletRotateKey": wallet_rotate_key,
        }
    });

    let out = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write e2e vectors");
    println!("wrote {OUT_PATH}");
}

/*──────────────────────── json helpers ────────────────────────*/

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

/// const-fn hex decode for 20-byte address literals.
const fn hex20c(s: &str) -> [u8; 20] {
    let b = s.as_bytes();
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = hex_nibble(b[i * 2]) * 16 + hex_nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}
