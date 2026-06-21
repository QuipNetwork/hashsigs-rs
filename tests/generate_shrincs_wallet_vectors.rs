// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates SHRINCS test vectors bound to the `ShrincsWallet` smart-account's canonical
// signing context (quip-solidity). Unlike `generate_shrincs_vectors.rs`, which signs raw
// messages, every signature here is produced over the wallet's exact
// `statefulActionMessageHash` / `statelessActionMessageHash` / rotation message, computed for a
// FIXED wallet address + chain id. The Solidity tests place the wallet at `WALLET` via
// `vm.etch` + `vm.chainId(CHAIN_ID)` so the wallet's `_shrincsDomainSeparator()` reproduces the
// `domain_separator` baked into these vectors.
//
// NO-NONCE STATEFUL SCHEME: the wallet uses a used-leaf bitmap for anti-replay, so the stateful
// `ActionContext.nonce` is ALWAYS 0 (freshness comes from the one-time leaf + the EntryPoint
// nonce bound inside userOpHash). Stateful actions therefore verify in any order. Stateless
// rotations (`recoverWallet` + the recovery half of `transferOwnership`) bind `RotationContext`
// with `nonce = $.nonce` (0 on a fresh wallet) and `keyVersion = $.keyVersion`.
//
// Run: cargo test --test generate_shrincs_wallet_vectors -- --ignored --nocapture
// Then copy tests/test_vectors/shrincs_wallet_sphincs_256s_keccak.json into
// quip-solidity/test/test_vectors/.

use hashsigs_rs::shrincs::{
    ActionContext, ParameterSetId, PublicKey, RotationContext, RotationTarget, ShrincsSigner,
    ShrincsVerifier, StatefulSignature, StatelessSignature, HASH_LEN,
};
use serde_json::{json, Value};
use solana_program::keccak;
use std::fs;
use std::path::Path;

const OUT_PATH: &str = "tests/test_vectors/shrincs_wallet_sphincs_256s_keccak.json";

// Must match ShrincsWallet / ShrincsWalletCodec constants.
const DOMAIN_TAG_MESSAGE: &[u8] = b"quip-shrincs-wallet-v1";
const CHAIN_ID: u64 = 31337;
// Fixed wallet address the Solidity test etches the wallet to.
const WALLET: [u8; 20] = [
    0x5b, 0x38, 0xda, 0x6a, 0x70, 0x1c, 0x56, 0x85, 0x45, 0xdc, 0xfc, 0xb0, 0x3f, 0xcb, 0x87, 0x5f,
    0x56, 0xbe, 0xdd, 0xc4,
];
const PROFILE: ParameterSetId = ParameterSetId::Sphincs256sKeccakQ20;
const MAX_SIG: u32 = 8;

fn k(bytes: &[u8]) -> [u8; HASH_LEN] {
    keccak::hash(bytes).to_bytes()
}

/// Mirrors `ParameterSetId::packed_byte` (crate-private), used in commitment preimages.
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

fn domain_separator() -> [u8; HASH_LEN] {
    hash_words(&[&k(DOMAIN_TAG_MESSAGE), &u256(CHAIN_ID), &addr32(WALLET)])
}

fn commitment_word(pk: &PublicKey) -> [u8; HASH_LEN] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.public_key_commitment);
    out
}

// ShrincsWalletCodec.ACTION_* constants.
fn action(name: &str) -> [u8; HASH_LEN] {
    k(name.as_bytes())
}

/// Canonical stateful `ActionContext`. The wallet ALWAYS binds `nonce = 0` on the stateful path
/// (anti-replay is the used-leaf bitmap), so the generator does too.
fn stateful_ctx(
    key_version: u64,
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
) -> ActionContext {
    ActionContext {
        domain_separator: domain_separator(),
        nonce: u256(0),
        key_version: u256(key_version),
        action_type,
        payload_hash,
    }
}

fn rotation_target(pk: &PublicKey) -> RotationTarget {
    RotationTarget {
        parameter_set_id: pk.parameter_set_id,
        stateful_public_key: pk.stateful_public_key.clone(),
        public_key_commitment: pk.public_key_commitment.clone(),
        pk_seed: pk.pk_seed.clone(),
        hypertree_root: pk.hypertree_root.clone(),
    }
}

#[test]
#[ignore = "run explicitly to refresh ShrincsWallet Solidity vectors"]
fn generate_shrincs_wallet_vectors() {
    let verifier = ShrincsVerifier::new();

    // Installed main hybrid key (stateful normal ops + stateless break-glass recovery).
    let (main_key, main_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs wallet main key seed", MAX_SIG)
            .expect("main keygen");
    let main_commit = commitment_word(&main_pub);

    // Dedicated ERC-1271 stateless verifier key.
    let (erc1271_key, erc1271_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs wallet erc1271 key seed", MAX_SIG)
            .expect("1271 keygen");
    let erc1271_commit = commitment_word(&erc1271_pub);

    // Replacement bundles for rotation cases.
    let (_next_stateful_key, next_stateful_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs wallet rotateKey next seed", MAX_SIG)
            .expect("rk keygen");
    // `next_full` is the incoming bundle for BOTH `recoverWallet` (case `rotateFullKey`) and the
    // recovery half of `transferOwnership`. Both rotate from the same fresh wallet state
    // (RotationContext nonce=0, keyVersion=0) to this same bundle, so their stateless signatures
    // and `nextKey` coincide — the Solidity tests read `nextKey` from `.cases.rotateFullKey`.
    let (_next_full_key, next_full_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs wallet rotateFull next seed", MAX_SIG)
            .expect("rf keygen");
    let next_full_commit = commitment_word(&next_full_pub);

    // ---- ERC-4337 stateful sequence (leaves 1..3, no-nonce ⇒ any order accepted) ----
    // The Solidity `outOfOrderLeaves` test submits erc4337[2] (leaf 3) then erc4337[1] (leaf 2)
    // and expects both to pass — proving the bitmap accepts out-of-order leaves.
    let mut erc4337 = Vec::new();
    for leaf in 1u32..=3 {
        let user_op_hash = k(format!("shrincs-wallet-userop-{leaf}").as_bytes());
        let fee = 0u64;
        let payload_hash = hash_words(&[&user_op_hash, &u256(fee)]);
        let ctx = stateful_ctx(
            0,
            action("quip.shrincs.action.erc4337Execute"),
            payload_hash,
        );
        let msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &ctx);
        let sig =
            ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, leaf, &msg).expect("erc4337 sign");
        erc4337.push(json!({
            "leaf": leaf,
            "nonce": 0,
            "keyVersion": 0,
            "userOpHash": hex(user_op_hash),
            "fee": fee,
            "payloadHash": hex(payload_hash),
            "message": hex(msg),
            "signature": stateful_sig_json(&sig),
        }));
    }

    // ---- execute(bytes) owner path (leaf 1, empty call = LeafConsumedOnly) ----
    // Target/value/data/fee MUST match the Solidity `execute` test (TARGET=0xBEEF, value 0, empty).
    let exec_target: [u8; 20] = hex20("0x000000000000000000000000000000000000beef");
    let exec_value = 0u64;
    let exec_data: Vec<u8> = Vec::new();
    let exec_fee = 0u64;
    let exec_payload = hash_words(&[
        &addr32(exec_target),
        &u256(exec_value),
        &k(&exec_data),
        &u256(exec_fee),
    ]);
    let exec_ctx = stateful_ctx(0, action("quip.shrincs.action.execute"), exec_payload);
    let exec_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &exec_ctx);
    let exec_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &exec_msg).expect("execute sign");

    // ---- execute(bytes) ETH transfer (leaf 1): TARGET=0xBEEF, value 1 ether, empty data ----
    let exec_eth_value = 1_000_000_000_000_000_000u64; // 1 ether
    let exec_eth_payload = hash_words(&[
        &addr32(exec_target),
        &u256(exec_eth_value),
        &k(&[]),
        &u256(exec_fee),
    ]);
    let exec_eth_ctx = stateful_ctx(0, action("quip.shrincs.action.execute"), exec_eth_payload);
    let exec_eth_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &exec_eth_ctx);
    let exec_eth_sig = ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &exec_eth_msg)
        .expect("execute eth sign");

    // ---- execute(bytes) contract call (leaf 1): target=0xCA11 (test etches a callee), data 0x1234 ----
    let exec_call_target: [u8; 20] = hex20("0x000000000000000000000000000000000000ca11");
    let exec_call_data: Vec<u8> = vec![0x12, 0x34];
    let exec_call_payload = hash_words(&[
        &addr32(exec_call_target),
        &u256(0),
        &k(&exec_call_data),
        &u256(exec_fee),
    ]);
    let exec_call_ctx = stateful_ctx(0, action("quip.shrincs.action.execute"), exec_call_payload);
    let exec_call_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &exec_call_ctx);
    let exec_call_sig = ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &exec_call_msg)
        .expect("execute call sign");

    // ---- withdrawDepositTo (leaf 1) — TO=0xD00D, amount 0 (matches Solidity test) ----
    let wd_to: [u8; 20] = hex20("0x000000000000000000000000000000000000d00d");
    let wd_amount = 0u64;
    let wd_payload = hash_words(&[&addr32(wd_to), &u256(wd_amount)]);
    let wd_ctx = stateful_ctx(0, action("quip.shrincs.action.withdrawDeposit"), wd_payload);
    let wd_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &wd_ctx);
    let wd_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &wd_msg).expect("withdraw sign");

    // ---- transferOwnership (atomic handover): dual signature ----
    // newOwner = foundry makeAddr("newOwner"). The stateful owner-binding sig commits to
    // (newOwner, nextCommitment) where nextCommitment is the incoming `next_full` bundle; the
    // stateless recovery sig authorizes the full rotation to `next_full`.
    let new_owner: [u8; 20] = hex20("0x7240b687730BE024bcfD084621f794C2e4F8408f");
    let to_payload = hash_words(&[&addr32(new_owner), &next_full_commit]);
    let to_ctx = stateful_ctx(
        0,
        action("quip.shrincs.action.transferOwnership"),
        to_payload,
    );
    let to_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &to_ctx);
    let to_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &to_msg).expect("transfer sign");

    let to_rctx = RotationContext {
        domain_separator: domain_separator(),
        nonce: u256(0),
        key_version: u256(0),
    };
    let to_recovery_msg = verifier.full_rotation_message_hash(
        PROFILE,
        main_commit,
        &main_pub,
        &to_rctx,
        &rotation_target(&next_full_pub),
    );
    let to_recovery_sig = ShrincsSigner::sign_stateless_raw(&main_key, &to_recovery_msg)
        .expect("transfer recovery sign");

    // ---- setErc1271Key (leaf 1): install a brand-new 1271 verifier ----
    let (_replacement_1271_key, replacement_1271_pub) =
        ShrincsSigner::keygen(PROFILE, b"shrincs wallet replacement 1271 seed", MAX_SIG)
            .expect("r1271 keygen");
    let new_1271_commit = commitment_word(&replacement_1271_pub);
    let set1271_payload = hash_words(&[&new_1271_commit, &u256(0)]);
    let set1271_ctx = stateful_ctx(
        0,
        action("quip.shrincs.action.setErc1271Key"),
        set1271_payload,
    );
    let set1271_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &set1271_ctx);
    let set1271_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &set1271_msg).expect("set1271 sign");

    // ---- rotateKey (stateful routine): refresh stateful subkey, reuse stateless root ----
    // nextCommitment = keccak("shrincs-public-key" || paramSetId || nextStatefulPK || curPkSeed || curHypertreeRoot)
    let mut rk_preimage: Vec<u8> = Vec::new();
    rk_preimage.extend_from_slice(b"shrincs-public-key");
    rk_preimage.push(packed(PROFILE));
    rk_preimage.extend_from_slice(&next_stateful_pub.stateful_public_key);
    rk_preimage.extend_from_slice(&main_pub.pk_seed);
    rk_preimage.extend_from_slice(&main_pub.hypertree_root);
    let rk_next_commit = k(&rk_preimage);
    let rk_payload = hash_words(&[&rk_next_commit, &u256(0)]);
    let rk_ctx = stateful_ctx(0, action("quip.shrincs.action.rotateKey"), rk_payload);
    let rk_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &rk_ctx);
    let rk_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &rk_msg).expect("rotateKey sign");

    // ---- upgradeToAndCall (leaf 1, no migrate) ----
    // newImplementation = 0xBEEF (matches the Solidity verifyUpgrade test), shouldMigrate=false,
    // migratorPayload empty ⇒ migratorHash = keccak("").
    let upg_impl: [u8; 20] = hex20("0x000000000000000000000000000000000000beef");
    let upg_payload = hash_words(&[&addr32(upg_impl), &u256(0), &k(&[])]);
    let upg_ctx = stateful_ctx(0, action("quip.shrincs.action.upgrade"), upg_payload);
    let upg_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &upg_ctx);
    let upg_sig =
        ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &upg_msg).expect("upgrade sign");

    // ---- upgradeToAndCall WITH migrate (leaf 1): shouldMigrate=true, empty migratorPayload ----
    let upg_mig_payload = hash_words(&[&addr32(upg_impl), &u256(1), &k(&[])]);
    let upg_mig_ctx = stateful_ctx(0, action("quip.shrincs.action.upgrade"), upg_mig_payload);
    let upg_mig_msg = verifier.stateful_action_message_hash(PROFILE, main_commit, &upg_mig_ctx);
    let upg_mig_sig = ShrincsSigner::sign_stateful_raw_at_leaf(&main_key, 1, &upg_mig_msg)
        .expect("upgrade migrate sign");

    // ---- recoverWallet (case key `rotateFullKey`): stateless break-glass, same owner ----
    let rf_ctx = RotationContext {
        domain_separator: domain_separator(),
        nonce: u256(0),
        key_version: u256(0),
    };
    let rf_msg = verifier.full_rotation_message_hash(
        PROFILE,
        main_commit,
        &main_pub,
        &rf_ctx,
        &rotation_target(&next_full_pub),
    );
    let rf_sig = ShrincsSigner::sign_stateless_raw(&main_key, &rf_msg).expect("rotateFull sign");

    // ---- ERC-1271 (stateless, dedicated key, fixed nonce 0) ----
    let erc1271_hash = k(b"shrincs wallet 1271 digest");
    let erc1271_ctx = stateful_ctx(0, action("quip.shrincs.action.erc1271"), erc1271_hash);
    let erc1271_msg = verifier.stateless_action_message_hash(PROFILE, erc1271_commit, &erc1271_ctx);
    let erc1271_sig =
        ShrincsSigner::sign_stateless_raw(&erc1271_key, &erc1271_msg).expect("1271 sign");

    let vectors = json!({
        "wallet": hex(WALLET),
        "chainId": CHAIN_ID,
        "domainTag": String::from_utf8_lossy(DOMAIN_TAG_MESSAGE),
        "domainSeparator": hex(domain_separator()),
        "mainKey": public_key_json(&main_pub),
        "erc1271Key": public_key_json(&erc1271_pub),
        "cases": {
            "erc4337": erc4337,
            "execute": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "target": hex(exec_target), "value": exec_value, "data": hex(&exec_data), "fee": exec_fee,
                "payloadHash": hex(exec_payload), "message": hex(exec_msg),
                "signature": stateful_sig_json(&exec_sig),
            },
            "executeEth": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "target": hex(exec_target), "value": exec_eth_value, "data": "0x", "fee": exec_fee,
                "payloadHash": hex(exec_eth_payload), "message": hex(exec_eth_msg),
                "signature": stateful_sig_json(&exec_eth_sig),
            },
            "executeCall": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "target": hex(exec_call_target), "value": 0, "data": hex(&exec_call_data), "fee": exec_fee,
                "payloadHash": hex(exec_call_payload), "message": hex(exec_call_msg),
                "signature": stateful_sig_json(&exec_call_sig),
            },
            "withdraw": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "to": hex(wd_to), "amount": wd_amount,
                "payloadHash": hex(wd_payload), "message": hex(wd_msg),
                "signature": stateful_sig_json(&wd_sig),
            },
            "transferOwnership": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "newOwner": hex(new_owner),
                "nextCommitment": hex(next_full_commit),
                "nextKey": public_key_json(&next_full_pub),
                "payloadHash": hex(to_payload), "message": hex(to_msg),
                "signature": stateful_sig_json(&to_sig),
                "recoverySignature": stateless_sig_json(&to_recovery_sig),
            },
            "setErc1271Key": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "newCommitment": hex(new_1271_commit), "newParameterSetId": 0,
                "newErc1271Key": public_key_json(&replacement_1271_pub),
                "payloadHash": hex(set1271_payload), "message": hex(set1271_msg),
                "signature": stateful_sig_json(&set1271_sig),
            },
            "rotateKey": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "nextParameterSetId": 0,
                "nextStatefulPublicKey": hex(&next_stateful_pub.stateful_public_key),
                "nextStatefulKey": public_key_json(&next_stateful_pub),
                "nextCommitment": hex(rk_next_commit),
                "payloadHash": hex(rk_payload), "message": hex(rk_msg),
                "signature": stateful_sig_json(&rk_sig),
            },
            "upgrade": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "newImplementation": hex(upg_impl), "shouldMigrate": false, "migratorPayload": "0x",
                "payloadHash": hex(upg_payload), "message": hex(upg_msg),
                "signature": stateful_sig_json(&upg_sig),
            },
            "upgradeMigrate": {
                "leaf": 1, "nonce": 0, "keyVersion": 0,
                "newImplementation": hex(upg_impl), "shouldMigrate": true, "migratorPayload": "0x",
                "payloadHash": hex(upg_mig_payload), "message": hex(upg_mig_msg),
                "signature": stateful_sig_json(&upg_mig_sig),
            },
            "rotateFullKey": {
                "nonce": 0, "keyVersion": 0,
                "nextKey": public_key_json(&next_full_pub),
                "message": hex(rf_msg),
                "signature": stateless_sig_json(&rf_sig),
            },
            "erc1271": {
                "keyVersion": 0,
                "hash": hex(erc1271_hash),
                "message": hex(erc1271_msg),
                "signature": stateless_sig_json(&erc1271_sig),
            }
        }
    });

    let out = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(Path::new(OUT_PATH), format!("{out}\n")).expect("write wallet vectors");
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

fn stateless_sig_json(sig: &StatelessSignature) -> Value {
    json!({
        "fors": {
            "randomizer": hex(&sig.fors.randomizer),
            "counter": sig.fors.counter,
            "entries": sig.fors.entries.iter().map(|e| json!({
                "secretLeaf": hex(&e.secret_leaf),
                "authPath": e.auth_path.iter().map(hex).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        },
        "hypertree": sig.hypertree.iter().map(|l| json!({
            "treeIndex": l.tree_index,
            "leafIndex": l.leaf_index,
            "wotsCPkHash": hex(&l.wots_c_pk_hash),
            "wotsCSignature": {
                "randomizer": hex(&l.wots_c_signature.randomizer),
                "counter": l.wots_c_signature.counter,
                "chains": l.wots_c_signature.chains.iter().map(hex).collect::<Vec<_>>(),
            },
            "authPath": l.auth_path.iter().map(hex).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn hex<T: AsRef<[u8]>>(bytes: T) -> String {
    let mut out = String::from("0x");
    for b in bytes.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex20(s: &str) -> [u8; 20] {
    let s = s.trim_start_matches("0x");
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}
