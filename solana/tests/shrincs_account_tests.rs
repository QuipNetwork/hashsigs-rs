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

//! Coverage for the SHRINCS account-example state machine (bead
//! hashsigs-rs-3na). Native mode only (no SBF build required), mirroring
//! `solana_unit_tests.rs::sphincs_plus_c_solana_test`. Every key uses a small
//! `max_stateful_signatures = 4` at the default 256s profile so tests stay
//! fast.

use hashsigs_rs_solana::account::{
    self, RotationTargetDto, ShrincsAccountState, StatefulPolicy, StatefulRotationTargetDto,
};
use hashsigs_rs_solana::processor::{process_instruction, WOTSPlusInstruction};
use hashsigs_rs_solana::sphincs_plus_c::{
    ShrincsPublicKeyDto, StatefulSignatureDto, StatelessSignatureDto,
};

use borsh::{BorshDeserialize, BorshSerialize};
use hashsigs_rs::shrincs::{
    ActionContext, PublicKey as ShrincsPublicKey, RotationContext, RotationTarget, ShrincsSigner,
    ShrincsVerifier, StatefulRotationTarget, PROFILE_NAME,
};
use solana_program_test::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};

async fn setup_test() -> (ProgramTest, Keypair) {
    let program_id = Keypair::new();
    let mut program_test = ProgramTest::new(
        "hashsigs_rs_solana",
        program_id.pubkey(),
        processor!(process_instruction),
    );
    program_test.set_compute_max_units(1_400_000);
    program_test.prefer_bpf(std::env::var_os("SBF_OUT_DIR").is_some());
    (program_test, program_id)
}

/// Send a single instruction signed by the payer plus any extra signers.
/// Forces a genuinely fresh blockhash first (not just "the latest", which can
/// still equal the previous one within a slot): several tests intentionally
/// resubmit byte-identical instruction data to prove replay rejection, and an
/// identical blockhash would make the two transactions identical signatures,
/// which banks-client treats as an already-landed duplicate and short-circuits
/// without re-invoking the program at all.
async fn send(
    context: &mut ProgramTestContext,
    program_id: &Pubkey,
    instruction_data: WOTSPlusInstruction,
    accounts: Vec<AccountMeta>,
    extra_signers: &[&Keypair],
) -> Result<(), BanksClientError> {
    let mut data = Vec::new();
    instruction_data.serialize(&mut data).unwrap();
    let instruction = Instruction {
        program_id: *program_id,
        accounts,
        data,
    };
    context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers: Vec<&Keypair> = vec![&context.payer];
    signers.extend_from_slice(extra_signers);
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&context.payer.pubkey()),
        &signers,
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
}

async fn load_state(context: &mut ProgramTestContext, account_pda: &Pubkey) -> ShrincsAccountState {
    let account = context
        .banks_client
        .get_account(*account_pda)
        .await
        .unwrap()
        .expect("account exists");
    ShrincsAccountState::try_from_slice(&account.data).expect("valid account state")
}

/// The formula behind `hashsigs_rs::shrincs`'s crate-private
/// `public_key_commitment`, replicated here because it isn't part of the
/// public API: `keccak256("shrincs-public-key/" || PROFILE_NAME ||
/// stateful_public_key || pk_seed || hypertree_root)`. Needed to predict the
/// commitment for a `StatefulRotationTarget` that keeps the current
/// stateless key material and only swaps in a fresh stateful subtree.
fn stateful_rotation_commitment(
    stateful_public_key: &[u8],
    pk_seed: &[u8],
    hypertree_root: &[u8],
) -> [u8; 32] {
    solana_program::keccak::hashv(&[
        b"shrincs-public-key/",
        PROFILE_NAME.as_bytes(),
        stateful_public_key,
        pk_seed,
        hypertree_root,
    ])
    .to_bytes()
}

fn commitment32(public_key: &ShrincsPublicKey) -> [u8; 32] {
    public_key
        .public_key_commitment
        .clone()
        .try_into()
        .expect("commitment is 32 bytes")
}

struct Fixture {
    program_test: ProgramTest,
    program_id: Keypair,
    owner: Keypair,
    salt: [u8; 32],
    account_pda: Pubkey,
}

async fn setup_account_fixture(seed: &'static [u8]) -> Fixture {
    let (program_test, program_id) = setup_test().await;
    let owner = Keypair::new();
    let salt = solana_program::keccak::hash(seed).to_bytes();
    let (account_pda, _bump) = account::account_pda(&program_id.pubkey(), &owner.pubkey(), &salt);
    Fixture {
        program_test,
        program_id,
        owner,
        salt,
        account_pda,
    }
}

async fn init_account(
    context: &mut ProgramTestContext,
    program_id: &Pubkey,
    owner: &Keypair,
    salt: [u8; 32],
    account_pda: Pubkey,
    initial_commitment: [u8; 32],
) {
    let result = send(
        context,
        program_id,
        WOTSPlusInstruction::ShrincsAccountInit {
            salt,
            initial_public_key_commitment: initial_commitment,
        },
        vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(owner.pubkey(), true),
            AccountMeta::new(account_pda, false),
            AccountMeta::new_readonly(solana_program::system_program::id(), false),
        ],
        &[owner],
    )
    .await;
    result.expect("init should succeed");
}

#[tokio::test]
async fn init_then_happy_stateful_action_advances_nonce_leaf_and_freezes() {
    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"account happy stateful seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account happy stateful fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_type = [7u8; 32];
    let payload_hash = [9u8; 32];
    let context_msg = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type,
        payload_hash,
    };
    let signature =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context_msg)
            .expect("sign");
    assert!(ShrincsVerifier::new().verify_stateful(
        commitment,
        &public_key,
        &context_msg,
        &signature,
    ));

    let bitmap_pda = account::bitmap_word_pda(
        &fixture.program_id.pubkey(),
        &fixture.account_pda,
        &[0u8; 32],
        0,
    )
    .0;

    let accounts = vec![
        AccountMeta::new(fixture.account_pda, false),
        AccountMeta::new(bitmap_pda, false),
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];
    let result = send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key.clone()),
            signature: StatefulSignatureDto::from(signature),
        },
        accounts,
        &[],
    )
    .await;
    result.expect("stateful action should succeed");

    let state = load_state(&mut context, &fixture.account_pda).await;
    let mut expected_nonce = [0u8; 32];
    expected_nonce[31] = 1;
    assert_eq!(state.nonce, expected_nonce);
    assert_eq!(state.next_stateful_leaf_index, 2);
    assert!(state.stateful_policy_frozen);
    assert_eq!(state.stateful_policy, StatefulPolicy::MonotonicIndex as u8);
}

#[tokio::test]
async fn monotonic_replay_is_rejected() {
    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"account monotonic replay seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account monotonic replay fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_type = [1u8; 32];
    let payload_hash = [2u8; 32];
    let context_msg = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type,
        payload_hash,
    };
    let signature =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context_msg)
            .expect("sign");
    let bitmap_pda = account::bitmap_word_pda(
        &fixture.program_id.pubkey(),
        &fixture.account_pda,
        &[0u8; 32],
        0,
    )
    .0;
    let accounts = vec![
        AccountMeta::new(fixture.account_pda, false),
        AccountMeta::new(bitmap_pda, false),
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key.clone()),
            signature: StatefulSignatureDto::from(signature.clone()),
        },
        accounts.clone(),
        &[],
    )
    .await
    .expect("first stateful action should succeed");

    // Leaf 1 has already been consumed under monotonic tracking; the next
    // expected leaf is now 2, so replaying the leaf-1 signature must fail.
    let replay = send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key),
            signature: StatefulSignatureDto::from(signature),
        },
        accounts,
        &[],
    )
    .await;
    assert!(replay.is_err(), "replaying leaf 1 must be rejected");
}

#[tokio::test]
async fn stateless_action_advances_budget_accounting() {
    let (signing_key, public_key) =
        ShrincsSigner::keygen(b"account stateless budget seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account stateless budget fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_type = [3u8; 32];
    let payload_hash = [4u8; 32];
    let context_msg = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type,
        payload_hash,
    };
    let message = ShrincsVerifier::new().stateless_action_message_hash(commitment, &context_msg);
    let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).expect("sign");

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatelessAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key),
            signature: StatelessSignatureDto::from(signature),
        },
        vec![AccountMeta::new(fixture.account_pda, false)],
        &[],
    )
    .await
    .expect("stateless action should succeed");

    let state = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state.stateless_signatures_used, 1);
    assert_ne!(state.nonce, [0u8; 32]);
}

#[tokio::test]
async fn recovery_rotation_policy_blocks_stateful_actions() {
    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"account recovery blocks stateful seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture =
        setup_account_fixture(b"account recovery blocks stateful fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountSetPolicyRecoveryRotation,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can select recovery policy");

    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_type = [5u8; 32];
    let payload_hash = [6u8; 32];
    let context_msg = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type,
        payload_hash,
    };
    let signature =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context_msg)
            .expect("sign");
    let bitmap_pda = account::bitmap_word_pda(
        &fixture.program_id.pubkey(),
        &fixture.account_pda,
        &[0u8; 32],
        0,
    )
    .0;

    let accounts = vec![
        AccountMeta::new(fixture.account_pda, false),
        AccountMeta::new(bitmap_pda, false),
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];
    let result = send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key),
            signature: StatefulSignatureDto::from(signature),
        },
        accounts,
        &[],
    )
    .await;
    assert!(
        result.is_err(),
        "stateful actions must be disabled under the recovery-rotation policy"
    );
}

#[tokio::test]
async fn owner_gating_rejects_non_owner_policy_change() {
    let (_signing_key, public_key) =
        ShrincsSigner::keygen(b"account owner gating seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account owner gating fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    let not_owner = Keypair::new();
    let result = send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountSetPolicyRecoveryRotation,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(not_owner.pubkey(), true),
        ],
        &[&not_owner],
    )
    .await;
    assert!(result.is_err(), "a non-owner signer must be rejected");

    let state = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state.stateful_policy, StatefulPolicy::MonotonicIndex as u8);
}

#[tokio::test]
async fn enter_recovery_mode_then_rotate_to_fresh_key_installs_and_resets() {
    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"account rotate fresh current seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account rotate fresh fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    // Consume one stateful leaf under the default monotonic policy first, so
    // the rotation below has to prove it un-freezes policy changes and
    // resets the leaf cursor, not just that a fresh account looks reset.
    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_context = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type: [8u8; 32],
        payload_hash: [9u8; 32],
    };
    let stateful_signature =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &action_context)
            .expect("sign stateful");
    let bitmap_pda = account::bitmap_word_pda(
        &fixture.program_id.pubkey(),
        &fixture.account_pda,
        &[0u8; 32],
        0,
    )
    .0;
    let warm_up_accounts = vec![
        AccountMeta::new(fixture.account_pda, false),
        AccountMeta::new(bitmap_pda, false),
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];
    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type: [8u8; 32],
            payload_hash: [9u8; 32],
            public_key: ShrincsPublicKeyDto::from(public_key.clone()),
            signature: StatefulSignatureDto::from(stateful_signature),
        },
        warm_up_accounts,
        &[],
    )
    .await
    .expect("stateful warm-up action should succeed");
    let warmed = load_state(&mut context, &fixture.account_pda).await;
    assert!(warmed.stateful_policy_frozen);
    assert_eq!(warmed.next_stateful_leaf_index, 2);

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountSetPolicyRecoveryRotation,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can select recovery policy even after the freeze");
    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountEnterRecoveryMode,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can arm recovery mode");

    let state_before_rotation = load_state(&mut context, &fixture.account_pda).await;
    let (_next_signing_key, next_public_key) =
        ShrincsSigner::keygen(b"account rotate fresh next seed", 8).expect("keygen next");
    let next_commitment = stateful_rotation_commitment(
        &next_public_key.stateful_public_key,
        &public_key.pk_seed,
        &public_key.hypertree_root,
    );
    let next_target = StatefulRotationTarget {
        stateful_public_key: next_public_key.stateful_public_key.clone(),
        public_key_commitment: next_commitment.to_vec(),
    };
    let rotation_context = RotationContext {
        domain_separator,
        nonce: state_before_rotation.nonce,
        key_version: state_before_rotation.key_version,
    };
    let rotation_message = ShrincsVerifier::new().stateful_rotation_message_hash(
        state_before_rotation.current_public_key_commitment,
        &public_key,
        &rotation_context,
        &next_target,
    );
    let recovery_signature =
        ShrincsSigner::sign_stateless_raw(&signing_key, &rotation_message).expect("sign recovery");

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountRotateToFreshKey {
            public_key: ShrincsPublicKeyDto::from(public_key),
            recovery_signature: StatelessSignatureDto::from(recovery_signature),
            next_stateful_key: StatefulRotationTargetDto {
                stateful_public_key: next_target.stateful_public_key,
                public_key_commitment: next_commitment,
            },
        },
        vec![AccountMeta::new(fixture.account_pda, false)],
        &[],
    )
    .await
    .expect("rotate to fresh key should succeed");

    let state = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state.current_public_key_commitment, next_commitment);
    assert_eq!(
        state.stateless_signatures_used, 1,
        "the recovery signature itself counts as a stateless use, and a fresh-key \
         rotation does not reset usage since the stateless key material is unchanged"
    );
    assert_eq!(state.next_stateful_leaf_index, 1, "leaf cursor resets on rotation");
    assert!(!state.stateful_policy_frozen, "rotation clears the policy freeze");
    assert_eq!(state.stateful_policy, StatefulPolicy::MonotonicIndex as u8);
    assert!(!state.recovery_mode, "rotation exits recovery mode");
    assert_ne!(state.key_version, [0u8; 32]);
}

#[tokio::test]
async fn full_rotation_resets_stateless_usage() {
    let (signing_key, public_key) =
        ShrincsSigner::keygen(b"account full rotation current seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account full rotation fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountSetPolicyRecoveryRotation,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can select recovery policy");
    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountEnterRecoveryMode,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can arm recovery mode");

    // Recovery mode also permits plain stateless actions, so consume one to
    // establish a nonzero usage baseline the rotation below must clear.
    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let warm_up_state = load_state(&mut context, &fixture.account_pda).await;
    let warm_up_context = ActionContext {
        domain_separator,
        nonce: warm_up_state.nonce,
        key_version: warm_up_state.key_version,
        action_type: [1u8; 32],
        payload_hash: [2u8; 32],
    };
    let warm_up_message =
        ShrincsVerifier::new().stateless_action_message_hash(commitment, &warm_up_context);
    let warm_up_signature =
        ShrincsSigner::sign_stateless_raw(&signing_key, &warm_up_message).expect("sign warm-up");
    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatelessAction {
            action_type: [1u8; 32],
            payload_hash: [2u8; 32],
            public_key: ShrincsPublicKeyDto::from(public_key.clone()),
            signature: StatelessSignatureDto::from(warm_up_signature),
        },
        vec![AccountMeta::new(fixture.account_pda, false)],
        &[],
    )
    .await
    .expect("warm-up stateless action should succeed");
    let state_before_rotation = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state_before_rotation.stateless_signatures_used, 1);

    let (_next_signing_key, next_public_key) =
        ShrincsSigner::keygen(b"account full rotation next seed", 8).expect("keygen next");
    let next_target = RotationTarget {
        stateful_public_key: next_public_key.stateful_public_key.clone(),
        public_key_commitment: next_public_key.public_key_commitment.clone(),
        pk_seed: next_public_key.pk_seed.clone(),
        hypertree_root: next_public_key.hypertree_root.clone(),
    };
    let rotation_context = RotationContext {
        domain_separator,
        nonce: state_before_rotation.nonce,
        key_version: state_before_rotation.key_version,
    };
    let rotation_message = ShrincsVerifier::new().full_rotation_message_hash(
        state_before_rotation.current_public_key_commitment,
        &public_key,
        &rotation_context,
        &next_target,
    );
    let recovery_signature =
        ShrincsSigner::sign_stateless_raw(&signing_key, &rotation_message).expect("sign recovery");
    let next_commitment = commitment32(&next_public_key);

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountRotateFullKey {
            public_key: ShrincsPublicKeyDto::from(public_key),
            recovery_signature: StatelessSignatureDto::from(recovery_signature),
            next_key: RotationTargetDto {
                stateful_public_key: next_target.stateful_public_key,
                public_key_commitment: next_commitment,
                pk_seed: next_target.pk_seed,
                hypertree_root: next_target.hypertree_root,
            },
        },
        vec![AccountMeta::new(fixture.account_pda, false)],
        &[],
    )
    .await
    .expect("full rotation should succeed");

    let state = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state.current_public_key_commitment, next_commitment);
    assert_eq!(
        state.stateless_signatures_used, 0,
        "full rotation resets stateless usage because the stateless key material changed"
    );
    assert_eq!(state.next_stateful_leaf_index, 1);
    assert!(!state.stateful_policy_frozen);
    assert_eq!(state.stateful_policy, StatefulPolicy::MonotonicIndex as u8);
    assert!(!state.recovery_mode);
}

#[tokio::test]
async fn leaf_bitmap_policy_rejects_leaf_reuse() {
    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"account leaf bitmap seed", 4).expect("keygen");
    let commitment = commitment32(&public_key);
    let fixture = setup_account_fixture(b"account leaf bitmap fixture").await;
    let mut context = fixture.program_test.start_with_context().await;
    init_account(
        &mut context,
        &fixture.program_id.pubkey(),
        &fixture.owner,
        fixture.salt,
        fixture.account_pda,
        commitment,
    )
    .await;

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountSetPolicyLeafBitmap,
        vec![
            AccountMeta::new(fixture.account_pda, false),
            AccountMeta::new_readonly(fixture.owner.pubkey(), true),
        ],
        &[&fixture.owner],
    )
    .await
    .expect("owner can select leaf-bitmap policy");
    let state = load_state(&mut context, &fixture.account_pda).await;
    assert_eq!(state.stateful_policy, StatefulPolicy::LeafBitmap as u8);

    let domain_separator =
        account::domain_separator(&fixture.program_id.pubkey(), &fixture.account_pda);
    let action_type = [11u8; 32];
    let payload_hash = [12u8; 32];
    let context_msg = ActionContext {
        domain_separator,
        nonce: [0u8; 32],
        key_version: [0u8; 32],
        action_type,
        payload_hash,
    };
    let signature =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context_msg)
            .expect("sign");
    let bitmap_pda = account::bitmap_word_pda(
        &fixture.program_id.pubkey(),
        &fixture.account_pda,
        &[0u8; 32],
        0,
    )
    .0;
    let accounts = vec![
        AccountMeta::new(fixture.account_pda, false),
        AccountMeta::new(bitmap_pda, false),
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
    ];

    send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key.clone()),
            signature: StatefulSignatureDto::from(signature.clone()),
        },
        accounts.clone(),
        &[],
    )
    .await
    .expect("first use of leaf 1 should succeed under bitmap tracking");

    let state = load_state(&mut context, &fixture.account_pda).await;
    // Bitmap tracking never advances the monotonic cursor; only the freeze
    // flag and the (out-of-account) bitmap word change.
    assert_eq!(state.next_stateful_leaf_index, 1);
    assert!(state.stateful_policy_frozen);

    let reuse = send(
        &mut context,
        &fixture.program_id.pubkey(),
        WOTSPlusInstruction::ShrincsAccountVerifyStatefulAction {
            action_type,
            payload_hash,
            public_key: ShrincsPublicKeyDto::from(public_key),
            signature: StatefulSignatureDto::from(signature),
        },
        accounts,
        &[],
    )
    .await;
    assert!(reuse.is_err(), "reusing a marked-used leaf must be rejected");
}
