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

//! Instruction handlers for SHRINCS account actions.
//!
//! Ported from the deleted Solana account program (`solana/src/account.rs`
//! prior to its removal at `5e13d35~1`), adapted to build on this crate's
//! `state`/`pda`/`messages` modules instead of a `hashsigs-rs` dependency
//! living directly in the handler file.
//!
//! `process_init`, `process_verify_stateful_action`,
//! `process_verify_stateless_action`, `process_set_policy_monotonic`,
//! `process_set_policy_recovery_rotation`, `process_set_policy_leaf_bitmap`,
//! `process_enter_recovery_mode`, `process_rotate_to_fresh_key`,
//! `process_rotate_full_key`, `process_is_valid_signature`, and
//! `process_is_leaf_used` are exposed `pub(crate)` and are dispatched from
//! [`process_instruction`] through the [`ShrincsAccountInstruction`] enum --
//! one variant per handler above. This module's own tests still exercise most
//! handlers through a lighter test-only dispatcher (see `tests` below) for
//! direct-call convenience, plus one end-to-end test that submits real
//! `ShrincsAccountInstruction`-encoded instructions through
//! [`process_instruction`] itself.
//!
//! `process_rotate_to_fresh_key`/`process_rotate_full_key` authorize their
//! rotation through [`crate::rotation`] rather than a dedicated raw-verify
//! path -- see that module's doc comment for why.
//!
//! `process_is_valid_signature`/`process_is_leaf_used` are READ-ONLY query
//! handlers ported from the deleted wasm host wrapper's `isValidSignature`/
//! `isLeafUsed` (`src/account/mod.rs` prior to its removal at `d982d45~1`):
//! unlike every other handler above, they never call `store_state` or touch a
//! leaf-bitmap PDA -- they answer through `set_return_data` and always return
//! `Ok(())`, even when the query answer is "no".

use borsh::{BorshDeserialize, BorshSerialize};
use hashsigs_rs::shrincs::verifier::{
    ActionContext, PublicKey, ShrincsVerifier, StatefulSignature, StatelessSignature,
    STATEFUL_PUBLIC_KEY_BYTES, STATELESS_SIGNATURE_LIMIT,
};
use hashsigs_rs_solana::sphincs_plus_c::{
    ShrincsPublicKeyDto, StatefulSignatureDto, StatelessSignatureDto,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::set_return_data,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::messages;
use crate::pda::{
    account_pda, is_leaf_used, mark_leaf_used, LeafBitmapAccounts, ACCOUNT_SEED_PREFIX,
};
use crate::rotation::{self, RotationAuthorization};
use crate::state::{increment_u256_be, ShrincsAccountState, StatefulPolicy, HASH_LEN};

/// Freshly installed keys begin stateful signing at leaf 1: `auth_path` is
/// never empty for a valid stateful signature (see
/// [`hashsigs_rs::shrincs::verifier::StatefulSignature::auth_path`]'s "its
/// length is also the leaf index" doc), so leaf 0 is not a valid leaf.
const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;

/// Distinct wrapper failure reasons for the handlers in this module.
/// Mirrors (a subset of) `hashsigs_rs::account::AccountError`'s numbering
/// scheme, covering what `process_init`, `process_verify_stateful_action`,
/// `process_verify_stateless_action`, the policy/recovery setters, and the
/// rotation handlers (`process_rotate_to_fresh_key`/`process_rotate_full_key`,
/// via `crate::rotation`) can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum ShrincsAccountError {
    InvalidSignature = 0,
    StatefulPathDisabled = 1,
    StatefulLeafRejected = 2,
    RecoveryNotArmed = 3,
    BudgetExhausted = 4,
    OnlyOwner = 5,
    StatefulPolicyFrozen = 6,
    StatefulIndexRollback = 7,
    RecoveryPolicyRequired = 8,
    /// A rotation's `next_stateful_public_key` decodes to `max_signatures == 0`.
    RotationTargetInvalid = 9,
    /// A rotation's caller-declared `next_commitment` doesn't match the
    /// recomputed `ShrincsVerifier::public_key_commitment`.
    CommitmentMismatch = 10,
}

impl From<ShrincsAccountError> for ProgramError {
    fn from(err: ShrincsAccountError) -> Self {
        ProgramError::Custom(err as u32)
    }
}

/// Instruction data for [`process_init`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct InitArgs {
    pub salt: [u8; HASH_LEN],
    pub initial_commitment: [u8; HASH_LEN],
}

/// Instruction data for [`process_verify_stateful_action`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct StatefulActionArgs {
    pub public_key: ShrincsPublicKeyDto,
    pub action_type: [u8; HASH_LEN],
    pub payload_hash: [u8; HASH_LEN],
    pub signature: StatefulSignatureDto,
}

/// Instruction data for [`process_verify_stateless_action`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct StatelessActionArgs {
    pub public_key: ShrincsPublicKeyDto,
    pub action_type: [u8; HASH_LEN],
    pub payload_hash: [u8; HASH_LEN],
    pub signature: StatelessSignatureDto,
}

/// Instruction data for [`process_set_policy_monotonic`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct SetPolicyMonotonicArgs {
    pub initial_leaf_index: u32,
}

/// Instruction data for [`process_rotate_to_fresh_key`]. `recovery_signature`
/// is the CURRENT key's stateless signature authorizing this rotation (see
/// `crate::rotation`); the stateless half (`pk_seed`/`hypertree_root`) is not
/// repeated here because this rotation flavor keeps it unchanged.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct RotateToFreshKeyArgs {
    pub current_public_key: ShrincsPublicKeyDto,
    pub next_stateful_public_key: [u8; STATEFUL_PUBLIC_KEY_BYTES],
    pub next_commitment: [u8; HASH_LEN],
    pub recovery_signature: StatelessSignatureDto,
}

/// Instruction data for [`process_rotate_full_key`]. Like
/// [`RotateToFreshKeyArgs`], but also replaces the stateless half with
/// `next_pk_seed`/`next_hypertree_root`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct RotateFullKeyArgs {
    pub current_public_key: ShrincsPublicKeyDto,
    pub next_stateful_public_key: [u8; STATEFUL_PUBLIC_KEY_BYTES],
    pub next_pk_seed: [u8; HASH_LEN],
    pub next_hypertree_root: [u8; HASH_LEN],
    pub next_commitment: [u8; HASH_LEN],
    pub recovery_signature: StatelessSignatureDto,
}

/// [`IsValidSignatureArgs::mode`] value selecting stateful-action
/// verification. Mirrors the deleted wasm host wrapper's
/// `ERC1271_MODE_STATEFUL_ACTION` (`src/envelope.rs` prior to its removal at
/// `d982d45~1`).
pub(crate) const MODE_STATEFUL_ACTION: u8 = 1;
/// [`IsValidSignatureArgs::mode`] value selecting stateless-action
/// verification. Mirrors `ERC1271_MODE_STATELESS_ACTION`.
pub(crate) const MODE_STATELESS_ACTION: u8 = 2;

/// Instruction data for [`process_is_valid_signature`]: a mode-prefixed
/// ERC-1271-style envelope, modeled on the deleted wasm host wrapper's
/// `isValidSignature`/`Erc1271Envelope` (`src/account/mod.rs` and
/// `src/envelope.rs` prior to their removal at `d982d45~1`), kept
/// Borsh-decodable instead of ABI-encoded. `mode` selects how
/// `signature_bytes` decodes: [`MODE_STATEFUL_ACTION`] for a
/// `StatefulSignatureDto`, [`MODE_STATELESS_ACTION`] for a
/// `StatelessSignatureDto`; any other value is a malformed envelope.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct IsValidSignatureArgs {
    pub mode: u8,
    pub public_key: ShrincsPublicKeyDto,
    pub action_type: [u8; HASH_LEN],
    pub payload_hash: [u8; HASH_LEN],
    pub signature_bytes: Vec<u8>,
}

/// Instruction data for [`process_is_leaf_used`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct IsLeafUsedArgs {
    pub leaf_index: u32,
}

fn load_state(
    account_info: &AccountInfo,
    program_id: &Pubkey,
) -> Result<ShrincsAccountState, ProgramError> {
    if account_info.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let data = account_info.try_borrow_data()?;
    ShrincsAccountState::try_from_slice(&data).map_err(|_| ProgramError::InvalidAccountData)
}

fn store_state(account_info: &AccountInfo, state: &ShrincsAccountState) -> ProgramResult {
    let mut data = Vec::new();
    state
        .serialize(&mut data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let mut account_data = account_info.try_borrow_mut_data()?;
    if account_data.len() != data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    account_data.copy_from_slice(&data);
    Ok(())
}

/// Require `owner_info` to be a transaction signer matching `state.owner`.
/// Split into two distinct failures (matching [`process_init`]'s style for
/// signer checks): a missing signature is a generic Solana
/// `MissingRequiredSignature`, while a present-but-wrong signer is this
/// module's own [`ShrincsAccountError::OnlyOwner`].
fn only_owner(state: &ShrincsAccountState, owner_info: &AccountInfo) -> Result<(), ProgramError> {
    if !owner_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *owner_info.key != state.owner {
        return Err(ShrincsAccountError::OnlyOwner.into());
    }
    Ok(())
}

/// Check whether the active policy allows `leaf_index` before verification
/// (mirrors the deleted port's `checkStatefulLeafUse`/`precheckStatefulLeafUse`).
fn check_stateful_leaf_use(
    state: &ShrincsAccountState,
    leaf_index: u32,
    program_id: &Pubkey,
    account_key: &Pubkey,
    bitmap_account: &AccountInfo,
) -> Result<(), ProgramError> {
    match StatefulPolicy::try_from(state.stateful_policy)? {
        StatefulPolicy::RecoveryRotation => Err(ShrincsAccountError::StatefulPathDisabled.into()),
        StatefulPolicy::MonotonicIndex => {
            if leaf_index == state.next_stateful_leaf_index {
                Ok(())
            } else {
                Err(ShrincsAccountError::StatefulLeafRejected.into())
            }
        }
        StatefulPolicy::LeafBitmap => {
            if is_leaf_used(
                program_id,
                account_key,
                &state.key_version,
                leaf_index,
                bitmap_account,
            )? {
                Err(ShrincsAccountError::StatefulLeafRejected.into())
            } else {
                Ok(())
            }
        }
    }
}

/// Record a successfully verified stateful leaf under the active policy
/// (mirrors the deleted port's `commitStatefulLeafUse`).
fn commit_stateful_leaf_use(
    state: &mut ShrincsAccountState,
    leaf_index: u32,
    program_id: &Pubkey,
    account_key: &Pubkey,
    accounts: &LeafBitmapAccounts,
) -> ProgramResult {
    match StatefulPolicy::try_from(state.stateful_policy)? {
        StatefulPolicy::MonotonicIndex => {
            state.next_stateful_leaf_index = state.next_stateful_leaf_index.saturating_add(1);
        }
        StatefulPolicy::LeafBitmap => {
            mark_leaf_used(
                program_id,
                account_key,
                &state.key_version,
                leaf_index,
                accounts,
            )?;
        }
        StatefulPolicy::RecoveryRotation => {}
    }
    state.stateful_policy_frozen = true;
    Ok(())
}

/// Create `target` as a `program_id`-owned PDA of `space` bytes for the
/// account-state PDA itself, using the same griefing-resistant create-or-adopt
/// pattern as the bitmap word PDAs. The account PDA address is deterministic
/// (`account_pda(program_id, owner, salt)`), so a plain `create_account` CPI
/// would let anyone permanently block `Init` for that `(owner, salt)` by
/// sending the address a single lamport before the owner calls it
/// (`create_account` then fails `AccountAlreadyInUse`). Delegating to
/// [`crate::pda::create_or_adopt_pda`] tops up a pre-funded, still-empty
/// destination instead of failing. `process_init` has already confirmed
/// `target.data_is_empty()` (rejecting re-init), satisfying that function's
/// precondition.
fn create_account_pda<'info>(
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    program_id: &Pubkey,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    crate::pda::create_or_adopt_pda(
        &crate::pda::PdaInit {
            payer,
            target,
            system_program,
            program_id,
            space,
        },
        signer_seeds,
    )
}

/// Accounts: `[payer (signer, writable), owner (signer), account PDA
/// (writable), system_program]`. Installs the initial commitment, default
/// `MonotonicIndex` policy, `next_stateful_leaf_index = 1`, and zeroed
/// nonce/key_version.
pub(crate) fn process_init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: InitArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let payer = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;
    let account_info = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !payer.is_signer || !owner_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_pda, bump) = account_pda(program_id, owner_info.key, &args.salt);
    if expected_pda != *account_info.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if !account_info.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = ShrincsAccountState {
        current_public_key_commitment: args.initial_commitment,
        owner: *owner_info.key,
        nonce: [0u8; HASH_LEN],
        key_version: [0u8; HASH_LEN],
        stateless_signatures_used: 0,
        stateful_policy: StatefulPolicy::MonotonicIndex as u8,
        stateful_policy_frozen: false,
        next_stateful_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
        recovery_mode: false,
    };
    let mut data = Vec::new();
    state
        .serialize(&mut data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    create_account_pda(
        payer,
        account_info,
        system_program,
        program_id,
        data.len(),
        &[
            ACCOUNT_SEED_PREFIX,
            owner_info.key.as_ref(),
            &args.salt,
            &[bump],
        ],
    )?;

    account_info.try_borrow_mut_data()?[..data.len()].copy_from_slice(&data);
    msg!(
        "shrincs-account-event:Initialized:owner={}:commitment={:?}",
        owner_info.key,
        args.initial_commitment
    );
    Ok(())
}

/// Accounts: `[account PDA (writable), leaf-bitmap word PDA (writable;
/// required positionally, only touched under `LeafBitmap` policy), payer
/// (signer, writable; only used to fund a new bitmap word), system_program]`.
///
/// Builds the [`ActionContext`] itself from account STATE (`nonce` /
/// `key_version`) rather than accepting a caller-supplied context -- that is
/// the replay defense. The leaf-policy gate is keyed off
/// `signature.auth_path.len()`, the leaf the signature itself used (see the
/// "CRITICAL" note on [`ShrincsAccountError`]'s callers), never a free
/// caller-declared index.
pub(crate) fn process_verify_stateful_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: StatefulActionArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let bitmap_account = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    let public_key: PublicKey = args.public_key.into();
    let signature: StatefulSignature = args.signature.into();

    // Bind the leaf-policy gate to the leaf the SIGNATURE actually used.
    // `auth_path.len()` IS the stateful leaf index -- both
    // `hashsigs_rs::shrincs::Signature::auth_path`'s doc comment and
    // the core verifier (`uxmss::verify_stateful_unsafe_raw`, which derives
    // `leaf_index` the same way before recomputing the tree root) agree on
    // this. A caller cannot forge it independently of the signature: the
    // root recomputation folds `leaf_index` into every parent-hash step, so
    // an attacker declaring an unused index while replaying a signature over
    // an already-spent leaf would fail cryptographic verification, not just
    // the policy gate.
    if signature.auth_path.len() > u32::MAX as usize {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }
    let leaf_index = signature.auth_path.len() as u32;

    check_stateful_leaf_use(
        &state,
        leaf_index,
        program_id,
        account_info.key,
        bitmap_account,
    )?;

    let domain_separator = messages::domain_separator(program_id, account_info.key);
    let context: ActionContext = messages::action_context(
        domain_separator,
        state.nonce,
        state.key_version,
        args.action_type,
        args.payload_hash,
    );

    let is_valid = ShrincsVerifier::new().verify_stateful(
        state.current_public_key_commitment,
        &public_key,
        &context,
        &signature,
    );
    // Fail closed: a CPI caller that checks only instruction success must not
    // treat an invalid signature as accepted. Write the boolean first for
    // callers that inspect return data, then abort the transaction.
    set_return_data(&[is_valid as u8]);
    if !is_valid {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }

    commit_stateful_leaf_use(
        &mut state,
        leaf_index,
        program_id,
        account_info.key,
        &LeafBitmapAccounts {
            bitmap_account,
            payer,
            system_program,
        },
    )?;
    increment_u256_be(&mut state.nonce);
    msg!(
        "shrincs-account-event:StatefulSignatureVerified:leaf_index={}:nonce={:?}:key_version={:?}",
        leaf_index,
        state.nonce,
        state.key_version
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable)]`.
///
/// Builds the [`ActionContext`] itself from account STATE, exactly like
/// [`process_verify_stateful_action`] -- see that function's doc comment.
pub(crate) fn process_verify_stateless_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: StatelessActionArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    let policy = StatefulPolicy::try_from(state.stateful_policy)?;
    if policy == StatefulPolicy::RecoveryRotation && !state.recovery_mode {
        return Err(ShrincsAccountError::RecoveryNotArmed.into());
    }
    if state.stateless_signatures_used >= STATELESS_SIGNATURE_LIMIT {
        return Err(ShrincsAccountError::BudgetExhausted.into());
    }

    let public_key: PublicKey = args.public_key.into();
    let signature: StatelessSignature = args.signature.into();
    let domain_separator = messages::domain_separator(program_id, account_info.key);
    let context: ActionContext = messages::action_context(
        domain_separator,
        state.nonce,
        state.key_version,
        args.action_type,
        args.payload_hash,
    );

    let is_valid = ShrincsVerifier::new().verify_stateless(
        state.current_public_key_commitment,
        &public_key,
        &context,
        &signature,
    );
    // Fail closed: see `process_verify_stateful_action`.
    set_return_data(&[is_valid as u8]);
    if !is_valid {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }

    increment_u256_be(&mut state.nonce);
    state.stateless_signatures_used += 1;
    msg!(
        "shrincs-account-event:StatelessSignatureVerified:used_count={}:nonce={:?}:key_version={:?}",
        state.stateless_signatures_used,
        state.nonce,
        state.key_version
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
///
/// Owner-gated. Switches the stateful-leaf-tracking policy to
/// `MonotonicIndex` and resets the expected-next-leaf cursor to
/// `args.initial_leaf_index`. Blocked while `stateful_policy_frozen` (set by
/// [`commit_stateful_leaf_use`] on first stateful use) and rejects any
/// `initial_leaf_index` below the current cursor -- a rollback would
/// re-enable leaves already consumed under the prior policy.
pub(crate) fn process_set_policy_monotonic(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: SetPolicyMonotonicArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;
    if state.stateful_policy_frozen {
        return Err(ShrincsAccountError::StatefulPolicyFrozen.into());
    }
    if args.initial_leaf_index < state.next_stateful_leaf_index {
        return Err(ShrincsAccountError::StatefulIndexRollback.into());
    }

    state.stateful_policy = StatefulPolicy::MonotonicIndex as u8;
    state.next_stateful_leaf_index = args.initial_leaf_index;
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
///
/// Owner-gated. Switches the stateful policy to `RecoveryRotation`.
/// EXEMPT from the `stateful_policy_frozen` check -- an intentional Rust
/// divergence from Solidity, documented as "Recovery-rotation freeze
/// exemption (audit F1)" in `docs/solidity-parity.md`: Solidity requires an
/// unfrozen policy to enter `RecoveryRotation`, but freezing happens on
/// first stateful use and only rotation clears it, so under Solidity's rule
/// a used monotonic/bitmap account can never reach `RecoveryRotation` (and
/// therefore can never rotate) again. Skipping the freeze check here cannot
/// re-enable a spent stateful leaf: [`check_stateful_leaf_use`] rejects all
/// stateful use outright once the policy is `RecoveryRotation`.
pub(crate) fn process_set_policy_recovery_rotation(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;

    state.stateful_policy = StatefulPolicy::RecoveryRotation as u8;
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
///
/// Owner-gated. Switches the stateful policy to `LeafBitmap`. Blocked while
/// `stateful_policy_frozen`, like [`process_set_policy_monotonic`] (not
/// exempt: unlike `RecoveryRotation`, `LeafBitmap` still accepts stateful
/// signatures, so switching into it while frozen could bypass the freeze).
pub(crate) fn process_set_policy_leaf_bitmap(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;
    if state.stateful_policy_frozen {
        return Err(ShrincsAccountError::StatefulPolicyFrozen.into());
    }

    state.stateful_policy = StatefulPolicy::LeafBitmap as u8;
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
///
/// Owner-gated. Arms recovery mode, the gate
/// [`process_verify_stateless_action`] checks before accepting a stateless
/// signature under `RecoveryRotation` policy. Requires `RecoveryRotation` to
/// already be the active policy.
pub(crate) fn process_enter_recovery_mode(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;
    if StatefulPolicy::try_from(state.stateful_policy)? != StatefulPolicy::RecoveryRotation {
        return Err(ShrincsAccountError::RecoveryPolicyRequired.into());
    }

    state.recovery_mode = true;
    msg!(
        "shrincs-account-event:RecoveryModeEntered:key_version={:?}",
        state.key_version
    );
    store_state(account_info, &state)
}

/// Reset per-epoch state on a successful rotation, shared by both flavors
/// (ports the deleted `install_rotated_key`, `solana/src/account.rs` prior to
/// `5e13d35~1`, line ~487): install `next_commitment`, bump `key_version` and
/// `nonce`, and reopen the account for ordinary use (`next_stateful_leaf_index`
/// back to 1, `MonotonicIndex` unfrozen, `recovery_mode` cleared).
/// `reset_stateless_usage` is the caller's per-flavor decision on
/// `stateless_signatures_used` (always false for fresh-key; only true for
/// full-key when [`rotation::stateless_half_changed`] reports the stateless
/// half moved).
fn install_rotated_key(
    state: &mut ShrincsAccountState,
    next_commitment: [u8; HASH_LEN],
    reset_stateless_usage: bool,
) {
    state.current_public_key_commitment = next_commitment;
    increment_u256_be(&mut state.key_version);
    if reset_stateless_usage {
        state.stateless_signatures_used = 0;
    }
    state.next_stateful_leaf_index = INITIAL_STATEFUL_LEAF_INDEX;
    state.stateful_policy = StatefulPolicy::MonotonicIndex as u8;
    state.stateful_policy_frozen = false;
    state.recovery_mode = false;
    increment_u256_be(&mut state.nonce);
}

/// Require `RecoveryRotation` policy AND `state.recovery_mode == true` --
/// both gates the deleted port's rotation handlers checked before
/// authorizing anything (`solana/src/account.rs` prior to `5e13d35~1`,
/// `process_rotate_to_fresh_key`/`process_rotate_full_key`, lines ~710-716
/// and ~770-776): `RecoveryPolicyRequired` if the active policy isn't
/// `RecoveryRotation`, `RecoveryNotArmed` if recovery mode isn't armed.
fn require_recovery_mode(state: &ShrincsAccountState) -> Result<(), ProgramError> {
    if StatefulPolicy::try_from(state.stateful_policy)? != StatefulPolicy::RecoveryRotation {
        return Err(ShrincsAccountError::RecoveryPolicyRequired.into());
    }
    if !state.recovery_mode {
        return Err(ShrincsAccountError::RecoveryNotArmed.into());
    }
    Ok(())
}

/// Accounts: `[account PDA (writable)]`.
///
/// Rotates the stateful bundle only, keeping the current stateless half in
/// place. Authorized by the CURRENT key's stateless recovery signature over
/// an `ACTION_ROTATE_STATEFUL` action (see [`crate::rotation`] for what that
/// binds and why there is no owner-signer requirement here: the deleted port
/// (`solana/src/account.rs` prior to `5e13d35~1`, `process_rotate_to_fresh_key`,
/// line 699) took only this same single-account layout -- the stateless
/// recovery signature IS the sole authorization).
pub(crate) fn process_rotate_to_fresh_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: RotateToFreshKeyArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    require_recovery_mode(&state)?;

    let current_public_key: PublicKey = args.current_public_key.into();
    let recovery_signature: StatelessSignature = args.recovery_signature.into();
    let auth = RotationAuthorization {
        state: &state,
        domain_separator: messages::domain_separator(program_id, account_info.key),
        current_public_key: &current_public_key,
        recovery_signature: &recovery_signature,
    };
    rotation::authorize_fresh_key_rotation(
        &auth,
        &args.next_stateful_public_key,
        args.next_commitment,
    )?;

    let previous_commitment = state.current_public_key_commitment;
    // Fresh-key rotation keeps the current stateless half unchanged, so its
    // usage accounting carries forward: reset_stateless_usage = false.
    install_rotated_key(&mut state, args.next_commitment, false);
    msg!(
        "shrincs-account-event:KeyRotated:previous={:?}:next={:?}:key_version={:?}:full_rotation=false",
        previous_commitment,
        state.current_public_key_commitment,
        state.key_version
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable)]`.
///
/// Rotates both the stateful bundle and the stateless half. Authorized by
/// the CURRENT key's stateless recovery signature over an `ACTION_ROTATE_FULL`
/// action, exactly like [`process_rotate_to_fresh_key`] -- see that
/// function's doc comment for the account-layout rationale.
pub(crate) fn process_rotate_full_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: RotateFullKeyArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    require_recovery_mode(&state)?;

    let current_public_key: PublicKey = args.current_public_key.into();
    let recovery_signature: StatelessSignature = args.recovery_signature.into();
    let stateless_key_changed = rotation::stateless_half_changed(
        &current_public_key,
        &args.next_pk_seed,
        &args.next_hypertree_root,
    );
    let auth = RotationAuthorization {
        state: &state,
        domain_separator: messages::domain_separator(program_id, account_info.key),
        current_public_key: &current_public_key,
        recovery_signature: &recovery_signature,
    };
    rotation::authorize_full_key_rotation(
        &auth,
        &args.next_stateful_public_key,
        args.next_pk_seed,
        args.next_hypertree_root,
        args.next_commitment,
    )?;

    let previous_commitment = state.current_public_key_commitment;
    install_rotated_key(&mut state, args.next_commitment, stateless_key_changed);
    msg!(
        "shrincs-account-event:KeyRotated:previous={:?}:next={:?}:key_version={:?}:full_rotation=true",
        previous_commitment,
        state.current_public_key_commitment,
        state.key_version
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (read-only)]`.
///
/// ERC-1271-style read-only query, ported from the deleted wasm host
/// wrapper's `isValidSignature` (`src/account/mod.rs` prior to its removal at
/// `d982d45~1`). Rebuilds the [`ActionContext`] from account STATE
/// (`state.nonce`/`state.key_version`) exactly like
/// [`process_verify_stateful_action`]/[`process_verify_stateless_action`] --
/// this is a point-in-time check against the CURRENT nonce: a signature that
/// verifies here answers "is this valid right now", not "will this still be
/// valid later" (an actual mutating action against the same nonce can still
/// be replayed afterward, and this query does nothing to prevent that).
///
/// Unlike the mutating action handlers, this never calls `store_state`: no
/// nonce bump, no leaf-policy check/commit, no stateless-budget consumption.
/// `set_return_data` carries the boolean answer and this always returns
/// `Ok(())` for a well-formed envelope, even when `is_valid` is `false` --
/// it is a query, not a mutation, so there is nothing to fail closed against.
/// A malformed envelope (undecodable `signature_bytes`, unknown `mode`) is
/// still a distinct `Err(ProgramError::InvalidInstructionData)`: that is a
/// caller/encoding bug, not a "no" answer to the query.
pub(crate) fn process_is_valid_signature(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: IsValidSignatureArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let state = load_state(account_info, program_id)?;
    let public_key: PublicKey = args.public_key.into();
    let domain_separator = messages::domain_separator(program_id, account_info.key);
    let context: ActionContext = messages::action_context(
        domain_separator,
        state.nonce,
        state.key_version,
        args.action_type,
        args.payload_hash,
    );

    let is_valid = match args.mode {
        MODE_STATEFUL_ACTION => {
            let signature: StatefulSignature =
                StatefulSignatureDto::try_from_slice(&args.signature_bytes)
                    .map_err(|_| ProgramError::InvalidInstructionData)?
                    .into();
            ShrincsVerifier::new().verify_stateful(
                state.current_public_key_commitment,
                &public_key,
                &context,
                &signature,
            )
        }
        MODE_STATELESS_ACTION => {
            let signature: StatelessSignature =
                StatelessSignatureDto::try_from_slice(&args.signature_bytes)
                    .map_err(|_| ProgramError::InvalidInstructionData)?
                    .into();
            ShrincsVerifier::new().verify_stateless(
                state.current_public_key_commitment,
                &public_key,
                &context,
                &signature,
            )
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    };

    set_return_data(&[is_valid as u8]);
    Ok(())
}

/// Accounts: `[account PDA (read-only), leaf-bitmap word PDA (read-only) for
/// `args.leaf_index`'s word]`.
///
/// Read-only bitmap query, ported from the deleted wasm host wrapper's
/// `isLeafUsed` (`src/account/mod.rs` prior to its removal at `d982d45~1`),
/// answering via `set_return_data` instead of a return value. No mutation:
/// unlike [`commit_stateful_leaf_use`]'s `mark_leaf_used` call, this never
/// creates the bitmap-word PDA on a miss -- [`is_leaf_used`] already treats
/// an uncreated word as "every leaf in it is unused" and returns `Ok(false)`
/// without touching the account.
pub(crate) fn process_is_leaf_used(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: IsLeafUsedArgs,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let bitmap_account = next_account_info(accounts_iter)?;

    let state = load_state(account_info, program_id)?;
    let used = is_leaf_used(
        program_id,
        account_info.key,
        &state.key_version,
        args.leaf_index,
        bitmap_account,
    )?;
    set_return_data(&[used as u8]);
    Ok(())
}

/// Top-level instruction enum for [`process_instruction`]: one variant per
/// handler in this module, Borsh-encoded by the caller and decoded here.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) enum ShrincsAccountInstruction {
    Init(InitArgs),
    VerifyStatefulAction(StatefulActionArgs),
    VerifyStatelessAction(StatelessActionArgs),
    SetPolicyMonotonic(SetPolicyMonotonicArgs),
    SetPolicyRecoveryRotation,
    SetPolicyLeafBitmap,
    EnterRecoveryMode,
    RotateToFreshKey(RotateToFreshKeyArgs),
    RotateFullKey(RotateFullKeyArgs),
    IsValidSignature(IsValidSignatureArgs),
    IsLeafUsed(IsLeafUsedArgs),
}

/// Crate entrypoint. Decodes a [`ShrincsAccountInstruction`] from
/// `instruction_data` and dispatches to the matching handler, threading
/// `accounts` through unchanged.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ShrincsAccountInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match instruction {
        ShrincsAccountInstruction::Init(args) => process_init(program_id, accounts, args),
        ShrincsAccountInstruction::VerifyStatefulAction(args) => {
            process_verify_stateful_action(program_id, accounts, args)
        }
        ShrincsAccountInstruction::VerifyStatelessAction(args) => {
            process_verify_stateless_action(program_id, accounts, args)
        }
        ShrincsAccountInstruction::SetPolicyMonotonic(args) => {
            process_set_policy_monotonic(program_id, accounts, args)
        }
        ShrincsAccountInstruction::SetPolicyRecoveryRotation => {
            process_set_policy_recovery_rotation(program_id, accounts)
        }
        ShrincsAccountInstruction::SetPolicyLeafBitmap => {
            process_set_policy_leaf_bitmap(program_id, accounts)
        }
        ShrincsAccountInstruction::EnterRecoveryMode => {
            process_enter_recovery_mode(program_id, accounts)
        }
        ShrincsAccountInstruction::RotateToFreshKey(args) => {
            process_rotate_to_fresh_key(program_id, accounts, args)
        }
        ShrincsAccountInstruction::RotateFullKey(args) => {
            process_rotate_full_key(program_id, accounts, args)
        }
        ShrincsAccountInstruction::IsValidSignature(args) => {
            process_is_valid_signature(program_id, accounts, args)
        }
        ShrincsAccountInstruction::IsLeafUsed(args) => {
            process_is_leaf_used(program_id, accounts, args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};
    use hashsigs_rs::shrincs::signer::ShrincsSigner;
    use hashsigs_rs::shrincs::verifier::ShrincsVerifier as CoreShrincsVerifier;
    use hashsigs_rs::shrincs::Keys;
    use solana_program_test::*;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey as SdkPubkey,
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
    };

    /// Test-only instruction tag + router: the real dispatch enum is a later
    /// task, so tests drive `process_init`/`process_verify_stateful_action`/
    /// `process_verify_stateless_action` through `solana-program-test`'s
    /// BanksClient (for real CPI/runtime behavior) via this local stand-in.
    #[derive(Clone, BorshSerialize, BorshDeserialize)]
    enum TestInstruction {
        Init(InitArgs),
        StatefulAction(StatefulActionArgs),
        StatelessAction(StatelessActionArgs),
        SetPolicyMonotonic(SetPolicyMonotonicArgs),
        SetPolicyRecoveryRotation,
        SetPolicyLeafBitmap,
        EnterRecoveryMode,
        RotateToFreshKey(RotateToFreshKeyArgs),
        RotateFullKey(RotateFullKeyArgs),
        IsValidSignature(IsValidSignatureArgs),
        IsLeafUsed(IsLeafUsedArgs),
    }

    fn test_dispatch(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        let instruction = TestInstruction::try_from_slice(data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        match instruction {
            TestInstruction::Init(args) => process_init(program_id, accounts, args),
            TestInstruction::StatefulAction(args) => {
                process_verify_stateful_action(program_id, accounts, args)
            }
            TestInstruction::StatelessAction(args) => {
                process_verify_stateless_action(program_id, accounts, args)
            }
            TestInstruction::SetPolicyMonotonic(args) => {
                process_set_policy_monotonic(program_id, accounts, args)
            }
            TestInstruction::SetPolicyRecoveryRotation => {
                process_set_policy_recovery_rotation(program_id, accounts)
            }
            TestInstruction::SetPolicyLeafBitmap => {
                process_set_policy_leaf_bitmap(program_id, accounts)
            }
            TestInstruction::EnterRecoveryMode => process_enter_recovery_mode(program_id, accounts),
            TestInstruction::RotateToFreshKey(args) => {
                process_rotate_to_fresh_key(program_id, accounts, args)
            }
            TestInstruction::RotateFullKey(args) => {
                process_rotate_full_key(program_id, accounts, args)
            }
            TestInstruction::IsValidSignature(args) => {
                process_is_valid_signature(program_id, accounts, args)
            }
            TestInstruction::IsLeafUsed(args) => process_is_leaf_used(program_id, accounts, args),
        }
    }

    async fn setup_test() -> (ProgramTest, Keypair) {
        let program_id = Keypair::new();
        let mut program_test = ProgramTest::new(
            "shrincs_account_example",
            program_id.pubkey(),
            processor!(test_dispatch),
        );
        program_test.set_compute_max_units(1_400_000);
        (program_test, program_id)
    }

    async fn init_account(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        owner: &Keypair,
        salt: [u8; HASH_LEN],
        initial_commitment: [u8; HASH_LEN],
    ) -> SdkPubkey {
        let (account_pda_key, _bump) = account_pda(program_id, &owner.pubkey(), &salt);

        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(owner.pubkey(), true),
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::Init(InitArgs {
                    salt,
                    initial_commitment,
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("init should succeed");
        account_pda_key
    }

    async fn fetch_state(
        context: &mut ProgramTestContext,
        account_pda_key: &SdkPubkey,
    ) -> ShrincsAccountState {
        let account = context
            .banks_client
            .get_account(*account_pda_key)
            .await
            .unwrap()
            .expect("account exists");
        ShrincsAccountState::try_from_slice(&account.data).expect("valid state")
    }

    /// Build an owner-gated policy/recovery instruction: every handler in
    /// this task shares the `[account PDA (writable), owner (signer)]`
    /// account layout.
    fn policy_instruction(
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        owner_pubkey: &SdkPubkey,
        instruction: TestInstruction,
    ) -> Instruction {
        Instruction {
            program_id: *program_id,
            accounts: vec![
                AccountMeta::new(*account_pda_key, false),
                AccountMeta::new_readonly(*owner_pubkey, true),
            ],
            data: borsh::to_vec(&instruction).unwrap(),
        }
    }

    /// Assert the transaction aborted with the given [`ShrincsAccountError`]
    /// custom code.
    fn assert_custom_error(
        result: &Result<(), solana_sdk::transaction::TransactionError>,
        expected: ShrincsAccountError,
    ) {
        match result {
            Err(solana_sdk::transaction::TransactionError::InstructionError(
                _,
                solana_sdk::instruction::InstructionError::Custom(code),
            )) => {
                assert_eq!(*code, expected as u32, "unexpected custom error code");
            }
            other => panic!("expected custom error {:?}, got {other:?}", expected as u32),
        }
    }

    /// Assert the transaction aborted because a required signer was absent.
    fn assert_missing_signature(result: &Result<(), solana_sdk::transaction::TransactionError>) {
        match result {
            Err(solana_sdk::transaction::TransactionError::InstructionError(
                _,
                solana_sdk::instruction::InstructionError::MissingRequiredSignature,
            )) => {}
            other => panic!("expected MissingRequiredSignature, got {other:?}"),
        }
    }

    /// Drive one successful stateful action to flip `stateful_policy_frozen`,
    /// mirroring `stateful_action_valid_signature_advances_state`'s flow.
    async fn freeze_stateful_policy(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        keys: &mut Keys,
        public_key: &PublicKey,
    ) {
        let domain_separator = messages::domain_separator(program_id, account_pda_key);
        let action_type = messages::ACTION_STATEFUL;
        let payload_hash = messages::action_payload(&action_type, b"freeze policy payload");
        let context_msg = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash,
        );
        let signature =
            ShrincsSigner::sign_stateful_action(keys, public_key, &context_msg).expect("sign");

        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(program_id, account_pda_key, &[0u8; HASH_LEN], 0);
        let instruction = Instruction {
            program_id: *program_id,
            accounts: vec![
                AccountMeta::new(*account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.clone().into(),
                    action_type,
                    payload_hash,
                    signature: signature.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("freezing stateful action should succeed");
    }

    #[tokio::test]
    async fn stateful_action_valid_signature_advances_state() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [7u8; HASH_LEN];

        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test stateful", 1024).expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");

        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATEFUL;
        let payload_hash = messages::action_payload(&action_type, b"stateful action payload");
        let context_msg = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN], // fresh account: nonce starts zeroed
            [0u8; HASH_LEN], // fresh account: key_version starts zeroed
            action_type,
            payload_hash,
        );
        let signature = ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &context_msg)
            .expect("sign");
        assert_eq!(
            signature.auth_path.len(),
            1,
            "first stateful signature uses leaf 1"
        );

        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(&program_id, &account_pda_key, &[0u8; HASH_LEN], 0);
        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.clone().into(),
                    action_type,
                    payload_hash,
                    signature: signature.clone().into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert!(
            result.result.is_ok(),
            "valid stateful action should succeed: {:?}",
            result.result
        );
        assert_eq!(result.metadata.unwrap().return_data.unwrap().data, vec![1]);

        let state = fetch_state(&mut context, &account_pda_key).await;
        let mut expected_nonce = [0u8; HASH_LEN];
        expected_nonce[HASH_LEN - 1] = 1;
        assert_eq!(state.nonce, expected_nonce, "nonce advances by one");
        assert_eq!(
            state.next_stateful_leaf_index, 2,
            "MonotonicIndex advances past leaf 1"
        );
        assert!(state.stateful_policy_frozen);
    }

    #[tokio::test]
    async fn stateful_action_tampered_signature_rejected() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [9u8; HASH_LEN];

        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test tampered", 1024).expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATEFUL;
        let payload_hash = messages::action_payload(&action_type, b"tampered action payload");
        let context_msg = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash,
        );
        let mut signature =
            ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &context_msg)
                .expect("sign");
        signature.randomizer[0] ^= 0x01; // tamper one byte

        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(&program_id, &account_pda_key, &[0u8; HASH_LEN], 0);
        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.into(),
                    action_type,
                    payload_hash,
                    signature: signature.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert!(
            result.result.is_err(),
            "tampered signature must abort the instruction"
        );
        let return_data = result
            .metadata
            .expect("metadata present even on failure")
            .return_data
            .expect("return data set before the fail-closed abort");
        assert_eq!(return_data.data, vec![0]);
    }

    #[tokio::test]
    async fn stateful_action_monotonic_reuse_rejected() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [3u8; HASH_LEN];

        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test reuse", 1024).expect("keygen");
        let keys_replay = keys.clone(); // independent signer, still at leaf 1
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        let action_type = messages::ACTION_STATEFUL;
        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(&program_id, &account_pda_key, &[0u8; HASH_LEN], 0);

        // First action: consumes leaf 1, advances next_stateful_leaf_index to 2.
        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let payload_hash_1 = messages::action_payload(&action_type, b"first action");
        let context_1 = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash_1,
        );
        let signature_1 =
            ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &context_1).expect("sign");
        let instruction_1 = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.clone().into(),
                    action_type,
                    payload_hash: payload_hash_1,
                    signature: signature_1.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction_1 = Transaction::new_signed_with_payer(
            &[instruction_1],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction_1)
            .await
            .unwrap()
            .result
            .expect("first stateful action should succeed");

        // Second action: a freshly, validly signed leaf-1 signature from the
        // independent `keys_replay` clone. The leaf-policy gate must reject
        // this because leaf 1 has already been consumed -- MonotonicIndex now
        // expects leaf 2 -- regardless of the signature's own validity.
        let mut keys_replay = keys_replay;
        let payload_hash_2 = messages::action_payload(&action_type, b"replay action");
        let context_2 = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash_2,
        );
        let signature_2 =
            ShrincsSigner::sign_stateful_action(&mut keys_replay, &public_key, &context_2)
                .expect("sign");
        assert_eq!(signature_2.auth_path.len(), 1, "replay reuses leaf 1");

        context.last_blockhash = context.banks_client.get_latest_blockhash().await.unwrap();
        let instruction_2 = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.into(),
                    action_type,
                    payload_hash: payload_hash_2,
                    signature: signature_2.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction_2 = Transaction::new_signed_with_payer(
            &[instruction_2],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction_2)
            .await
            .unwrap();
        assert!(
            result.result.is_err(),
            "reusing leaf 1 must be rejected under MonotonicIndex"
        );
    }

    #[tokio::test]
    async fn stateless_action_valid_signature_advances_state() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [11u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test stateless", 1024).expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATELESS;
        let payload_hash = messages::action_payload(&action_type, b"stateless action payload");
        let context_msg = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash,
        );
        // verify_stateless computes its own action-message-hash from the
        // ActionContext, same as the stateful path; sign that same hash.
        let message =
            CoreShrincsVerifier::new().stateless_action_message_hash(commitment, &context_msg);
        let signature = ShrincsSigner::sign_stateless_raw(&keys, &message).expect("sign");

        let instruction = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(account_pda_key, false)],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatelessAction(StatelessActionArgs {
                    public_key: public_key.into(),
                    action_type,
                    payload_hash,
                    signature: signature.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert!(
            result.result.is_ok(),
            "valid stateless action should succeed: {:?}",
            result.result
        );
        assert_eq!(result.metadata.unwrap().return_data.unwrap().data, vec![1]);

        let state = fetch_state(&mut context, &account_pda_key).await;
        let mut expected_nonce = [0u8; HASH_LEN];
        expected_nonce[HASH_LEN - 1] = 1;
        assert_eq!(state.nonce, expected_nonce, "nonce advances by one");
        assert_eq!(state.stateless_signatures_used, 1);
    }

    #[tokio::test]
    async fn policy_setters_reject_wrong_owner_or_missing_signer() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let attacker = Keypair::new();
        let salt = [21u8; HASH_LEN];

        let (_keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test policy owner-gate", 1024)
                .expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        let setters: Vec<TestInstruction> = vec![
            TestInstruction::SetPolicyMonotonic(SetPolicyMonotonicArgs {
                initial_leaf_index: 1,
            }),
            TestInstruction::SetPolicyRecoveryRotation,
            TestInstruction::SetPolicyLeafBitmap,
            TestInstruction::EnterRecoveryMode,
        ];

        for setter in setters {
            // Wrong owner: `attacker` genuinely signs, but does not match `state.owner`.
            context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
            let instruction = policy_instruction(
                &program_id,
                &account_pda_key,
                &attacker.pubkey(),
                setter.clone(),
            );
            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&context.payer.pubkey()),
                &[&context.payer, &attacker],
                context.last_blockhash,
            );
            let result = context
                .banks_client
                .process_transaction_with_metadata(transaction)
                .await
                .unwrap();
            assert_custom_error(&result.result, ShrincsAccountError::OnlyOwner);

            // Missing signer: the instruction marks `owner` non-signer and the
            // transaction never signs with it.
            context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
            let instruction = Instruction {
                program_id,
                accounts: vec![
                    AccountMeta::new(account_pda_key, false),
                    AccountMeta::new_readonly(owner.pubkey(), false),
                ],
                data: borsh::to_vec(&setter).unwrap(),
            };
            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&context.payer.pubkey()),
                &[&context.payer],
                context.last_blockhash,
            );
            let result = context
                .banks_client
                .process_transaction_with_metadata(transaction)
                .await
                .unwrap();
            assert_missing_signature(&result.result);
        }
    }

    #[tokio::test]
    async fn policy_frozen_blocks_monotonic_and_bitmap_but_not_recovery_rotation() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [22u8; HASH_LEN];

        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test freeze exemption", 1024)
                .expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        freeze_stateful_policy(
            &mut context,
            &program_id,
            &account_pda_key,
            &mut keys,
            &public_key,
        )
        .await;
        let frozen_state = fetch_state(&mut context, &account_pda_key).await;
        assert!(
            frozen_state.stateful_policy_frozen,
            "one stateful use must freeze the policy"
        );

        // Blocked while frozen: MonotonicIndex.
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyMonotonic(SetPolicyMonotonicArgs {
                initial_leaf_index: 5,
            }),
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert_custom_error(&result.result, ShrincsAccountError::StatefulPolicyFrozen);

        // Blocked while frozen: LeafBitmap.
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyLeafBitmap,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert_custom_error(&result.result, ShrincsAccountError::StatefulPolicyFrozen);

        // The divergence under test: RecoveryRotation is exempt from the freeze
        // check (see docs/solidity-parity.md, "Recovery-rotation freeze
        // exemption (audit F1)").
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyRecoveryRotation,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("set_policy_recovery_rotation is exempt from the freeze check");

        let state = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(
            state.stateful_policy,
            StatefulPolicy::RecoveryRotation as u8
        );
        assert!(
            state.stateful_policy_frozen,
            "the freeze flag itself is untouched by this setter"
        );
    }

    #[tokio::test]
    async fn set_policy_monotonic_rejects_rollback_below_cursor() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [23u8; HASH_LEN];

        let (_keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rollback", 1024).expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        // Advance the cursor to 5.
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyMonotonic(SetPolicyMonotonicArgs {
                initial_leaf_index: 5,
            }),
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("advancing the cursor forward should succeed");
        let state = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(state.next_stateful_leaf_index, 5);

        // Rolling back below 5 must be rejected, and must not mutate state.
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyMonotonic(SetPolicyMonotonicArgs {
                initial_leaf_index: 3,
            }),
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert_custom_error(&result.result, ShrincsAccountError::StatefulIndexRollback);

        let state = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(
            state.next_stateful_leaf_index, 5,
            "rejected rollback must not mutate the cursor"
        );
    }

    #[tokio::test]
    async fn enter_recovery_mode_requires_recovery_rotation_policy() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [24u8; HASH_LEN];

        let (_keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test enter recovery", 1024)
                .expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        // Default policy is MonotonicIndex: entering recovery must fail.
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::EnterRecoveryMode,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert_custom_error(&result.result, ShrincsAccountError::RecoveryPolicyRequired);

        // Switch to RecoveryRotation, then entering recovery must succeed.
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyRecoveryRotation,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("set_policy_recovery_rotation should succeed");

        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::EnterRecoveryMode,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("enter_recovery_mode should succeed once RecoveryRotation is active");

        let state = fetch_state(&mut context, &account_pda_key).await;
        assert!(
            state.recovery_mode,
            "recovery_mode must be armed after enter_recovery_mode"
        );
    }

    // --- rotation (Task 6) --------------------------------------------------

    fn fixed_hash_bytes(bytes: &[u8]) -> [u8; HASH_LEN] {
        bytes.try_into().expect("expected a 32-byte field")
    }

    fn fixed_stateful_key_bytes(bytes: &[u8]) -> [u8; STATEFUL_PUBLIC_KEY_BYTES] {
        bytes
            .try_into()
            .expect("expected a 68-byte stateful public key")
    }

    /// Switch to `RecoveryRotation` policy and arm recovery mode -- the
    /// shared precondition every rotation test needs.
    async fn arm_recovery(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        owner: &Keypair,
    ) {
        for instruction_kind in [
            TestInstruction::SetPolicyRecoveryRotation,
            TestInstruction::EnterRecoveryMode,
        ] {
            context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
            let instruction = policy_instruction(
                program_id,
                account_pda_key,
                &owner.pubkey(),
                instruction_kind,
            );
            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&context.payer.pubkey()),
                &[&context.payer, owner],
                context.last_blockhash,
            );
            context
                .banks_client
                .process_transaction_with_metadata(transaction)
                .await
                .unwrap()
                .result
                .expect("arming recovery mode should succeed");
        }
    }

    /// Submit `instruction` against the single-account `[account PDA
    /// (writable)]` layout shared by the stateless-action and rotation
    /// handlers, returning the on-chain result.
    async fn send_single_account(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        instruction: TestInstruction,
    ) -> Result<(), solana_sdk::transaction::TransactionError> {
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let ix = Instruction {
            program_id: *program_id,
            accounts: vec![AccountMeta::new(*account_pda_key, false)],
            data: borsh::to_vec(&instruction).unwrap(),
        };
        let transaction = Transaction::new_signed_with_payer(
            &[ix],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
    }

    /// Attempt an ordinary `StatelessAction` signed by `keys`/`public_key`,
    /// hashing the action message against `message_commitment`. Reused by
    /// the rotation tests to check both "the old key/commitment no longer
    /// works" and "the new key's action verifies" after a rotation.
    async fn try_stateless_action(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        keys: &Keys,
        public_key: &PublicKey,
        message_commitment: [u8; HASH_LEN],
    ) -> Result<(), solana_sdk::transaction::TransactionError> {
        let state = fetch_state(context, account_pda_key).await;
        let domain_separator = messages::domain_separator(program_id, account_pda_key);
        let action_type = messages::ACTION_STATELESS;
        let payload_hash = messages::action_payload(&action_type, b"post-rotation probe");
        let action_context = messages::action_context(
            domain_separator,
            state.nonce,
            state.key_version,
            action_type,
            payload_hash,
        );
        let message = CoreShrincsVerifier::new()
            .stateless_action_message_hash(message_commitment, &action_context);
        let signature = ShrincsSigner::sign_stateless_raw(keys, &message).expect("sign");
        let args = StatelessActionArgs {
            public_key: public_key.clone().into(),
            action_type,
            payload_hash,
            signature: signature.into(),
        };
        send_single_account(
            context,
            program_id,
            account_pda_key,
            TestInstruction::StatelessAction(args),
        )
        .await
    }

    /// Build a fresh-key rotation's args, keeping the CURRENT stateless half
    /// (`public_key.pk_seed`/`hypertree_root`) for the next commitment, and
    /// assert the embedded recovery signature verifies against `state`
    /// before returning it -- confirming the produced signature is genuinely
    /// valid, not just structurally well-formed, before any test asserts the
    /// rotation itself succeeds.
    fn build_fresh_key_rotation_args(
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        state: &ShrincsAccountState,
        keys: &Keys,
        public_key: &PublicKey,
    ) -> RotateToFreshKeyArgs {
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let current_pk_seed = fixed_hash_bytes(&public_key.pk_seed);
        let current_hypertree_root = fixed_hash_bytes(&public_key.hypertree_root);
        let (_next_keys, next_public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate fresh next", 1024)
                .expect("keygen");
        let next_stateful_public_key =
            fixed_stateful_key_bytes(&next_public_key.stateful_public_key);
        let next_commitment = CoreShrincsVerifier::new().public_key_commitment(
            &next_stateful_public_key,
            current_pk_seed,
            current_hypertree_root,
        );

        let domain_separator = messages::domain_separator(program_id, account_pda_key);
        let payload_hash =
            messages::rotate_stateful_payload(&next_stateful_public_key, &next_commitment);
        let action_context = messages::action_context(
            domain_separator,
            state.nonce,
            state.key_version,
            messages::ACTION_ROTATE_STATEFUL,
            payload_hash,
        );
        let message =
            CoreShrincsVerifier::new().stateless_action_message_hash(commitment, &action_context);
        let recovery_signature = ShrincsSigner::sign_stateless_raw(keys, &message).expect("sign");
        assert!(
            CoreShrincsVerifier::new().verify_stateless(
                commitment,
                public_key,
                &action_context,
                &recovery_signature
            ),
            "recovery signature must verify before submitting the rotation"
        );

        RotateToFreshKeyArgs {
            current_public_key: public_key.clone().into(),
            next_stateful_public_key,
            next_commitment,
            recovery_signature: recovery_signature.into(),
        }
    }

    /// Build a full rotation's args with a completely fresh stateless half,
    /// asserting the embedded recovery signature verifies before returning
    /// it (see [`build_fresh_key_rotation_args`]'s doc comment).
    fn build_full_key_rotation_args(
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        state: &ShrincsAccountState,
        keys: &Keys,
        public_key: &PublicKey,
    ) -> RotateFullKeyArgs {
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let (_next_keys, next_public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate full next", 1024)
                .expect("keygen");
        let next_stateful_public_key =
            fixed_stateful_key_bytes(&next_public_key.stateful_public_key);
        let next_pk_seed = fixed_hash_bytes(&next_public_key.pk_seed);
        let next_hypertree_root = fixed_hash_bytes(&next_public_key.hypertree_root);
        let next_commitment = CoreShrincsVerifier::new().public_key_commitment(
            &next_stateful_public_key,
            next_pk_seed,
            next_hypertree_root,
        );

        let domain_separator = messages::domain_separator(program_id, account_pda_key);
        let payload_hash = messages::rotate_full_payload(
            &next_stateful_public_key,
            &next_pk_seed,
            &next_hypertree_root,
            &next_commitment,
        );
        let action_context = messages::action_context(
            domain_separator,
            state.nonce,
            state.key_version,
            messages::ACTION_ROTATE_FULL,
            payload_hash,
        );
        let message =
            CoreShrincsVerifier::new().stateless_action_message_hash(commitment, &action_context);
        let recovery_signature = ShrincsSigner::sign_stateless_raw(keys, &message).expect("sign");
        assert!(
            CoreShrincsVerifier::new().verify_stateless(
                commitment,
                public_key,
                &action_context,
                &recovery_signature
            ),
            "recovery signature must verify before submitting the rotation"
        );

        RotateFullKeyArgs {
            current_public_key: public_key.clone().into(),
            next_stateful_public_key,
            next_pk_seed,
            next_hypertree_root,
            next_commitment,
            recovery_signature: recovery_signature.into(),
        }
    }

    #[tokio::test]
    async fn rotate_to_fresh_key_with_valid_recovery_signature_succeeds() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [31u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate fresh", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        arm_recovery(&mut context, &program_id, &account_pda_key, &owner).await;

        // Consume one stateless action first so `stateless_signatures_used` is
        // non-zero going into the rotation; otherwise asserting it stays 0
        // afterward cannot distinguish "preserved" from "reset to 0".
        try_stateless_action(
            &mut context,
            &program_id,
            &account_pda_key,
            &keys,
            &public_key,
            commitment,
        )
        .await
        .expect("a stateless action under armed recovery should succeed");

        let state_before = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(
            state_before.stateless_signatures_used, 1,
            "setup consumed one stateless signature"
        );
        let args = build_fresh_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state_before,
            &keys,
            &public_key,
        );
        let next_commitment = args.next_commitment;
        let next_stateful_public_key = args.next_stateful_public_key;

        send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateToFreshKey(args),
        )
        .await
        .expect("valid fresh-key rotation should succeed");

        let state = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(state.current_public_key_commitment, next_commitment);
        let mut expected_key_version = state_before.key_version;
        increment_u256_be(&mut expected_key_version);
        assert_eq!(
            state.key_version, expected_key_version,
            "key_version advances by one"
        );
        assert_eq!(
            state.stateless_signatures_used, state_before.stateless_signatures_used,
            "fresh-key rotation preserves stateless usage (kept at 1, not reset to 0)"
        );
        assert_eq!(state.next_stateful_leaf_index, 1);
        assert_eq!(state.stateful_policy, StatefulPolicy::MonotonicIndex as u8);
        assert!(!state.stateful_policy_frozen);
        assert!(!state.recovery_mode);
        assert_ne!(
            state.nonce, state_before.nonce,
            "nonce advances on rotation"
        );

        let old_result = try_stateless_action(
            &mut context,
            &program_id,
            &account_pda_key,
            &keys,
            &public_key,
            commitment,
        )
        .await;
        assert!(
            old_result.is_err(),
            "the old key/commitment must be rejected after rotation"
        );

        let new_public_key = PublicKey {
            stateful_public_key: next_stateful_public_key.to_vec(),
            public_key_commitment: next_commitment.to_vec(),
            pk_seed: public_key.pk_seed.clone(),
            hypertree_root: public_key.hypertree_root.clone(),
        };
        try_stateless_action(
            &mut context,
            &program_id,
            &account_pda_key,
            &keys,
            &new_public_key,
            next_commitment,
        )
        .await
        .expect("the new key's action should verify after rotation");
    }

    #[tokio::test]
    async fn rotate_full_key_with_fresh_stateless_half_resets_budget() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [32u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate full", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        arm_recovery(&mut context, &program_id, &account_pda_key, &owner).await;

        let state_before = fetch_state(&mut context, &account_pda_key).await;
        let args = build_full_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state_before,
            &keys,
            &public_key,
        );
        let next_commitment = args.next_commitment;

        send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateFullKey(args),
        )
        .await
        .expect("valid full-key rotation should succeed");

        let state = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(state.current_public_key_commitment, next_commitment);
        assert_eq!(
            state.stateless_signatures_used, 0,
            "fresh stateless half resets usage accounting"
        );
        let mut expected_key_version = state_before.key_version;
        increment_u256_be(&mut expected_key_version);
        assert_eq!(state.key_version, expected_key_version);
        assert!(!state.recovery_mode);
    }

    #[tokio::test]
    async fn rotate_rejected_when_not_in_recovery_mode() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [33u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate not armed", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        // Switch to RecoveryRotation but do NOT enter recovery mode: the
        // "not in recovery mode" gate, not the "wrong policy" gate.
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyRecoveryRotation,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("set_policy_recovery_rotation should succeed");

        let state = fetch_state(&mut context, &account_pda_key).await;
        let args = build_fresh_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state,
            &keys,
            &public_key,
        );
        let result = send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateToFreshKey(args),
        )
        .await;
        assert_custom_error(&result, ShrincsAccountError::RecoveryNotArmed);
    }

    #[tokio::test]
    async fn rotate_rejected_when_next_stateful_key_has_zero_max_signatures() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [34u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate zero max sig", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        arm_recovery(&mut context, &program_id, &account_pda_key, &owner).await;

        let state = fetch_state(&mut context, &account_pda_key).await;
        let mut args = build_fresh_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state,
            &keys,
            &public_key,
        );
        args.next_stateful_public_key[64..68].copy_from_slice(&0u32.to_be_bytes());

        let result = send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateToFreshKey(args),
        )
        .await;
        assert_custom_error(&result, ShrincsAccountError::RotationTargetInvalid);
    }

    #[tokio::test]
    async fn rotate_rejected_when_next_commitment_mismatches() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [35u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate bad commitment", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        arm_recovery(&mut context, &program_id, &account_pda_key, &owner).await;

        let state = fetch_state(&mut context, &account_pda_key).await;
        let mut args = build_fresh_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state,
            &keys,
            &public_key,
        );
        args.next_commitment[0] ^= 0x01;

        let result = send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateToFreshKey(args),
        )
        .await;
        assert_custom_error(&result, ShrincsAccountError::CommitmentMismatch);
    }

    #[tokio::test]
    async fn rotate_rejected_when_recovery_signature_is_from_wrong_key() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [36u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate wrong key", 1024)
                .expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        arm_recovery(&mut context, &program_id, &account_pda_key, &owner).await;

        let (wrong_keys, _wrong_public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test rotate wrong signer", 1024)
                .expect("keygen");

        let state = fetch_state(&mut context, &account_pda_key).await;
        let mut args = build_fresh_key_rotation_args(
            &program_id,
            &account_pda_key,
            &state,
            &keys,
            &public_key,
        );

        // Re-sign the SAME context/payload with the WRONG key's stateless half.
        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let payload_hash = messages::rotate_stateful_payload(
            &args.next_stateful_public_key,
            &args.next_commitment,
        );
        let action_context = messages::action_context(
            domain_separator,
            state.nonce,
            state.key_version,
            messages::ACTION_ROTATE_STATEFUL,
            payload_hash,
        );
        let message =
            CoreShrincsVerifier::new().stateless_action_message_hash(commitment, &action_context);
        let wrong_signature =
            ShrincsSigner::sign_stateless_raw(&wrong_keys, &message).expect("sign");
        assert!(
            !CoreShrincsVerifier::new().verify_stateless(
                commitment,
                &public_key,
                &action_context,
                &wrong_signature
            ),
            "a wrong-key signature must not verify"
        );
        args.recovery_signature = wrong_signature.into();

        let result = send_single_account(
            &mut context,
            &program_id,
            &account_pda_key,
            TestInstruction::RotateToFreshKey(args),
        )
        .await;
        assert_custom_error(&result, ShrincsAccountError::InvalidSignature);
    }

    // --- read-only queries (Task 7) -----------------------------------------

    /// Submit a [`TestInstruction::IsValidSignature`] query against the
    /// single read-only `[account PDA]` layout and return its return data.
    async fn query_is_valid_signature(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        args: IsValidSignatureArgs,
    ) -> Vec<u8> {
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let ix = Instruction {
            program_id: *program_id,
            accounts: vec![AccountMeta::new_readonly(*account_pda_key, false)],
            data: borsh::to_vec(&TestInstruction::IsValidSignature(args)).unwrap(),
        };
        let transaction = Transaction::new_signed_with_payer(
            &[ix],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        result
            .result
            .expect("is_valid_signature query should succeed");
        result
            .metadata
            .expect("metadata present")
            .return_data
            .expect("return data set")
            .data
    }

    /// Submit a [`TestInstruction::IsLeafUsed`] query against the read-only
    /// `[account PDA, leaf-bitmap word PDA]` layout and return its return data.
    async fn query_is_leaf_used(
        context: &mut ProgramTestContext,
        program_id: &SdkPubkey,
        account_pda_key: &SdkPubkey,
        bitmap_key: &SdkPubkey,
        leaf_index: u32,
    ) -> Vec<u8> {
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let ix = Instruction {
            program_id: *program_id,
            accounts: vec![
                AccountMeta::new_readonly(*account_pda_key, false),
                AccountMeta::new_readonly(*bitmap_key, false),
            ],
            data: borsh::to_vec(&TestInstruction::IsLeafUsed(IsLeafUsedArgs { leaf_index }))
                .unwrap(),
        };
        let transaction = Transaction::new_signed_with_payer(
            &[ix],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        result.result.expect("is_leaf_used query should succeed");
        result
            .metadata
            .expect("metadata present")
            .return_data
            .expect("return data set")
            .data
    }

    #[tokio::test]
    async fn is_valid_signature_verifies_without_mutating_state() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [41u8; HASH_LEN];

        let (keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test is_valid_signature", 1024)
                .expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;
        let state_before = fetch_state(&mut context, &account_pda_key).await;

        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATELESS;
        let payload_hash =
            messages::action_payload(&action_type, b"is_valid_signature query payload");
        let action_context = messages::action_context(
            domain_separator,
            state_before.nonce,
            state_before.key_version,
            action_type,
            payload_hash,
        );
        let message =
            CoreShrincsVerifier::new().stateless_action_message_hash(commitment, &action_context);
        let signature = ShrincsSigner::sign_stateless_raw(&keys, &message).expect("sign");

        // A signature that currently verifies against `state.nonce`/`state.key_version` reads `[1]`.
        let valid_args = IsValidSignatureArgs {
            mode: MODE_STATELESS_ACTION,
            public_key: public_key.clone().into(),
            action_type,
            payload_hash,
            signature_bytes: borsh::to_vec(&StatelessSignatureDto::from(signature.clone()))
                .unwrap(),
        };
        let return_data =
            query_is_valid_signature(&mut context, &program_id, &account_pda_key, valid_args).await;
        assert_eq!(
            return_data,
            vec![1],
            "current valid signature must read as valid"
        );
        assert_eq!(
            fetch_state(&mut context, &account_pda_key).await,
            state_before,
            "a valid query must not mutate nonce, key_version, or any other state field"
        );

        // A tampered signature over the same context reads `[0]`, not an aborted transaction.
        let mut tampered_signature = signature;
        tampered_signature.fors.randomizer[0] ^= 0x01;
        let tampered_args = IsValidSignatureArgs {
            mode: MODE_STATELESS_ACTION,
            public_key: public_key.into(),
            action_type,
            payload_hash,
            signature_bytes: borsh::to_vec(&StatelessSignatureDto::from(tampered_signature))
                .unwrap(),
        };
        let return_data =
            query_is_valid_signature(&mut context, &program_id, &account_pda_key, tampered_args)
                .await;
        assert_eq!(
            return_data,
            vec![0],
            "tampered signature must read as invalid, not abort the instruction"
        );
        assert_eq!(
            fetch_state(&mut context, &account_pda_key).await,
            state_before,
            "an invalid query must not mutate state either -- it is Ok(()) with is_valid = false"
        );
    }

    #[tokio::test]
    async fn is_leaf_used_reflects_bitmap_policy_consumption() {
        let (program_test, program_id) = setup_test().await;
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [42u8; HASH_LEN];

        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example test is_leaf_used", 1024)
                .expect("keygen");
        let commitment: [u8; HASH_LEN] = public_key
            .public_key_commitment
            .clone()
            .try_into()
            .expect("commitment is 32 bytes");
        let account_pda_key =
            init_account(&mut context, &program_id, &owner, salt, commitment).await;

        // Switch to LeafBitmap before any stateful use (the policy is not frozen yet).
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = policy_instruction(
            &program_id,
            &account_pda_key,
            &owner.pubkey(),
            TestInstruction::SetPolicyLeafBitmap,
        );
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("set_policy_leaf_bitmap should succeed");

        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(&program_id, &account_pda_key, &[0u8; HASH_LEN], 0);

        // Leaf 1 reads unused before any stateful action consumes it.
        let return_data =
            query_is_leaf_used(&mut context, &program_id, &account_pda_key, &bitmap_key, 1).await;
        assert_eq!(
            return_data,
            vec![0],
            "leaf 1 must read unused before any stateful action"
        );

        // Consume leaf 1 via an ordinary stateful action under LeafBitmap policy.
        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATEFUL;
        let payload_hash =
            messages::action_payload(&action_type, b"consume leaf 1 under bitmap policy");
        let action_context = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash,
        );
        let signature =
            ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &action_context)
                .expect("sign");
        assert_eq!(
            signature.auth_path.len(),
            1,
            "first stateful signature uses leaf 1"
        );

        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: {
                let mut data = Vec::new();
                TestInstruction::StatefulAction(StatefulActionArgs {
                    public_key: public_key.into(),
                    action_type,
                    payload_hash,
                    signature: signature.into(),
                })
                .serialize(&mut data)
                .unwrap();
                data
            },
        };
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("stateful action under LeafBitmap policy should succeed");

        // Leaf 1 now reads used; leaf 2 (same bitmap word) still reads unused.
        let return_data =
            query_is_leaf_used(&mut context, &program_id, &account_pda_key, &bitmap_key, 1).await;
        assert_eq!(
            return_data,
            vec![1],
            "leaf 1 must read used after the stateful action consumes it"
        );

        let return_data =
            query_is_leaf_used(&mut context, &program_id, &account_pda_key, &bitmap_key, 2).await;
        assert_eq!(
            return_data,
            vec![0],
            "leaf 2 (same bitmap word) must remain unused"
        );
    }

    // --- end-to-end through the real router (Task 8) ------------------------

    /// Full account lifecycle submitted as real [`ShrincsAccountInstruction`]-
    /// encoded instructions through the real [`process_instruction`] router
    /// (not the test-only `test_dispatch` stand-in above): init -> a stateful
    /// action at leaf 1 -> switch to `RecoveryRotation` -> arm recovery mode
    /// -> a full-key rotation authorized by the current key's stateless
    /// recovery signature -> a stateful action under the NEW key at leaf 1 of
    /// the new epoch succeeds, and an ordinary action still carrying the OLD
    /// commitment/key fails.
    #[tokio::test]
    async fn end_to_end_flow_through_real_router() {
        let program_id = Keypair::new();
        let mut program_test = ProgramTest::new(
            "shrincs_account_example",
            program_id.pubkey(),
            processor!(process_instruction),
        );
        program_test.set_compute_max_units(1_400_000);
        let mut context = program_test.start_with_context().await;
        let program_id = program_id.pubkey();
        let owner = Keypair::new();
        let salt = [200u8; HASH_LEN];

        // --- init -------------------------------------------------------
        let (mut keys, public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example e2e router", 1024).expect("keygen");
        let commitment = fixed_hash_bytes(&public_key.public_key_commitment);
        let (account_pda_key, _bump) = account_pda(&program_id, &owner.pubkey(), &salt);

        let init_instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(owner.pubkey(), true),
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: borsh::to_vec(&ShrincsAccountInstruction::Init(InitArgs {
                salt,
                initial_commitment: commitment,
            }))
            .unwrap(),
        };
        let transaction = Transaction::new_signed_with_payer(
            &[init_instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer, &owner],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("init should succeed");

        // --- stateful action at leaf 1 -----------------------------------
        let domain_separator = messages::domain_separator(&program_id, &account_pda_key);
        let action_type = messages::ACTION_STATEFUL;
        let payload_hash = messages::action_payload(&action_type, b"e2e router stateful action");
        let action_context = messages::action_context(
            domain_separator,
            [0u8; HASH_LEN],
            [0u8; HASH_LEN],
            action_type,
            payload_hash,
        );
        let signature =
            ShrincsSigner::sign_stateful_action(&mut keys, &public_key, &action_context)
                .expect("sign");
        assert_eq!(
            signature.auth_path.len(),
            1,
            "first stateful signature uses leaf 1"
        );

        let (bitmap_key, _) =
            crate::pda::bitmap_word_pda(&program_id, &account_pda_key, &[0u8; HASH_LEN], 0);
        let stateful_instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: borsh::to_vec(&ShrincsAccountInstruction::VerifyStatefulAction(
                StatefulActionArgs {
                    public_key: public_key.clone().into(),
                    action_type,
                    payload_hash,
                    signature: signature.into(),
                },
            ))
            .unwrap(),
        };
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[stateful_instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        result
            .result
            .expect("stateful action at leaf 1 should succeed");
        assert_eq!(result.metadata.unwrap().return_data.unwrap().data, vec![1]);

        // --- switch to RecoveryRotation and arm recovery mode ------------
        for instruction_kind in [
            ShrincsAccountInstruction::SetPolicyRecoveryRotation,
            ShrincsAccountInstruction::EnterRecoveryMode,
        ] {
            context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
            let instruction = Instruction {
                program_id,
                accounts: vec![
                    AccountMeta::new(account_pda_key, false),
                    AccountMeta::new_readonly(owner.pubkey(), true),
                ],
                data: borsh::to_vec(&instruction_kind).unwrap(),
            };
            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&context.payer.pubkey()),
                &[&context.payer, &owner],
                context.last_blockhash,
            );
            context
                .banks_client
                .process_transaction_with_metadata(transaction)
                .await
                .unwrap()
                .result
                .expect("arming recovery mode should succeed");
        }

        let state_before_rotation = fetch_state(&mut context, &account_pda_key).await;
        assert!(state_before_rotation.recovery_mode);

        // --- full rotation authorized by the current key's stateless
        // recovery signature ----------------------------------------------
        let (next_keys, next_public_key) =
            ShrincsSigner::keygen(b"shrincs-account-example e2e router next", 1024)
                .expect("keygen");
        let next_stateful_public_key =
            fixed_stateful_key_bytes(&next_public_key.stateful_public_key);
        let next_pk_seed = fixed_hash_bytes(&next_public_key.pk_seed);
        let next_hypertree_root = fixed_hash_bytes(&next_public_key.hypertree_root);
        let next_commitment = CoreShrincsVerifier::new().public_key_commitment(
            &next_stateful_public_key,
            next_pk_seed,
            next_hypertree_root,
        );

        let rotate_payload_hash = messages::rotate_full_payload(
            &next_stateful_public_key,
            &next_pk_seed,
            &next_hypertree_root,
            &next_commitment,
        );
        let rotate_action_context = messages::action_context(
            domain_separator,
            state_before_rotation.nonce,
            state_before_rotation.key_version,
            messages::ACTION_ROTATE_FULL,
            rotate_payload_hash,
        );
        let rotate_message = CoreShrincsVerifier::new()
            .stateless_action_message_hash(commitment, &rotate_action_context);
        let recovery_signature =
            ShrincsSigner::sign_stateless_raw(&keys, &rotate_message).expect("sign");
        assert!(
            CoreShrincsVerifier::new().verify_stateless(
                commitment,
                &public_key,
                &rotate_action_context,
                &recovery_signature
            ),
            "recovery signature must verify before submitting the rotation"
        );

        let rotate_instruction = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(account_pda_key, false)],
            data: borsh::to_vec(&ShrincsAccountInstruction::RotateFullKey(
                RotateFullKeyArgs {
                    current_public_key: public_key.clone().into(),
                    next_stateful_public_key,
                    next_pk_seed,
                    next_hypertree_root,
                    next_commitment,
                    recovery_signature: recovery_signature.into(),
                },
            ))
            .unwrap(),
        };
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[rotate_instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap()
            .result
            .expect("full rotation with a valid recovery signature should succeed");

        let state_after_rotation = fetch_state(&mut context, &account_pda_key).await;
        assert_eq!(
            state_after_rotation.current_public_key_commitment,
            next_commitment
        );
        let mut expected_key_version = state_before_rotation.key_version;
        increment_u256_be(&mut expected_key_version);
        assert_eq!(
            state_after_rotation.key_version, expected_key_version,
            "key_version advances by one"
        );
        assert_eq!(
            state_after_rotation.next_stateful_leaf_index, 1,
            "new epoch resets the leaf cursor"
        );

        // --- the new key's first action (leaf 1 of the new epoch) succeeds
        let mut next_keys = next_keys;
        let new_public_key = PublicKey {
            stateful_public_key: next_stateful_public_key.to_vec(),
            public_key_commitment: next_commitment.to_vec(),
            pk_seed: next_pk_seed.to_vec(),
            hypertree_root: next_hypertree_root.to_vec(),
        };
        let new_payload_hash =
            messages::action_payload(&action_type, b"post-rotation stateful action");
        let new_action_context = messages::action_context(
            domain_separator,
            state_after_rotation.nonce,
            state_after_rotation.key_version,
            action_type,
            new_payload_hash,
        );
        let new_signature = ShrincsSigner::sign_stateful_action(
            &mut next_keys,
            &new_public_key,
            &new_action_context,
        )
        .expect("sign");
        assert_eq!(
            new_signature.auth_path.len(),
            1,
            "new epoch's first stateful signature uses leaf 1"
        );

        let (new_bitmap_key, _) = crate::pda::bitmap_word_pda(
            &program_id,
            &account_pda_key,
            &state_after_rotation.key_version,
            0,
        );
        let new_stateful_instruction = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account_pda_key, false),
                AccountMeta::new(new_bitmap_key, false),
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
            ],
            data: borsh::to_vec(&ShrincsAccountInstruction::VerifyStatefulAction(
                StatefulActionArgs {
                    public_key: new_public_key.into(),
                    action_type,
                    payload_hash: new_payload_hash,
                    signature: new_signature.into(),
                },
            ))
            .unwrap(),
        };
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[new_stateful_instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        result
            .result
            .expect("the new key's first action should verify after rotation");
        assert_eq!(result.metadata.unwrap().return_data.unwrap().data, vec![1]);

        // --- an action still carrying the OLD commitment/key fails --------
        let old_probe_payload_hash =
            messages::action_payload(&messages::ACTION_STATELESS, b"stale key probe");
        let old_probe_context = messages::action_context(
            domain_separator,
            state_after_rotation.nonce,
            state_after_rotation.key_version,
            messages::ACTION_STATELESS,
            old_probe_payload_hash,
        );
        let old_probe_message = CoreShrincsVerifier::new()
            .stateless_action_message_hash(commitment, &old_probe_context);
        let old_probe_signature =
            ShrincsSigner::sign_stateless_raw(&keys, &old_probe_message).expect("sign");
        let old_probe_instruction = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(account_pda_key, false)],
            data: borsh::to_vec(&ShrincsAccountInstruction::VerifyStatelessAction(
                StatelessActionArgs {
                    public_key: public_key.into(),
                    action_type: messages::ACTION_STATELESS,
                    payload_hash: old_probe_payload_hash,
                    signature: old_probe_signature.into(),
                },
            ))
            .unwrap(),
        };
        context.last_blockhash = context.get_new_latest_blockhash().await.unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[old_probe_instruction],
            Some(&context.payer.pubkey()),
            &[&context.payer],
            context.last_blockhash,
        );
        let result = context
            .banks_client
            .process_transaction_with_metadata(transaction)
            .await
            .unwrap();
        assert!(
            result.result.is_err(),
            "an action carrying the OLD commitment/key must fail after rotation"
        );
    }
}
