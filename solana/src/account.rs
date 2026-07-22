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

//! Solana account-example program mirroring the SHRINCS account state
//! machine (`SHRINCSAccountVerifierExample.sol` / `hashsigs_rs::account`).
//!
//! State lives in a PDA (`ShrincsAccountState`) owned by this program instead
//! of contract storage. Stateful leaf-reuse tracking under the `LeafBitmap`
//! policy cannot use an in-account `HashMap` the way the host Rust port does
//! (Solana account data is bounded and rent-charged up front), so each
//! 256-leaf bitmap word is its own on-demand PDA, seeded by
//! `(account, key_version, word_index)`. Creating one costs the caller rent
//! for a 32-byte account; policies other than `LeafBitmap` never create these.
//!
//! ## Domain separator (needs-decision)
//!
//! Solidity binds signatures to `(chainid, address(this))`; the host Rust
//! port takes an arbitrary `(chainId, contractAddress: [u8; 20])` pair. Solana
//! has no chain id and addresses are 32-byte `Pubkey`s, not 20-byte EVM
//! addresses, so neither mapping applies as-is. This module uses:
//!
//! ```text
//! domain_separator = keccak256(keccak256("shrincs-account-v1") || program_id || account_pubkey)
//! ```
//!
//! i.e. the deployed *program id* stands in for `chainid` (it is the
//! network-and-build-wide constant a Solana program has) and the PDA's own
//! pubkey stands in for `address(this)`. This keeps the encoded length
//! identical to the Solidity/host version (tag + two 32-byte words) but is a
//! judgment call, not a derivation forced by the reference implementations --
//! flagged here for maintainer sign-off before this program handles real
//! funds.

use borsh::{BorshDeserialize, BorshSerialize};
use hashsigs_rs::shrincs::{
    ActionContext, PublicKey, RotationContext, RotationTarget, ShrincsVerifier,
    StatefulRotationTarget, StatefulSignature, StatelessSignature, HASH_LEN,
    STATELESS_SIGNATURE_LIMIT,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction::create_account,
    sysvar::{rent::Rent, Sysvar},
};

use crate::processor::keccak256;
use crate::sphincs_plus_c::{ShrincsPublicKeyDto, StatefulSignatureDto, StatelessSignatureDto};

/// Seed prefix for the per-owner account-state PDA.
pub const ACCOUNT_SEED_PREFIX: &[u8] = b"shrincs-account";
/// Seed prefix for a per-(key_version, word_index) leaf-usage bitmap word PDA.
pub const BITMAP_SEED_PREFIX: &[u8] = b"shrincs-bitmap";
/// Stable domain tag for this wrapper family (mirrors Solidity's `DOMAIN_TAG`).
pub const DOMAIN_TAG_MESSAGE: &[u8] = b"shrincs-account-v1";
/// Freshly installed keys begin stateful signing at leaf 1.
pub const INITIAL_STATEFUL_LEAF_INDEX: u32 = 1;

/// Current stateful leaf-tracking / recovery policy enforced by the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatefulPolicy {
    /// Accept only the next expected stateful leaf index.
    MonotonicIndex = 0,
    /// Treat stateless signatures as recovery/rotation authority once
    /// recovery mode is entered.
    RecoveryRotation = 1,
    /// Track stateful leaf reuse with a per-key-version bitmap.
    LeafBitmap = 2,
}

impl TryFrom<u8> for StatefulPolicy {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StatefulPolicy::MonotonicIndex),
            1 => Ok(StatefulPolicy::RecoveryRotation),
            2 => Ok(StatefulPolicy::LeafBitmap),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

/// Distinct wrapper failure reasons, mirroring
/// `hashsigs_rs::account::AccountError` one-to-one so on-chain failures stay
/// as observable as the host port's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShrincsAccountError {
    OnlyOwner = 0,
    RecoveryPolicyRequired = 1,
    StatefulIndexRollback = 2,
    StatefulPolicyFrozen = 3,
    InvalidSignature = 4,
    BudgetExhausted = 5,
    RecoveryNotArmed = 6,
    StatefulPathDisabled = 7,
    StatefulLeafRejected = 8,
}

impl From<ShrincsAccountError> for ProgramError {
    fn from(err: ShrincsAccountError) -> Self {
        ProgramError::Custom(err as u32)
    }
}

/// PDA-resident SHRINCS account state. Field order fixes the Borsh layout;
/// append-only if the layout ever needs to grow.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShrincsAccountState {
    /// Installed bundle commitment currently trusted by the wrapper.
    pub current_public_key_commitment: [u8; HASH_LEN],
    /// Account owner allowed to change wrapper policy and enter recovery mode.
    pub owner: Pubkey,
    /// Canonical action/rotation nonce consumed on successful wrapper operations.
    pub nonce: [u8; HASH_LEN],
    /// Installed-key epoch incremented whenever a fresh key bundle is installed.
    pub key_version: [u8; HASH_LEN],
    /// Number of stateless signatures consumed under the current installed key.
    pub stateless_signatures_used: u64,
    /// Current stateful leaf-tracking / recovery policy (`StatefulPolicy` as `u8`).
    pub stateful_policy: u8,
    /// Whether stateful leaf consumption has frozen policy changes for the current key epoch.
    pub stateful_policy_frozen: bool,
    /// Next expected stateful leaf when monotonic tracking is active.
    pub next_stateful_leaf_index: u32,
    /// Whether the wrapper is currently in recovery mode for stateless rotation.
    pub recovery_mode: bool,
}

/// Compact Borsh DTO for `hashsigs_rs::shrincs::StatefulRotationTarget`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StatefulRotationTargetDto {
    pub stateful_public_key: Vec<u8>,
    pub public_key_commitment: [u8; HASH_LEN],
}

impl From<StatefulRotationTargetDto> for StatefulRotationTarget {
    fn from(dto: StatefulRotationTargetDto) -> Self {
        StatefulRotationTarget {
            stateful_public_key: dto.stateful_public_key,
            public_key_commitment: dto.public_key_commitment.to_vec(),
        }
    }
}

/// Compact Borsh DTO for `hashsigs_rs::shrincs::RotationTarget`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RotationTargetDto {
    pub stateful_public_key: Vec<u8>,
    pub public_key_commitment: [u8; HASH_LEN],
    pub pk_seed: Vec<u8>,
    pub hypertree_root: Vec<u8>,
}

impl From<RotationTargetDto> for RotationTarget {
    fn from(dto: RotationTargetDto) -> Self {
        RotationTarget {
            stateful_public_key: dto.stateful_public_key,
            public_key_commitment: dto.public_key_commitment.to_vec(),
            pk_seed: dto.pk_seed,
            hypertree_root: dto.hypertree_root,
        }
    }
}

/// Derive the account-state PDA for `(owner, salt)`.
pub fn account_pda(program_id: &Pubkey, owner: &Pubkey, salt: &[u8; HASH_LEN]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ACCOUNT_SEED_PREFIX, owner.as_ref(), salt], program_id)
}

/// Derive the leaf-usage bitmap word PDA for `(account, key_version, word_index)`.
pub fn bitmap_word_pda(
    program_id: &Pubkey,
    account_key: &Pubkey,
    key_version: &[u8; HASH_LEN],
    word_index: u32,
) -> (Pubkey, u8) {
    let word_index_le = word_index.to_le_bytes();
    Pubkey::find_program_address(
        &[
            BITMAP_SEED_PREFIX,
            account_key.as_ref(),
            key_version,
            &word_index_le,
        ],
        program_id,
    )
}

/// Compute the canonical signing domain for `account_key` under `program_id`.
/// Off-chain signers must call this (or replicate it) to build the exact
/// `ActionContext`/`RotationContext` a given action/rotation instruction will
/// check against. See the module doc "Domain separator" section for the
/// mapping rationale.
pub fn domain_separator(program_id: &Pubkey, account_key: &Pubkey) -> [u8; HASH_LEN] {
    let tag = keccak256(DOMAIN_TAG_MESSAGE);
    let mut encoded = Vec::with_capacity(HASH_LEN * 3);
    encoded.extend_from_slice(&tag);
    encoded.extend_from_slice(program_id.as_ref());
    encoded.extend_from_slice(account_key.as_ref());
    keccak256(&encoded)
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

fn only_owner(state: &ShrincsAccountState, owner_info: &AccountInfo) -> Result<(), ProgramError> {
    if !owner_info.is_signer || *owner_info.key != state.owner {
        return Err(ShrincsAccountError::OnlyOwner.into());
    }
    Ok(())
}

/// Read bitmap-based stateful leaf usage. An uncreated word PDA means every
/// leaf in that word is unused.
fn is_leaf_used(
    program_id: &Pubkey,
    account_key: &Pubkey,
    key_version: &[u8; HASH_LEN],
    leaf_index: u32,
    bitmap_account: &AccountInfo,
) -> Result<bool, ProgramError> {
    let word_index = leaf_index >> 8;
    let bit_index = leaf_index & 0xff;
    let (expected_pda, _bump) = bitmap_word_pda(program_id, account_key, key_version, word_index);
    if expected_pda != *bitmap_account.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if bitmap_account.data_is_empty() {
        return Ok(false);
    }
    let data = bitmap_account.try_borrow_data()?;
    if data.len() != HASH_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let byte = data[(bit_index / 8) as usize];
    Ok(byte & (1 << (bit_index % 8)) != 0)
}

/// Mark a stateful leaf used under bitmap tracking, creating the 32-byte word
/// PDA on first use in that word. Rent for that account is paid by `payer`.
#[allow(clippy::too_many_arguments)]
fn mark_leaf_used<'a>(
    program_id: &Pubkey,
    account_key: &Pubkey,
    key_version: &[u8; HASH_LEN],
    leaf_index: u32,
    bitmap_account: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
) -> ProgramResult {
    let word_index = leaf_index >> 8;
    let bit_index = leaf_index & 0xff;
    let (expected_pda, bump) = bitmap_word_pda(program_id, account_key, key_version, word_index);
    if expected_pda != *bitmap_account.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if bitmap_account.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(HASH_LEN);
        let word_index_le = word_index.to_le_bytes();
        invoke_signed(
            &create_account(
                payer.key,
                bitmap_account.key,
                lamports,
                HASH_LEN as u64,
                program_id,
            ),
            &[payer.clone(), bitmap_account.clone(), system_program.clone()],
            &[&[
                BITMAP_SEED_PREFIX,
                account_key.as_ref(),
                key_version,
                &word_index_le,
                &[bump],
            ]],
        )?;
    }
    let mut data = bitmap_account.try_borrow_mut_data()?;
    data[(bit_index / 8) as usize] |= 1 << (bit_index % 8);
    Ok(())
}

/// Check whether the active policy allows a stateful leaf before verification
/// (mirrors `checkStatefulLeafUse`/`precheckStatefulLeafUse`).
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
            if is_leaf_used(program_id, account_key, &state.key_version, leaf_index, bitmap_account)? {
                Err(ShrincsAccountError::StatefulLeafRejected.into())
            } else {
                Ok(())
            }
        }
    }
}

/// Record a successfully verified stateful leaf under the active policy
/// (mirrors `commitStatefulLeafUse`).
#[allow(clippy::too_many_arguments)]
fn commit_stateful_leaf_use<'a>(
    state: &mut ShrincsAccountState,
    leaf_index: u32,
    program_id: &Pubkey,
    account_key: &Pubkey,
    bitmap_account: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
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
                bitmap_account,
                payer,
                system_program,
            )?;
        }
        StatefulPolicy::RecoveryRotation => {}
    }
    state.stateful_policy_frozen = true;
    Ok(())
}

fn increment_u256_be(value: &mut [u8; HASH_LEN]) {
    // Solidity uint256 values are encoded big-endian, matching
    // `hashsigs_rs::account::increment_u256_be`.
    for byte in value.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

/// Install a rotated key bundle and reset wrapper state for the next epoch
/// (mirrors `installRotatedKey`).
fn install_rotated_key(
    state: &mut ShrincsAccountState,
    next_commitment: [u8; HASH_LEN],
    reset_stateless_usage: bool,
) {
    let previous_commitment = state.current_public_key_commitment;
    state.current_public_key_commitment = next_commitment;
    increment_u256_be(&mut state.nonce);
    increment_u256_be(&mut state.key_version);
    if reset_stateless_usage {
        state.stateless_signatures_used = 0;
    }
    state.next_stateful_leaf_index = INITIAL_STATEFUL_LEAF_INDEX;
    state.stateful_policy_frozen = false;
    state.stateful_policy = StatefulPolicy::MonotonicIndex as u8;
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:KeyRotated:previous={:?}:next={:?}:key_version={:?}",
        previous_commitment,
        next_commitment,
        state.key_version
    );
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
}

/// Accounts: `[payer (signer, writable), owner (signer), account PDA
/// (writable), system_program]`.
pub fn process_init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    salt: [u8; HASH_LEN],
    initial_public_key_commitment: [u8; HASH_LEN],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let payer = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;
    let account_info = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !payer.is_signer || !owner_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_pda, bump) = account_pda(program_id, owner_info.key, &salt);
    if expected_pda != *account_info.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if !account_info.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let state = ShrincsAccountState {
        current_public_key_commitment: initial_public_key_commitment,
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

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(data.len());
    invoke_signed(
        &create_account(
            payer.key,
            account_info.key,
            lamports,
            data.len() as u64,
            program_id,
        ),
        &[payer.clone(), account_info.clone(), system_program.clone()],
        &[&[ACCOUNT_SEED_PREFIX, owner_info.key.as_ref(), &salt, &[bump]]],
    )?;

    account_info.try_borrow_mut_data()?[..data.len()].copy_from_slice(&data);
    msg!(
        "shrincs-account-event:Initialized:owner={}:commitment={:?}",
        owner_info.key,
        initial_public_key_commitment
    );
    Ok(())
}

/// Accounts: `[account PDA (writable), leaf-bitmap word PDA (writable;
/// required positionally, only touched under `LeafBitmap` policy), payer
/// (signer, writable; only used to fund a new bitmap word), system_program]`.
pub fn process_verify_stateful_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    public_key: ShrincsPublicKeyDto,
    signature: StatefulSignatureDto,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let bitmap_account = next_account_info(accounts_iter)?;
    let payer = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    let public_key: PublicKey = public_key.into();
    let signature: StatefulSignature = signature.into();

    // Defense-in-depth: reject an auth path so long its length would
    // truncate when narrowed to u32 before it becomes the leaf index.
    if signature.auth_path.len() > u32::MAX as usize {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }
    let leaf_index = signature.auth_path.len() as u32;

    check_stateful_leaf_use(&state, leaf_index, program_id, account_info.key, bitmap_account)?;

    let context = ActionContext {
        domain_separator: domain_separator(program_id, account_info.key),
        nonce: state.nonce,
        key_version: state.key_version,
        action_type,
        payload_hash,
    };

    let ok = ShrincsVerifier::new().verify_stateful(
        state.current_public_key_commitment,
        &public_key,
        &context,
        &signature,
    );
    if !ok {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }

    commit_stateful_leaf_use(
        &mut state,
        leaf_index,
        program_id,
        account_info.key,
        bitmap_account,
        payer,
        system_program,
    )?;
    msg!(
        "shrincs-account-event:StatefulSignatureVerified:leaf_index={}:nonce={:?}:key_version={:?}",
        leaf_index,
        state.nonce,
        state.key_version
    );
    increment_u256_be(&mut state.nonce);
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable)]`.
pub fn process_verify_stateless_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    action_type: [u8; HASH_LEN],
    payload_hash: [u8; HASH_LEN],
    public_key: ShrincsPublicKeyDto,
    signature: StatelessSignatureDto,
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

    let public_key: PublicKey = public_key.into();
    let signature: StatelessSignature = signature.into();
    let consumed_nonce = state.nonce;
    let context = ActionContext {
        domain_separator: domain_separator(program_id, account_info.key),
        nonce: state.nonce,
        key_version: state.key_version,
        action_type,
        payload_hash,
    };

    let ok = ShrincsVerifier::new().verify_stateless(
        state.current_public_key_commitment,
        &public_key,
        &context,
        &signature,
    );
    if !ok {
        return Err(ShrincsAccountError::InvalidSignature.into());
    }

    increment_u256_be(&mut state.nonce);
    state.stateless_signatures_used += 1;
    msg!(
        "shrincs-account-event:StatelessSignatureVerified:used_count={}:nonce={:?}:key_version={:?}",
        state.stateless_signatures_used,
        consumed_nonce,
        state.key_version
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable)]`.
pub fn process_rotate_to_fresh_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    public_key: ShrincsPublicKeyDto,
    recovery_signature: StatelessSignatureDto,
    next_stateful_key: StatefulRotationTargetDto,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    if StatefulPolicy::try_from(state.stateful_policy)? != StatefulPolicy::RecoveryRotation {
        return Err(ShrincsAccountError::RecoveryPolicyRequired.into());
    }
    if !state.recovery_mode {
        return Err(ShrincsAccountError::RecoveryNotArmed.into());
    }
    if state.stateless_signatures_used >= STATELESS_SIGNATURE_LIMIT {
        return Err(ShrincsAccountError::BudgetExhausted.into());
    }

    let current_public_key: PublicKey = public_key.into();
    let recovery_signature: StatelessSignature = recovery_signature.into();
    let next_target: StatefulRotationTarget = next_stateful_key.into();

    let context = RotationContext {
        domain_separator: domain_separator(program_id, account_info.key),
        nonce: state.nonce,
        key_version: state.key_version,
    };

    let Some(next_commitment) = ShrincsVerifier::new().rotate_stateful_via_stateless(
        state.current_public_key_commitment,
        &current_public_key,
        &context,
        &recovery_signature,
        &next_target,
    ) else {
        return Err(ShrincsAccountError::InvalidSignature.into());
    };

    state.stateless_signatures_used += 1;
    msg!(
        "shrincs-account-event:StatelessRotationConsumed:used_count={}:nonce={:?}:key_version={:?}:next_key={:?}:full_rotation=false",
        state.stateless_signatures_used,
        state.nonce,
        state.key_version,
        next_commitment
    );

    // Preserve stateless usage accounting: the stateless key material is
    // unchanged by a stateful-only rotation.
    install_rotated_key(&mut state, next_commitment, false);
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable)]`.
pub fn process_rotate_full_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    public_key: ShrincsPublicKeyDto,
    recovery_signature: StatelessSignatureDto,
    next_key: RotationTargetDto,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    if StatefulPolicy::try_from(state.stateful_policy)? != StatefulPolicy::RecoveryRotation {
        return Err(ShrincsAccountError::RecoveryPolicyRequired.into());
    }
    if !state.recovery_mode {
        return Err(ShrincsAccountError::RecoveryNotArmed.into());
    }
    if state.stateless_signatures_used >= STATELESS_SIGNATURE_LIMIT {
        return Err(ShrincsAccountError::BudgetExhausted.into());
    }

    let current_public_key: PublicKey = public_key.into();
    let recovery_signature: StatelessSignature = recovery_signature.into();
    let next_target: RotationTarget = next_key.into();

    // Reset the stateless budget only if the target actually replaces the
    // stateless key material -- a rotation target reusing the current
    // pk_seed/hypertree_root keeps the same few-time stateless key, so its
    // usage accounting must carry forward.
    let stateless_key_changed = next_target.pk_seed != current_public_key.pk_seed
        || next_target.hypertree_root != current_public_key.hypertree_root;

    let context = RotationContext {
        domain_separator: domain_separator(program_id, account_info.key),
        nonce: state.nonce,
        key_version: state.key_version,
    };

    let Some(next_commitment) = ShrincsVerifier::new().stateless_rotate(
        state.current_public_key_commitment,
        &current_public_key,
        &context,
        &recovery_signature,
        &next_target,
    ) else {
        return Err(ShrincsAccountError::InvalidSignature.into());
    };

    state.stateless_signatures_used += 1;
    msg!(
        "shrincs-account-event:StatelessRotationConsumed:used_count={}:nonce={:?}:key_version={:?}:next_key={:?}:full_rotation=true",
        state.stateless_signatures_used,
        state.nonce,
        state.key_version,
        next_commitment
    );

    install_rotated_key(&mut state, next_commitment, stateless_key_changed);
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
pub fn process_set_policy_monotonic(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    initial_leaf_index: u32,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;
    if state.stateful_policy_frozen {
        return Err(ShrincsAccountError::StatefulPolicyFrozen.into());
    }
    if initial_leaf_index < state.next_stateful_leaf_index {
        return Err(ShrincsAccountError::StatefulIndexRollback.into());
    }
    state.stateful_policy = StatefulPolicy::MonotonicIndex as u8;
    state.next_stateful_leaf_index = initial_leaf_index;
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
pub fn process_set_policy_recovery_rotation(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let account_info = next_account_info(accounts_iter)?;
    let owner_info = next_account_info(accounts_iter)?;

    let mut state = load_state(account_info, program_id)?;
    only_owner(&state, owner_info)?;
    // No freeze check: RecoveryRotation disables the stateful path entirely
    // (see checkStatefulLeafUse), so entering it cannot enable leaf reuse,
    // and it is the only route back to rotation, which clears the freeze.
    state.stateful_policy = StatefulPolicy::RecoveryRotation as u8;
    if state.next_stateful_leaf_index == 0 {
        state.next_stateful_leaf_index = INITIAL_STATEFUL_LEAF_INDEX;
    }
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
pub fn process_set_policy_leaf_bitmap(
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
    if state.next_stateful_leaf_index == 0 {
        state.next_stateful_leaf_index = INITIAL_STATEFUL_LEAF_INDEX;
    }
    state.recovery_mode = false;
    msg!(
        "shrincs-account-event:StatefulPolicySet:policy={}:next_leaf={}",
        state.stateful_policy,
        state.next_stateful_leaf_index
    );
    store_state(account_info, &state)
}

/// Accounts: `[account PDA (writable), owner (signer)]`.
pub fn process_enter_recovery_mode(
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
