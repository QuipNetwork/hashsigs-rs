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

//! PDA seed derivation for SHRINCS account state.
//!
//! Ported near-verbatim from the deleted Solana account program
//! (`solana/src/account.rs` prior to its removal at `5e13d35~1`), adapted to
//! drop the `hashsigs-rs` dependency: `HASH_LEN` now comes from
//! [`crate::state::HASH_LEN`], and the leaf-bitmap bit math
//! ([`bitmap_word_index`], [`bitmap_bit_index`], [`set_leaf_bit`],
//! [`leaf_bit_is_set`]) was factored out of `is_leaf_used`/`mark_leaf_used`
//! into standalone pure functions so it is unit-testable without
//! constructing `AccountInfo` fixtures.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction::{allocate, assign, create_account, transfer},
    sysvar::{rent::Rent, Sysvar},
};

use crate::state::HASH_LEN;

/// Seed prefix for the per-owner account-state PDA.
pub const ACCOUNT_SEED_PREFIX: &[u8] = b"shrincs-account";
/// Seed prefix for a per-(key_version, word_index) leaf-usage bitmap word PDA.
pub const BITMAP_SEED_PREFIX: &[u8] = b"shrincs-bitmap";

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

/// Word index (0-based) of the 256-leaf bitmap word containing `leaf_index`.
pub fn bitmap_word_index(leaf_index: u32) -> u32 {
    leaf_index >> 8
}

/// Bit position (0..=255) of `leaf_index` within its bitmap word.
pub fn bitmap_bit_index(leaf_index: u32) -> u8 {
    (leaf_index & 0xff) as u8
}

/// Set the bit for `leaf_index` in a 32-byte bitmap word.
pub fn set_leaf_bit(word: &mut [u8; HASH_LEN], leaf_index: u32) {
    let bit_index = bitmap_bit_index(leaf_index);
    word[(bit_index / 8) as usize] |= 1 << (bit_index % 8);
}

/// Read the bit for `leaf_index` in a 32-byte bitmap word.
pub fn leaf_bit_is_set(word: &[u8; HASH_LEN], leaf_index: u32) -> bool {
    let bit_index = bitmap_bit_index(leaf_index);
    word[(bit_index / 8) as usize] & (1 << (bit_index % 8)) != 0
}

/// Read bitmap-based stateful leaf usage. An uncreated word PDA means every
/// leaf in that word is unused.
pub fn is_leaf_used(
    program_id: &Pubkey,
    account_key: &Pubkey,
    key_version: &[u8; HASH_LEN],
    leaf_index: u32,
    bitmap_account: &AccountInfo,
) -> Result<bool, ProgramError> {
    let word_index = bitmap_word_index(leaf_index);
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
    let mut word = [0u8; HASH_LEN];
    word.copy_from_slice(&data);
    Ok(leaf_bit_is_set(&word, leaf_index))
}

/// Inputs for creating (or adopting) a program-owned PDA of fixed size.
///
/// Bundled to keep [`create_or_adopt_pda`] within the positional-argument
/// budget. `payer`/`target`/`system_program` share the instruction's account
/// lifetime `'info`; the struct borrows them for the call's lifetime `'a`.
struct PdaInit<'a, 'info> {
    /// Signer funding any rent shortfall on `target`.
    payer: &'a AccountInfo<'info>,
    /// Destination PDA to bring under `program_id` ownership.
    target: &'a AccountInfo<'info>,
    /// System program, required by the allocate/assign/transfer/create CPIs.
    system_program: &'a AccountInfo<'info>,
    /// Program that should own `target` once created.
    program_id: &'a Pubkey,
    /// Fixed data length to allocate for `target`.
    space: usize,
}

/// Create `target` as a `program_id`-owned PDA of `init.space` bytes,
/// tolerating a pre-funded destination.
///
/// `create_account` fails with `AccountAlreadyInUse` when the destination
/// already holds lamports, which lets anyone permanently block a not-yet-used
/// PDA by sending it a single lamport. When the (still system-owned,
/// data-empty) destination already holds lamports, this instead tops up any
/// rent shortfall via `transfer`, then `allocate`s and `assign`s it -- the
/// standard Solana create-or-adopt pattern -- so a griefing pre-fund cannot
/// deny the leaf or the account. Callers must confirm `target.data_is_empty()`
/// before calling. `signer_seeds` are the PDA seeds (including bump)
/// authorizing the CPIs.
fn create_or_adopt_pda(init: &PdaInit, signer_seeds: &[&[u8]]) -> ProgramResult {
    let rent = Rent::get()?;
    let required_lamports = rent.minimum_balance(init.space);
    let current_lamports = init.target.lamports();
    let space = init.space as u64;

    if current_lamports == 0 {
        // Empty and unfunded: create_account funds, allocates, and assigns atomically.
        invoke_signed(
            &create_account(
                init.payer.key,
                init.target.key,
                required_lamports,
                space,
                init.program_id,
            ),
            &[
                init.payer.clone(),
                init.target.clone(),
                init.system_program.clone(),
            ],
            &[signer_seeds],
        )?;
        return Ok(());
    }

    // Pre-funded system-owned destination: create_account would fail with
    // AccountAlreadyInUse, so top up any rent shortfall, then allocate + assign.
    if required_lamports > current_lamports {
        invoke(
            &transfer(
                init.payer.key,
                init.target.key,
                required_lamports - current_lamports,
            ),
            &[
                init.payer.clone(),
                init.target.clone(),
                init.system_program.clone(),
            ],
        )?;
    }
    invoke_signed(
        &allocate(init.target.key, space),
        &[init.target.clone(), init.system_program.clone()],
        &[signer_seeds],
    )?;
    invoke_signed(
        &assign(init.target.key, init.program_id),
        &[init.target.clone(), init.system_program.clone()],
        &[signer_seeds],
    )?;
    Ok(())
}

/// Mark a stateful leaf used under bitmap tracking, creating the 32-byte word
/// PDA on first use in that word. Rent for that account is paid by `payer`.
#[allow(clippy::too_many_arguments)]
pub fn mark_leaf_used<'a>(
    program_id: &Pubkey,
    account_key: &Pubkey,
    key_version: &[u8; HASH_LEN],
    leaf_index: u32,
    bitmap_account: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
) -> ProgramResult {
    let word_index = bitmap_word_index(leaf_index);
    let (expected_pda, bump) = bitmap_word_pda(program_id, account_key, key_version, word_index);
    if expected_pda != *bitmap_account.key {
        return Err(ProgramError::InvalidSeeds);
    }
    if bitmap_account.data_is_empty() {
        let word_index_le = word_index.to_le_bytes();
        create_or_adopt_pda(
            &PdaInit {
                payer,
                target: bitmap_account,
                system_program,
                program_id,
                space: HASH_LEN,
            },
            &[
                BITMAP_SEED_PREFIX,
                account_key.as_ref(),
                key_version,
                &word_index_le,
                &[bump],
            ],
        )?;
    }
    let mut data = bitmap_account.try_borrow_mut_data()?;
    // Mirror is_leaf_used's length check: never index a short account.
    if data.len() != HASH_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let bit_index = bitmap_bit_index(leaf_index);
    data[(bit_index / 8) as usize] |= 1 << (bit_index % 8);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_pda_is_deterministic() {
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let salt = [7u8; HASH_LEN];
        let (pda1, bump1) = account_pda(&program_id, &owner, &salt);
        let (pda2, bump2) = account_pda(&program_id, &owner, &salt);
        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn bitmap_word_pda_varies_by_word_index() {
        let program_id = Pubkey::new_unique();
        let account_key = Pubkey::new_unique();
        let key_version = [1u8; HASH_LEN];
        let (pda0, _) = bitmap_word_pda(&program_id, &account_key, &key_version, 0);
        let (pda1, _) = bitmap_word_pda(&program_id, &account_key, &key_version, 1);
        assert_ne!(pda0, pda1);
    }

    #[test]
    fn bitmap_word_and_bit_index_split_leaf_index() {
        assert_eq!(bitmap_word_index(0), 0);
        assert_eq!(bitmap_bit_index(0), 0);
        assert_eq!(bitmap_word_index(255), 0);
        assert_eq!(bitmap_bit_index(255), 255);
        assert_eq!(bitmap_word_index(256), 1);
        assert_eq!(bitmap_bit_index(256), 0);
    }

    #[test]
    fn leaf_bit_set_and_read_within_one_word() {
        let mut word = [0u8; HASH_LEN];
        assert!(!leaf_bit_is_set(&word, 0));
        assert!(!leaf_bit_is_set(&word, 255));
        assert!(!leaf_bit_is_set(&word, 128));

        set_leaf_bit(&mut word, 0);
        set_leaf_bit(&mut word, 255);

        assert!(leaf_bit_is_set(&word, 0));
        assert!(leaf_bit_is_set(&word, 255));
        assert!(!leaf_bit_is_set(&word, 128));
    }

    /// A present-but-short bitmap-word account must be rejected with
    /// `InvalidAccountData` (matching `is_leaf_used`'s length guard) rather
    /// than panicking on the byte index. A non-empty account skips the
    /// create-or-adopt branch, so `mark_leaf_used` reaches the write path
    /// with a wrong-length buffer.
    #[test]
    fn mark_leaf_used_rejects_short_bitmap_account() {
        let program_id = Pubkey::new_unique();
        let account_key = Pubkey::new_unique();
        let key_version = [3u8; HASH_LEN];
        let leaf_index = 5u32; // word_index 0, bit_index 5.
        let (bitmap_key, _bump) = bitmap_word_pda(&program_id, &account_key, &key_version, 0);

        // 16 bytes: non-empty (skips create) but shorter than a full word.
        let mut short_data = vec![0u8; 16];
        let mut bitmap_lamports = 1_000_000u64;
        let bitmap_account = AccountInfo::new(
            &bitmap_key,
            false,
            true,
            &mut bitmap_lamports,
            &mut short_data,
            &program_id,
            false,
            u64::default(),
        );

        // Payer / system-program placeholders: unused on the guarded path.
        let system_id = solana_program::system_program::id();
        let payer_key = Pubkey::new_unique();
        let mut payer_lamports = 0u64;
        let mut payer_data: Vec<u8> = Vec::new();
        let payer = AccountInfo::new(
            &payer_key,
            true,
            true,
            &mut payer_lamports,
            &mut payer_data,
            &system_id,
            false,
            u64::default(),
        );
        let mut sys_lamports = 0u64;
        let mut sys_data: Vec<u8> = Vec::new();
        let system_program = AccountInfo::new(
            &system_id,
            false,
            false,
            &mut sys_lamports,
            &mut sys_data,
            &system_id,
            true,
            u64::default(),
        );

        let result = mark_leaf_used(
            &program_id,
            &account_key,
            &key_version,
            leaf_index,
            &bitmap_account,
            &payer,
            &system_program,
        );
        assert_eq!(result, Err(ProgramError::InvalidAccountData));
    }
}
