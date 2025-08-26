// Copyright (C) 2024 quip.network
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
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    program::invoke_signed,
    sysvar::{rent::Rent, Sysvar},
};
use hashsigs_rs::{WOTSPlus, PublicKey, constants};
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::keccak::hash as keccak256_hash;
use solana_program::program::set_return_data;
use solana_program::system_instruction::create_account;
use solana_program::account_info::next_account_info;

// NOTE: The following is supposed to increase the stack size but it does not work in practice.
/*
#![allow(clippy::all)]
#![cfg_attr(feature = "solana-runtime", feature(custom_stack_sizes))]
#[cfg_attr(feature = "solana-runtime", stack_size = "32768")]
*/

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak256_hash(data).to_bytes()
}

// Create a wrapper type for PublicKey
#[derive(Debug)]
pub struct PublicKeyWrapper(PublicKey);

// Implement conversion methods
impl From<PublicKey> for PublicKeyWrapper {
    fn from(pk: PublicKey) -> Self {
        PublicKeyWrapper(pk)
    }
}

impl From<PublicKeyWrapper> for PublicKey {
    fn from(wrapper: PublicKeyWrapper) -> Self {
        wrapper.0
    }
}

// Implement BorshSerialize for our wrapper
impl borsh::ser::BorshSerialize for PublicKeyWrapper {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.0.public_seed, writer)?;
        borsh::BorshSerialize::serialize(&self.0.public_key_hash, writer)?;
        Ok(())
    }
}

// Implement BorshDeserialize for our wrapper
impl borsh::de::BorshDeserialize for PublicKeyWrapper {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let public_seed: [u8; constants::HASH_LEN] = borsh::BorshDeserialize::deserialize(buf)?;
        let public_key_hash: [u8; constants::HASH_LEN] = borsh::BorshDeserialize::deserialize(buf)?;
        Ok(PublicKeyWrapper(PublicKey {
            public_seed,
            public_key_hash,
        }))
    }
    
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let public_seed: [u8; constants::HASH_LEN] = borsh::BorshDeserialize::deserialize_reader(reader)?;
        let public_key_hash: [u8; constants::HASH_LEN] = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Ok(PublicKeyWrapper(PublicKey {
            public_seed,
            public_key_hash,
        }))
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SignatureAccount {
    pub is_initialized: bool,
    pub signature: Vec<[u8; constants::HASH_LEN]>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum WOTSPlusInstruction {
    GenerateKeyPair {
        private_seed: [u8; 32],
    },
    Sign {
        private_key: [u8; 32],
        message: Vec<u8>,
    },
    Verify {
        public_key: PublicKeyWrapper,
        message: Vec<u8>,
        signature: Vec<[u8; constants::HASH_LEN]>,
    },
    VerifyWithRandomization {
        public_key_hash: [u8; constants::HASH_LEN],
        message: Vec<u8>,
        signature: Vec<[u8; constants::HASH_LEN]>,
        randomization_elements: Vec<[u8; constants::HASH_LEN]>,
    },
}

// Split the instruction processing into smaller functions to reduce stack usage
fn process_generate_keypair(
    wots: &WOTSPlus,
    private_seed: [u8; 32],
) -> ProgramResult {
    let (public_key, private_key) = wots.generate_key_pair(&private_seed);
    
    let mut result_data = Vec::new();
    let wrapper = PublicKeyWrapper::from(public_key);
    wrapper.serialize(&mut result_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    private_key.serialize(&mut result_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
        
    solana_program::program::set_return_data(&result_data);
    Ok(())
}

fn process_sign(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    private_key: [u8; 32],
    message: &[u8],
) -> ProgramResult {
    if message.len() != constants::MESSAGE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Get account info
    let accounts_iter = &mut accounts.iter();
    let signer = next_account_info(accounts_iter)?;
    let signature_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    // Create PDA for signature storage
    let (pda, bump_seed) = Pubkey::find_program_address(
        &[
            b"signature",
            signer.key.as_ref(),
            message.as_ref(),
        ],
        program_id
    );

    // Verify the PDA matches our signature account
    if pda != *signature_account.key {
        return Err(ProgramError::InvalidArgument);
    }

    // Calculate space needed for the account
    let account_size = 1 + // is_initialized
        4 + // Vec length prefix
        (constants::NUM_SIGNATURE_CHUNKS * constants::HASH_LEN); // actual signature data

    // Calculate rent
    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(account_size);

    // Create the account if it doesn't exist
    if signature_account.data_is_empty() {
        let create_account_ix = create_account(
            signer.key,
            &pda,
            rent_lamports,
            account_size as u64,
            program_id,
        );

        invoke_signed(
            &create_account_ix,
            &[
                signer.clone(),
                signature_account.clone(),
                system_program.clone(),
            ],
            &[&[
                b"signature",
                signer.key.as_ref(),
                message.as_ref(),
                &[bump_seed],
            ]],
        )?;
    }

    // Generate the signature
    let wots = WOTSPlus::new(keccak256);
    let signature = wots.sign(&private_key, message);

    // Store the signature in the account
    let signature_account_data = SignatureAccount {
        is_initialized: true,
        signature: signature.to_vec(),
    };

    signature_account_data.serialize(&mut &mut signature_account.try_borrow_mut_data()?[..])?;
    
    Ok(())
}

fn process_verify(
    wots: &WOTSPlus,
    public_key: PublicKeyWrapper,
    message: &[u8],
    signature: Vec<[u8; constants::HASH_LEN]>,
) -> ProgramResult {
    if message.len() != constants::MESSAGE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let public_key = PublicKey::from(public_key);
    let is_valid = wots.verify(&public_key, message, &signature);
    if !is_valid {
        set_return_data(&[0]);
    } else {
        set_return_data(&[1]);
    }
    Ok(())
}

fn process_verify_with_randomization(
    wots: &WOTSPlus,
    public_key_hash: [u8; constants::HASH_LEN],
    message: &[u8],
    signature: Vec<[u8; constants::HASH_LEN]>,
    randomization_elements: Vec<[u8; constants::HASH_LEN]>,
) -> ProgramResult {
    if message.len() != constants::MESSAGE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let is_valid = wots.verify_with_randomization_elements(
        &public_key_hash,
        message,
        &signature,
        &randomization_elements,
    );
    
    if !is_valid {
        set_return_data(&[0]);
    } else {
        set_return_data(&[1]);
    }
    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Only verify signatures for accounts that are marked as signers
    for account_info in accounts.iter() {
        if account_info.is_signer && account_info.signer_key().is_none() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    // Initialize WOTS+ instance
    let wots = WOTSPlus::new(keccak256);

    // Try to deserialize and log any errors
    let instruction = match WOTSPlusInstruction::try_from_slice(instruction_data) {
        Ok(inst) => {
            inst
        },
        Err(e) => {
            msg!("Failed to deserialize instruction: {:?}", e);
            return Err(ProgramError::InvalidInstructionData);
        }
    };

    // Process the instruction with minimal stack usage
    match instruction {
        WOTSPlusInstruction::GenerateKeyPair { private_seed } => {
            process_generate_keypair(&wots, private_seed)
        },
        WOTSPlusInstruction::Sign { private_key, message } => {
            process_sign(program_id, accounts, private_key, &message)
        },
        WOTSPlusInstruction::Verify { public_key, message, signature } => {
            process_verify(&wots, public_key, &message, signature)
        },
        WOTSPlusInstruction::VerifyWithRandomization { 
            public_key_hash, 
            message, 
            signature, 
            randomization_elements 
        } => {
            process_verify_with_randomization(
                &wots,
                public_key_hash,
                &message,
                signature,
                randomization_elements
            )
        }
    }
}
