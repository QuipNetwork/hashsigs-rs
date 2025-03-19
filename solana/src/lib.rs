#![allow(unexpected_cfgs)]

pub mod processor;

use crate::processor::process_instruction;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);
