// SPDX-License-Identifier: AGPL-3.0-or-later
//! Available only in the separately named hardware-check application.
use crate::{review, session::VerificationSession, wallet::DeviceWallet, AppSW};
use core::sync::atomic::{AtomicU32, Ordering};
use ledger_device_sdk::{
    io::{self, ApduHeader, Command},
    random::rand_bytes,
};
use zeroize::Zeroizing;

static LEAVES: AtomicU32 = AtomicU32::new(0);
static POLLS: AtomicU32 = AtomicU32::new(0);
static BUSY: AtomicU32 = AtomicU32::new(0);
static WRITES: AtomicU32 = AtomicU32::new(0);
pub fn leaf() {
    LEAVES.fetch_add(1, Ordering::Relaxed);
}
pub fn poll() {
    POLLS.fetch_add(1, Ordering::Relaxed);
}
pub fn busy_reply() {
    BUSY.fetch_add(1, Ordering::Relaxed);
}
pub fn nvm_write() {
    WRITES.fetch_add(1, Ordering::Relaxed);
}
pub fn reset_progress() {
    for value in [&LEAVES, &POLLS, &BUSY] {
        value.store(0, Ordering::Relaxed);
    }
}

pub(super) enum Instruction {
    Probe(u8),
    Report,
    Arm,
    Execute,
    Benchmark,
}
impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;
    fn try_from(h: ApduHeader) -> Result<Self, AppSW> {
        match (h.ins, h.p1, h.p2) {
            (0xf1, probe @ 0..=6, 0) => Ok(Self::Probe(probe)),
            (0xf2, 0, 0) => Ok(Self::Report),
            (0xf3, 0, 0) => Ok(Self::Arm),
            (0xf4, 0, 0) => Ok(Self::Execute),
            (0xf5, 0, 0) => Ok(Self::Benchmark),
            _ => Err(AppSW::WrongP1P2),
        }
    }
}

pub fn handle<'a>(
    command: Command<'a>,
    instruction: Instruction,
    verification: &VerificationSession,
    wallet: &mut DeviceWallet,
) -> Result<io::CommandResponse<'a>, AppSW> {
    if verification.is_active() {
        return Err(AppSW::BadState);
    }
    match instruction {
        Instruction::Arm => {
            wallet.check_create(command.get_data(), false)?;
            let comm = command.into_comm();
            if !review::show(
                comm,
                "Create SHRINCS key?",
                "Hardware test app\n4 signatures\nApproval arms one timed creation",
                "Create key",
                "Reject",
            ) {
                return Err(AppSW::Denied);
            }
            let mut token = Zeroizing::new([0; 16]);
            rand_bytes(&mut *token);
            if *token == [0; 16] {
                return Err(AppSW::InternalError);
            }
            let mut response = comm.begin_response();
            response.append(&token[..])?;
            wallet.measurement_token = Some(token);
            Ok(response)
        }
        Instruction::Execute => {
            // Consume even on malformed/wrong tokens. Approval cannot be replayed.
            let token = wallet.measurement_token.take().ok_or(AppSW::BadState)?;
            if command.get_data() != &token[..] {
                return Err(AppSW::BadState);
            }
            if wallet.wallet.state() != hashsigs_ledger_common::State::Empty {
                return Err(AppSW::BadState);
            }
            let comm = command.into_comm();
            wallet.create(comm)?;
            let id = wallet.wallet.identity().ok_or(AppSW::InternalError)?;
            let mut response = comm.begin_response();
            response.append(&id.commitment)?;
            response.append(&480u16.to_be_bytes())?;
            Ok(response)
        }
        Instruction::Benchmark => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let comm = command.into_comm();
            let commitment = wallet.benchmark(comm)?;
            let mut response = comm.begin_response();
            response.append(&commitment)?;
            Ok(response)
        }
        Instruction::Probe(id) => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            unsafe extern "C" {
                fn hardware_probe(id: u32, status: *mut u32, flags: *mut u8);
            }
            let mut status = 0;
            let mut flags = [0; 2];
            unsafe {
                hardware_probe(id as u32, &mut status, flags.as_mut_ptr());
            }
            let mut response = command.into_response();
            response.append(&[1, id])?;
            response.append(&status.to_be_bytes())?;
            response.append(&flags)?;
            Ok(response)
        }
        Instruction::Report => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let fingerprint = wallet.storage_fingerprint()?;
            let mut response = command.into_response();
            response.append(&[1])?;
            for value in [&LEAVES, &POLLS, &BUSY, &WRITES] {
                response.append(&value.load(Ordering::Relaxed).to_be_bytes())?;
            }
            response.append(&fingerprint)?;
            Ok(response)
        }
    }
}
