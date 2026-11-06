// SPDX-License-Identifier: AGPL-3.0-or-later
//! Full-budget keygen timing. Fresh device randomness; no secret export or NVM.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../app/src/metrics.rs"]
mod metrics;
#[path = "../../app/src/review.rs"]
mod review;

use alloc::{format, vec::Vec};
use hashsigs_rs::{
    profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS},
    shrincs::{ShrincsSigner, PROFILE_ID},
};
use ledger_device_sdk::{
    include_gif,
    io::{self, init_comm, ApduHeader, Comm, Command, Reply},
    nbgl::{NbglGlyph, NbglHomeAndSettings, NbglSpinner},
    random::rand_bytes,
};
use zeroize::Zeroizing;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);
const ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("../app/glyphs/crab_48x48.png", NBGL));
const CAPACITY: u32 = 4096;
const TOTAL_LEAVES: u32 = 256 + CAPACITY;

#[cfg(feature = "hardware-tests")]
compile_error!("keygen-bench does not expose the HW Check diagnostics");

#[repr(u16)]
#[derive(Clone, Copy)]
enum AppSW {
    Ok = 0x9000,
    Denied = 0x6985,
    BadState = 0x6986,
    BadData = 0x6a80,
    WrongP1P2 = 0x6a86,
    UnsupportedInstruction = 0x6d00,
    InternalError = 0x6f00,
}
impl From<AppSW> for Reply {
    fn from(value: AppSW) -> Self {
        Self(value as u16)
    }
}
impl From<io::CommError> for AppSW {
    fn from(_: io::CommError) -> Self {
        Self::InternalError
    }
}

enum Instruction {
    Version,
    Name,
    Info,
    Metrics,
    Public,
    Arm,
    Execute,
}
impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;
    fn try_from(h: ApduHeader) -> Result<Self, AppSW> {
        if h.p1 != 0 || h.p2 != 0 {
            return Err(AppSW::WrongP1P2);
        }
        match h.ins {
            3 => Ok(Self::Version),
            4 => Ok(Self::Name),
            6 => Ok(Self::Info),
            0xf0 => Ok(Self::Metrics),
            0x31 => Ok(Self::Public),
            0xf3 => Ok(Self::Arm),
            0xf4 => Ok(Self::Execute),
            _ => Err(AppSW::UnsupportedInstruction),
        }
    }
}

#[derive(Default)]
struct Benchmark {
    token: Option<Zeroizing<[u8; 16]>>,
    public: Vec<u8>,
    commitment: [u8; 32],
    leaves: u32,
    polls: u32,
}

// Keep the main loop and review frames out of the core keygen frame.
#[inline(never)]
fn generate<const N: usize>(
    state: &mut Benchmark,
    comm: &mut Comm<N>,
    spinner: &mut NbglSpinner,
) -> Result<(), AppSW> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_bytes(&mut *seed);
    spinner.show("Keygen: 0 / 4352");
    let (keys, public) = ShrincsSigner::keygen_with_progress::<
        SelectedProfile,
        NUM_CHAINS,
        NUM_LAYERS,
    >(&seed[..], CAPACITY, || {
        state.leaves += 1;
        if state.leaves % 64 == 0 {
            spinner.show(&format!("Keygen: {} / {}", state.leaves, TOTAL_LEAVES));
        }
        if state.leaves % 4 == 0 {
            state.polls += 1;
            review::busy_event(comm);
        }
    })
    .ok_or(AppSW::InternalError)?;
    state
        .commitment
        .copy_from_slice(&public.public_key_commitment);
    state.public = public.to_bytes();
    // The core's secret owners zeroize on drop; this benchmark saves no key.
    drop(keys);
    if state.leaves != TOTAL_LEAVES || state.public.len() != 480 {
        return Err(AppSW::InternalError);
    }
    Ok(())
}

#[inline(never)]
fn handle<'a>(
    command: Command<'a>,
    instruction: Instruction,
    state: &mut Benchmark,
    spinner: &mut NbglSpinner,
) -> Result<io::CommandResponse<'a>, AppSW> {
    if !matches!(instruction, Instruction::Execute | Instruction::Public)
        && !command.get_data().is_empty()
    {
        return Err(AppSW::BadData);
    }
    match instruction {
        Instruction::Arm => {
            if !state.public.is_empty() {
                return Err(AppSW::BadState);
            }
            let comm = command.into_comm();
            if !review::show(
                comm,
                "Benchmark full key?",
                "4096 stateful signatures\nMay take 20 minutes\nTest key is not saved",
                "Start benchmark",
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
            state.token = Some(token);
            Ok(response)
        }
        Instruction::Execute => {
            let token = state.token.take().ok_or(AppSW::BadState)?;
            if command.get_data() != &token[..] || !state.public.is_empty() {
                return Err(AppSW::BadState);
            }
            let comm = command.into_comm();
            generate(state, comm, spinner)?;
            let mut response = comm.begin_response();
            response.append(&state.commitment)?;
            response.append(&state.leaves.to_be_bytes())?;
            response.append(&state.polls.to_be_bytes())?;
            response.append(&metrics::report())?;
            Ok(response)
        }
        Instruction::Public => {
            let data = command.get_data();
            if data.len() != 3 || data[2] == 0 || data[2] > 200 {
                return Err(AppSW::BadData);
            }
            let offset = u16::from_be_bytes([data[0], data[1]]) as usize;
            let end = offset + data[2] as usize;
            let bytes = state.public.get(offset..end).ok_or(AppSW::BadData)?;
            let mut response = command.into_response();
            response.append(bytes)?;
            Ok(response)
        }
        _ => {
            let mut response = command.into_response();
            match instruction {
                Instruction::Version => {
                    response.append(&[0, 1, 0])?;
                }
                Instruction::Name => {
                    response.append(env!("CARGO_PKG_NAME").as_bytes())?;
                }
                Instruction::Info => {
                    response.append(&PROFILE_ID)?;
                    response.append(&CAPACITY.to_be_bytes())?;
                    response.append(&TOTAL_LEAVES.to_be_bytes())?;
                }
                Instruction::Metrics => {
                    response.append(&metrics::report())?;
                }
                _ => unreachable!(),
            }
            Ok(response)
        }
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    metrics::init();
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xe4);
    let mut home = NbglHomeAndSettings::new()
        .glyph(&ICON)
        .tagline("Full-budget key generation benchmark. Test keys are not saved.")
        .infos(
            "SHRINCS Keygen",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        );
    // Keep the spinner's text alive until the home screen replaces it.
    let mut spinner = NbglSpinner::new();
    let mut state = Benchmark::default();
    home.show_and_return();
    loop {
        let command = comm.next_command();
        let instruction = match command.decode::<Instruction>() {
            Ok(value) => value,
            Err(error) => {
                state.token = None;
                let _ = comm.send(&[], error);
                continue;
            }
        };
        if !matches!(instruction, Instruction::Execute) {
            state.token = None;
        }
        let show_home = matches!(instruction, Instruction::Arm | Instruction::Execute);
        match handle(command, instruction, &mut state, &mut spinner) {
            Ok(response) => {
                let _ = response.send(AppSW::Ok);
            }
            Err(error) => {
                let _ = comm.send(&[], error);
            }
        }
        if show_home {
            home.show_and_return();
        }
    }
}
