// Adapted from LedgerHQ/app-boilerplate-rust, copyright 2023 Ledger SAS.
// Modifications copyright 2026 quip.network.
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_std]
#![no_main]

extern crate alloc;

mod session;

use alloc::format;
use ledger_device_sdk::hash::{sha2::Sha2_256, HashInit};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, Reply};
use ledger_device_sdk::nbgl::{NbglChoice, NbglGlyph, NbglHomeAndSettings};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

const ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/crab_48x48.png", NBGL));

#[repr(u16)]
#[derive(Clone, Copy)]
enum AppSW {
    Ok = 0x9000,
    Denied = 0x6985,
    BadState = 0x6986,
    BadData = 0x6A80,
    WrongP1P2 = 0x6A86,
    UnsupportedInstruction = 0x6D00,
    InternalError = 0x6F00,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Self {
        Reply(sw as u16)
    }
}

impl From<io::CommError> for AppSW {
    fn from(_: io::CommError) -> Self {
        Self::InternalError
    }
}

enum Instruction {
    GetVersion,
    GetAppName,
    GetProfile,
    Sha256 { confirm: bool },
    BeginVerify,
    WriteVerify { offset: u16 },
    FinishVerify,
    Cancel,
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    fn try_from(header: ApduHeader) -> Result<Self, Self::Error> {
        match (header.ins, header.p1, header.p2) {
            (0x03, 0, 0) => Ok(Self::GetVersion),
            (0x04, 0, 0) => Ok(Self::GetAppName),
            (0x05, 0, 0) => Ok(Self::GetProfile),
            (0x10, 0 | 1, 0) => Ok(Self::Sha256 {
                confirm: header.p1 == 1,
            }),
            (0x20, 0, 0) => Ok(Self::BeginVerify),
            (0x21, p1, p2) => Ok(Self::WriteVerify {
                offset: u16::from_be_bytes([p1, p2]),
            }),
            (0x22, 0, 0) => Ok(Self::FinishVerify),
            (0x23, 0, 0) => Ok(Self::Cancel),
            (0x03 | 0x04 | 0x05 | 0x10 | 0x20 | 0x22 | 0x23, _, _) => Err(AppSW::WrongP1P2),
            _ => Err(AppSW::UnsupportedInstruction),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xE0);
    let mut home = NbglHomeAndSettings::new().glyph(&ICON).infos(
        "SHRINCS Lab",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    );
    home.show_and_return();
    let mut verification = session::VerificationSession::new();

    loop {
        let command = comm.next_command();
        let instruction = match command.decode::<Instruction>() {
            Ok(instruction) => instruction,
            Err(error) => {
                let _ = comm.send(&[], error);
                continue;
            }
        };
        let reviewed = matches!(instruction, Instruction::Sha256 { confirm: true });
        match handle_command(command, instruction, &mut verification) {
            Ok(response) => {
                let _ = response.send(AppSW::Ok);
            }
            Err(error) => {
                let _ = comm.send(&[], error);
            }
        }
        if reviewed {
            home.show_and_return();
        }
    }
}

fn handle_command<'a>(
    command: Command<'a>,
    instruction: Instruction,
    verification: &mut session::VerificationSession,
) -> Result<io::CommandResponse<'a>, AppSW> {
    match instruction {
        Instruction::GetAppName | Instruction::GetVersion => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            match instruction {
                Instruction::GetAppName => {
                    response.append(env!("CARGO_PKG_NAME").as_bytes())?;
                }
                _ => {
                    let mut version = [0u8; 3];
                    for (slot, part) in version.iter_mut().zip(env!("CARGO_PKG_VERSION").split('.'))
                    {
                        *slot = part.parse().map_err(|_| AppSW::InternalError)?;
                    }
                    response.append(&version)?;
                }
            }
            Ok(response)
        }
        Instruction::GetProfile => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            response.append(&[1])?;
            response.append(&(session::MAX_ENVELOPE as u16).to_be_bytes())?;
            response.append(&hashsigs_rs::shrincs::PROFILE_ID)?;
            response.append(hashsigs_rs::shrincs::PROFILE_NAME.as_bytes())?;
            Ok(response)
        }
        Instruction::BeginVerify => {
            let id = verification.begin(command.get_data())?;
            let mut response = command.into_response();
            response.append(&id)?;
            Ok(response)
        }
        Instruction::WriteVerify { offset } => {
            let received = verification.write(offset, command.get_data())?;
            let mut response = command.into_response();
            response.append(&received)?;
            Ok(response)
        }
        Instruction::FinishVerify => {
            let result = verification.finish(command.get_data())?;
            let mut response = command.into_response();
            response.append(&[result])?;
            Ok(response)
        }
        Instruction::Cancel => {
            verification.cancel(command.get_data())?;
            Ok(command.into_response())
        }
        Instruction::Sha256 { confirm } => {
            let data = command.get_data();
            let length = data.len();
            let mut digest = [0u8; 32];
            Sha2_256::new()
                .hash(data, &mut digest)
                .map_err(|_| AppSW::InternalError)?;

            // Freeze the digest before entering the UI; no secret keys or signing are involved.
            let mut response = if confirm {
                let mut hex_digest = [0u8; 64];
                hex::encode_to_slice(digest, &mut hex_digest).map_err(|_| AppSW::InternalError)?;
                let hex_digest =
                    core::str::from_utf8(&hex_digest).map_err(|_| AppSW::InternalError)?;
                let detail = format!("{} bytes\nSHA-256\n{}", length, hex_digest);
                let comm = command.into_comm();
                if !NbglChoice::new().glyph(&ICON).show(
                    comm,
                    "Approve test hash?",
                    &detail,
                    "Approve",
                    "Reject",
                ) {
                    return Err(AppSW::Denied);
                }
                comm.begin_response()
            } else {
                command.into_response()
            };
            response.append(&digest)?;
            Ok(response)
        }
    }
}
