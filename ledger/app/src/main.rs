// Adapted from LedgerHQ/app-boilerplate-rust, copyright 2023 Ledger SAS.
// Modifications copyright 2026 quip.network.
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_std]
#![no_main]

extern crate alloc;

#[cfg(feature = "memory-metrics")]
mod metrics;
mod review;
mod session;
mod wallet;

use alloc::format;
use hashsigs_ledger_common as common;
use ledger_device_sdk::hash::{sha2::Sha2_256, HashInit};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, Reply};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings, NbglSpinner};

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
    Locked = 0x6984,
    UnsupportedMode = 0x6A81,
    UnknownKey = 0x6A88,
    StorageFailure = 0x6581,
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
    #[cfg(feature = "memory-metrics")]
    GetMetrics,
    GetVersion,
    GetAppName,
    GetProfile,
    GetInfo,
    CreateKey,
    GetPublicKey,
    GetState,
    Sha256 {
        confirm: bool,
    },
    BeginVerify,
    WriteVerify {
        offset: u16,
    },
    FinishVerify,
    Cancel,
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    fn try_from(header: ApduHeader) -> Result<Self, Self::Error> {
        match (header.ins, header.p1, header.p2) {
            #[cfg(feature = "memory-metrics")]
            (0xf0, 0, 0) => Ok(Self::GetMetrics),
            (0x03, 0, 0) => Ok(Self::GetVersion),
            (0x04, 0, 0) => Ok(Self::GetAppName),
            (0x05, 0, 0) => Ok(Self::GetProfile),
            (0x06, 0, 0) => Ok(Self::GetInfo),
            (0x30, 0, 0) => Ok(Self::CreateKey),
            (0x31, 0, 0) => Ok(Self::GetPublicKey),
            (0x32, 0, 0) => Ok(Self::GetState),
            (0x10, 0 | 1, 0) => Ok(Self::Sha256 {
                confirm: header.p1 == 1,
            }),
            (0x20, 0, 0) => Ok(Self::BeginVerify),
            (0x21, p1, p2) => Ok(Self::WriteVerify {
                offset: u16::from_be_bytes([p1, p2]),
            }),
            (0x22, 0, 0) => Ok(Self::FinishVerify),
            (0x23, 0, 0) => Ok(Self::Cancel),
            (0x03 | 0x04 | 0x05 | 0x06 | 0x10 | 0x20 | 0x22 | 0x23 | 0x30 | 0x31 | 0x32, _, _) => {
                Err(AppSW::WrongP1P2)
            }
            _ => Err(AppSW::UnsupportedInstruction),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    #[cfg(feature = "memory-metrics")]
    metrics::init();
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xE0);
    let mut home = NbglHomeAndSettings::new().glyph(&ICON).infos(
        "SHRINCS Lab",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    );
    home.show_and_return();
    let mut verification = session::VerificationSession::new();
    let mut wallet = wallet::DeviceWallet::new();

    loop {
        let command = comm.next_command();
        let instruction = match command.decode::<Instruction>() {
            Ok(instruction) => instruction,
            Err(error) => {
                let _ = comm.send(&[], error);
                continue;
            }
        };
        let reviewed = matches!(
            instruction,
            Instruction::Sha256 { confirm: true } | Instruction::CreateKey
        );
        match handle_command(command, instruction, &mut verification, &mut wallet) {
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
    wallet: &mut wallet::DeviceWallet,
) -> Result<io::CommandResponse<'a>, AppSW> {
    match instruction {
        #[cfg(feature = "memory-metrics")]
        Instruction::GetMetrics => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            response.append(&metrics::report())?;
            Ok(response)
        }
        Instruction::GetAppName | Instruction::GetVersion => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            match instruction {
                Instruction::GetAppName => {
                    response.append(env!("CARGO_PKG_NAME").as_bytes())?;
                    #[cfg(feature = "memory-metrics")]
                    response.append(b"-metrics")?;
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
            response.append(&[2])?;
            response.append(&(session::MAX_ENVELOPE as u16).to_be_bytes())?;
            response.append(&hashsigs_rs::shrincs::PROFILE_ID)?;
            response.append(hashsigs_rs::shrincs::PROFILE_NAME.as_bytes())?;
            Ok(response)
        }
        Instruction::GetInfo => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            response.append(&[2, 0, 1])?;
            response.append(&3u32.to_be_bytes())?; // Verify and key management; no signing.
            response.append(&hashsigs_rs::shrincs::PROFILE_ID)?;
            response.append(&wallet.boot_nonce)?;
            response.append(&common::CAPACITY.to_be_bytes())?;
            for value in [
                32,
                session::MAX_ENVELOPE as u16,
                common::PUBLIC_LEN as u16,
                common::MAX_CHUNK as u16,
                1,
            ] {
                response.append(&value.to_be_bytes())?;
            }
            Ok(response)
        }
        Instruction::GetState => {
            if !command.get_data().is_empty() {
                return Err(AppSW::BadData);
            }
            let mut response = command.into_response();
            response.append(&wallet.wallet.state_bytes(verification.is_active()))?;
            Ok(response)
        }
        Instruction::GetPublicKey => {
            let (prefix, chunk) = wallet.public_chunk(command.get_data())?;
            let mut response = command.into_response();
            response.append(&prefix)?;
            response.append(chunk)?;
            Ok(response)
        }
        Instruction::CreateKey => {
            wallet.check_create(command.get_data(), verification.is_active())?;
            // All parameters are now fixed; the UI never reads the APDU buffer.
            let comm = command.into_comm();
            if !review::show(
                comm,
                "Create SHRINCS key?",
                "Experimental key\n4 signatures\nLosing app state means a new public key",
                "Create key",
                "Reject",
            ) {
                return Err(AppSW::Denied);
            }
            let mut spinner = NbglSpinner::new();
            spinner.show("Generating SHRINCS key");
            wallet.create()?;
            let id = wallet.wallet.identity().ok_or(AppSW::InternalError)?;
            let detail = format!("Commitment\n{}", hex::encode(id.commitment));
            // Both buttons acknowledge an already durable identity; neither can
            // undo creation. Recovery after a lost reply uses GET_STATE.
            review::show(comm, "Key created", &detail, "Done", "Close");
            let mut response = comm.begin_response();
            response.append(&id.commitment)?;
            response.append(&(common::PUBLIC_LEN as u16).to_be_bytes())?;
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
            if verification.is_active() {
                return Err(AppSW::BadState);
            }
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
                if !review::show(comm, "Approve test hash?", &detail, "Approve", "Reject") {
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
