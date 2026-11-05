// SPDX-License-Identifier: AGPL-3.0-or-later
//! Disposable PUBLIC-fixture storage diagnostics. No wallet seed or signing.
#![no_std]
#![no_main]
mod storage;

use hashsigs_ledger_common::{diagnostics, Error, State, Wallet};
use ledger_device_sdk::{
    include_gif,
    io::{init_comm, ApduHeader, Reply},
    nbgl::{NbglGlyph, NbglHomeAndSettings},
    random::rand_bytes,
};
use storage::{DeviceCrypto, DeviceStorage};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);
const ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("../app/glyphs/crab_48x48.png", NBGL));
const RECORDS: &[u8; 2048] = include_bytes!("../fixtures.bin");
const PUBLIC_MAC_KEY: [u8; 32] = [7; 32];

enum Instruction {
    Status,
    Prepare(u8),
    Run(u8, u8),
}
impl TryFrom<ApduHeader> for Instruction {
    type Error = Reply;
    fn try_from(h: ApduHeader) -> Result<Self, Reply> {
        match (h.ins, h.p1, h.p2) {
            (0x02, 0, 0) => Ok(Self::Status),
            (0x10, source @ (0 | 1 | 4), 0) => Ok(Self::Prepare(source)),
            (0x11, target @ (1 | 2 | 5), cut @ 0..=9) => Ok(Self::Run(target, cut)),
            (0x02 | 0x10 | 0x11, _, _) => Err(Reply(0x6a86)),
            _ => Err(Reply(0x6d00)),
        }
    }
}
fn record(next: u8) -> &'static [u8; 512] {
    let index = match next {
        1 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        _ => unreachable!(),
    };
    RECORDS[index * 512..(index + 1) * 512].try_into().unwrap()
}
fn load() -> Wallet {
    Wallet::load(&DeviceStorage, &DeviceCrypto, &PUBLIC_MAC_KEY)
}

fn prepare(source: u8) -> Result<(), Error> {
    for (page, bytes) in [
        (0, &[0x3c; 512]),
        (3, &[0xc3; 512]),
        (1, &[0; 512]),
        (2, &[0; 512]),
    ] {
        DeviceStorage::write_page(page, bytes)?;
        if DeviceStorage::read_page(page) != *bytes {
            return Err(Error::Storage);
        }
    }
    if source != 0 {
        diagnostics::commit(
            &mut DeviceStorage,
            &DeviceCrypto,
            &PUBLIC_MAC_KEY,
            record(source),
            |_| Ok(()),
        )?;
    }
    Ok(())
}

fn run(target: u8, cut: u8, stage: &mut u8) -> Result<(), Error> {
    let wallet = load();
    let valid_source = match target {
        1 => wallet.state() == State::Empty,
        2 => wallet.identity().is_some_and(|id| id.next_leaf == 1),
        5 => wallet.identity().is_some_and(|id| id.next_leaf == 4),
        _ => false,
    };
    if !valid_source || DeviceStorage::guards() != 3 {
        return Err(Error::BadState);
    }
    *stage = 0;
    let result = diagnostics::commit(
        &mut DeviceStorage,
        &DeviceCrypto,
        &PUBLIC_MAC_KEY,
        record(target),
        |point| {
            if point == cut {
                *stage = point;
                Err(Error::Storage)
            } else {
                Ok(())
            }
        },
    );
    if *stage == cut && cut != 0 && result.is_err() {
        return Ok(());
    }
    result?;
    *stage = 10;
    Ok(())
}

fn status(nonce: &[u8; 16], stage: u8) -> Result<[u8; 203], Error> {
    let mut out = [0; 203];
    out[..8].copy_from_slice(b"NVM-DIAG");
    out[8..11].copy_from_slice(&[0, 1, 0]);
    out[11] = stage;
    out[12] = DeviceStorage::guards();
    out[13..29].copy_from_slice(nonce);
    out[29..139].copy_from_slice(&load().state_bytes(false));
    out[139..171].copy_from_slice(&DeviceStorage::digest(1)?);
    out[171..203].copy_from_slice(&DeviceStorage::digest(2)?);
    Ok(out)
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xe1);
    let mut home = NbglHomeAndSettings::new().glyph(&ICON).infos(
        "SHRINCS NVM Diag",
        env!("CARGO_PKG_VERSION"),
        "PUBLIC fixtures only",
    );
    home.show_and_return();
    let mut nonce = [0; 16];
    rand_bytes(&mut nonce);
    let mut stage = 0;
    loop {
        let command = comm.next_command();
        let instruction = match command.decode::<Instruction>() {
            Ok(value) => value,
            Err(error) => {
                let _ = comm.send(&[], error);
                continue;
            }
        };
        if !command.get_data().is_empty() {
            let _ = comm.send(&[], Reply(0x6a80));
            continue;
        }
        let result = match instruction {
            Instruction::Status => Ok(()),
            Instruction::Prepare(source) => {
                stage = 0;
                prepare(source)
            }
            Instruction::Run(target, cut) => run(target, cut, &mut stage),
        };
        match result.and_then(|_| status(&nonce, stage)) {
            Ok(bytes) => {
                let _ = comm.send(&bytes, Reply(0x9000));
            }
            Err(error) => {
                let _ = comm.send(
                    &[],
                    Reply(if error == Error::BadState {
                        0x6986
                    } else {
                        0x6581
                    }),
                );
            }
        }
    }
}
