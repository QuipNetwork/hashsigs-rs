// SPDX-License-Identifier: AGPL-3.0-or-later
//! SDK launch/exit control: no derivation, scheme code, or application NVM.
#![no_std]
#![no_main]

use ledger_device_sdk::{
    include_gif,
    io::{init_comm, ApduHeader, Reply},
    nbgl::{NbglGlyph, NbglHomeAndSettings},
};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);
const ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("../app/glyphs/crab_48x48.png", NBGL));

enum Instruction {
    Version,
    Name,
}
struct Status(u16);
impl From<Status> for Reply {
    fn from(status: Status) -> Self {
        Self(status.0)
    }
}
impl TryFrom<ApduHeader> for Instruction {
    type Error = Status;
    fn try_from(header: ApduHeader) -> Result<Self, Self::Error> {
        match (header.ins, header.p1, header.p2) {
            (3, 0, 0) => Ok(Self::Version),
            (4, 0, 0) => Ok(Self::Name),
            (3 | 4, _, _) => Err(Status(0x6a86)),
            _ => Err(Status(0x6d00)),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xe3);
    let mut home = NbglHomeAndSettings::new().glyph(&ICON).infos(
        "SHRINCS Launch",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    );
    home.show_and_return();
    loop {
        let command = comm.next_command();
        let instruction = match command.decode::<Instruction>() {
            Ok(value) => value,
            Err(status) => {
                let _ = comm.send(&[], status);
                continue;
            }
        };
        if !command.get_data().is_empty() {
            let _ = comm.send(&[], Status(0x6a80));
            continue;
        }
        let data: &[u8] = match instruction {
            Instruction::Version => &[0, 1, 0],
            Instruction::Name => env!("CARGO_PKG_NAME").as_bytes(),
        };
        let mut response = command.into_response();
        if response.append(data).is_ok() {
            let _ = response.send(Status(0x9000));
        }
    }
}
