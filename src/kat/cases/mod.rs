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

//! The case catalog: one function for each replay group.

use alloc::vec::Vec;

use super::group::Group;
use crate::hash::backend::keccak256v;
use crate::sphincs_plus_c::{keygen, sign, Key, Signature as StatelessSignature};

mod abi;
mod addresses;
mod envelopes;
mod fors;
pub(crate) mod golden;
mod helpers;
mod hypertree;
mod shrincs;
mod uxmss;
mod wire;
mod wots_c;

/// The profile of the full-size groups.
pub(crate) type Full = crate::profiles::p256s::Profile256s;

/// Builds one group.
pub type Builder = fn() -> Group;

/// Every group, by name, in replay order.
pub fn catalog() -> Vec<(&'static str, Builder)> {
    alloc::vec![
        ("helpers", helpers::group as Builder),
        ("abi", abi::group),
        ("addresses", addresses::group),
        ("wots_c", wots_c::group),
        ("uxmss", uxmss::group),
        ("fors", fors::group),
        ("toy_fors", fors::toy_group),
        ("hypertree", hypertree::group),
        ("toy_sphincs", hypertree::toy_group),
        ("envelopes", envelopes::group),
        ("toy_envelopes", envelopes::toy_group),
        ("shrincs", shrincs::group),
        ("toy_shrincs", shrincs::toy_group),
    ]
}

/// Deterministic test input: Keccak-256 in counter mode over a label. The
/// recorder is not armed while a case builds its inputs.
pub(crate) fn label_bytes(label: &str, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 32);
    let mut counter = 0u32;
    while out.len() < size {
        out.extend_from_slice(&keccak256v(&[
            b"hashsigs-kat/",
            label.as_bytes(),
            &counter.to_be_bytes(),
        ]));
        counter += 1;
    }
    out.truncate(size);
    out
}

/// A 32-byte deterministic test input.
pub(crate) fn label_word(label: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&label_bytes(label, 32));
    out
}

/// A grind of the Rust code found no counter for a fixed test input. That
/// happens with a negligible probability, and the generator then stops.
pub(crate) fn grind_failed<T>() -> T {
    eprintln!("a grind found no counter for a fixed test input");
    std::process::exit(2)
}

/// One full-size stateless key, message, and signature, computed once per
/// run with the recorder unarmed. Signing costs about three million Keccak
/// calls, which no replay can afford, so the groups replay only verification.
pub(crate) fn full_stateless() -> &'static (Key, Vec<u8>, StatelessSignature) {
    static CELL: std::sync::OnceLock<(Key, Vec<u8>, StatelessSignature)> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let key = keygen::<Full, 8>(
            label_word("full/sk"),
            label_word("full/prf"),
            label_word("full/pk"),
        );
        let message = label_bytes("full/message", 32);
        let signature = sign::<Full, 8>(&key, &message).unwrap_or_else(grind_failed);
        (key, message, signature)
    })
}
