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

mod abi;
mod addresses;
mod helpers;
mod wire;

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
