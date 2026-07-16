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

//! Compatibility wrapper for the FORS-C component verifier path.

use super::super::components::fors_c;
use super::super::types::{ForsSignature, PublicKey, HASH_LEN};

pub(crate) fn verify_fors_c_and_return_root(
    public_key: &PublicKey,
    message: &[u8],
    signature: &ForsSignature,
) -> Option<([u8; HASH_LEN], u64, u32)> {
    fors_c::verify_fors_c_and_return_root(public_key, message, signature)
}
