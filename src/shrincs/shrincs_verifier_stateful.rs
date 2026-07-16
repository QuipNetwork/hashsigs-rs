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

//! Compatibility wrapper for the UXMSS component verifier path.

use super::super::components::uxmss;
use super::super::types::{PublicKey, StatefulSignature, HASH_LEN};

pub(crate) fn verify_stateful_unsafe_raw(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &PublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    uxmss::verify_stateful_unsafe_raw(
        expected_public_key_commitment,
        public_key,
        message,
        signature,
    )
}
