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

//! Signer result alias.
//!
//! Kept separate from `signer.rs` for historical reasons (it used to also
//! define `ShrincsSigningKey`, now replaced by the composed
//! [`crate::shrincs::keys::Keys`]).

/// Signer operations return `None` when stateful leaves are exhausted or
/// WOTS-C/FORS-C grinding fails within the configured counter budget.
pub type ShrincsSignerResult<T> = Option<T>;
