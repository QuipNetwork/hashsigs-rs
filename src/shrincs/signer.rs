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

//! Compatibility signer entrypoint.
//!
//! Public signer surfaces now live under `shrincs::signers::*`. This module
//! preserves the frozen `hashsigs_rs::shrincs::signer::*` path by re-exporting
//! the same types.

pub use super::signers::shrincs_signer::{ShrincsSigner, ShrincsSignerResult, ShrincsSigningKey};
pub use super::verifier;
