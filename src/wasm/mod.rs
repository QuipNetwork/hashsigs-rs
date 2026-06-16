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

//! WASM-oriented surface for `hashsigs-rs`.
//!
//! This module stays thin on purpose. It re-exports the verifier-facing WOTS+
//! and SHRINCS APIs now, and can later grow dedicated `wasm-bindgen` bindings
//! without moving the core cryptographic logic out of the main crate.

pub use crate::shrincs;
pub use crate::wotsplus;
