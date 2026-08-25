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

//! The `hashsigs` package's root extension: package-wide metadata.
//!
//! The signing surface lives in one extension per profile, under
//! `hashsigs._ext`, built from the crates in `py/profiles/`. This module is
//! what maturin compiles for the wheel. It carries the version, so
//! `hashsigs.__version__` comes from the same Cargo manifest maturin derives
//! the wheel version from rather than a second copy in Python, and the error
//! codes, so the Python layer does not restate an enum that lives in Rust.
use hashsigs_rs::ErrorCode;
use pyo3::prelude::*;

#[pymodule]
fn _hashsigs(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    // Every code `HashSigsError.code` can carry, taken from the Rust enum that
    // produces them. A hand-copied list in Python would drift silently: a code
    // added in Rust and missing here would still reach callers.
    module.add(
        "ERROR_CODES",
        ErrorCode::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
    )?;
    Ok(())
}
