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

//! The `128s-q20-sha2` SHRINCS profile as a Python extension module.
//!
//! One Cargo package builds at most one `cdylib`, so each profile needs its
//! own crate. Everything below the macro lives once, in `hashsigs-py-common`
//! and `hashsigs_rs::bindings`.

hashsigs_py_common::python_profile_surface!(
    _hashsigs_p128s_q20_sha2,
    hashsigs_rs::profiles::p128s_q20_sha2::Profile128sQ20Sha2,
    32,
    1
);
