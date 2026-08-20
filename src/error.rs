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

//! The machine-readable error taxonomy every binding shares.
//!
//! These codes cross three language boundaries. JavaScript reads them as
//! `error.code` strings, C maps them to `hashsigs_status` integers, and
//! Python maps them to exception classes. The string spelling is published
//! API and is frozen: additions are safe, renames and removals are breaking.
//!
//! The enum is deliberately NOT `#[non_exhaustive]`. Exhaustive matching is
//! the point: a new variant must fail every binding's build until that
//! binding handles it.

/// A machine-readable failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A fixed-width input had the wrong length.
    BadLength,
    /// The stateful key has no unused one-time leaves left.
    StatefulLeavesExhausted,
    /// A signature envelope could not be decoded.
    EnvelopeMalformed,
    /// Signing failed for the supplied inputs.
    SigningFailed,
    /// Key derivation failed for the supplied inputs.
    KeygenFailed,
    /// An argument was outside its permitted range.
    InvalidInput,
    /// An imported key failed its consistency check.
    ImportInvalid,
}

impl ErrorCode {
    /// Every variant, in declaration order. Bindings iterate this to build
    /// their own tables, so a new variant reaches them without a second edit.
    pub const ALL: [ErrorCode; 7] = [
        ErrorCode::BadLength,
        ErrorCode::StatefulLeavesExhausted,
        ErrorCode::EnvelopeMalformed,
        ErrorCode::SigningFailed,
        ErrorCode::KeygenFailed,
        ErrorCode::InvalidInput,
        ErrorCode::ImportInvalid,
    ];

    /// The published string form. Frozen API.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadLength => "ERR_BAD_LENGTH",
            ErrorCode::StatefulLeavesExhausted => "ERR_STATEFUL_LEAVES_EXHAUSTED",
            ErrorCode::EnvelopeMalformed => "ERR_ENVELOPE_MALFORMED",
            ErrorCode::SigningFailed => "ERR_SIGNING_FAILED",
            ErrorCode::KeygenFailed => "ERR_KEYGEN_FAILED",
            ErrorCode::InvalidInput => "ERR_INVALID_INPUT",
            ErrorCode::ImportInvalid => "ERR_IMPORT_INVALID",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn as_str_matches_the_published_wasm_strings() {
        assert_eq!(ErrorCode::BadLength.as_str(), "ERR_BAD_LENGTH");
        assert_eq!(
            ErrorCode::StatefulLeavesExhausted.as_str(),
            "ERR_STATEFUL_LEAVES_EXHAUSTED"
        );
        assert_eq!(
            ErrorCode::EnvelopeMalformed.as_str(),
            "ERR_ENVELOPE_MALFORMED"
        );
        assert_eq!(ErrorCode::SigningFailed.as_str(), "ERR_SIGNING_FAILED");
        assert_eq!(ErrorCode::KeygenFailed.as_str(), "ERR_KEYGEN_FAILED");
        assert_eq!(ErrorCode::InvalidInput.as_str(), "ERR_INVALID_INPUT");
        assert_eq!(ErrorCode::ImportInvalid.as_str(), "ERR_IMPORT_INVALID");
    }

    #[test]
    fn all_lists_every_variant_exactly_once() {
        let mut seen: alloc::vec::Vec<&'static str> =
            ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, 7, "ALL must hold seven codes");
        assert_eq!(seen.len(), 7, "two variants share one string");
    }
}
