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

//! The verifier interface: opaque key bytes plus a 32-byte message hash and
//! an opaque signature envelope, returning a tri-state verdict. Both schemes
//! implement it: [`crate::sphincs_plus_c::SphincsPlusCVerifier`] (64-byte
//! `pkSeed || hypertreeRoot` key, stateless signature envelope) and
//! [`crate::shrincs::ShrincsVerifier`] (32-byte public-key commitment,
//! stateful envelope; its stateless delegation path is the inherent
//! `verify_stateless_envelope`). On EVM the same shape is standardized as
//! ERC-7913 (`verify(bytes,bytes32,bytes) -> bytes4`); the name here is
//! generic because the interface is portable beyond the EVM.

use crate::types::HASH_LEN;

/// Outcome of a verifier-interface call. On EVM this maps onto ERC-7913's
/// magic-value / `0xffffffff` / revert tri-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The signature verified. Mirrors returning
    /// `IERC7913SignatureVerifier.verify.selector`.
    Valid,
    /// A well-formed envelope carrying a cryptographically invalid
    /// signature, or a key that is not exactly 32 bytes. Mirrors returning
    /// `0xffffffff`.
    Invalid,
    /// The envelope's ABI framing could not be decoded at all. Mirrors a
    /// Solidity revert (the calldata re-tag's member-access failure) — there
    /// is no revert here, so callers must treat this as a hard reject, the
    /// same way they would an unexpected revert.
    Malformed,
}

/// A verifier that checks an opaque signature envelope by an opaque key over
/// a 32-byte message hash.
pub trait VerifierInterface {
    fn verify_envelope(&self, key: &[u8], hash: &[u8; HASH_LEN], signature: &[u8])
        -> VerifyOutcome;
}
