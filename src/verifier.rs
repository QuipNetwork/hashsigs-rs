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
//! `verify_stateless_envelope`). The same byte-level shape is what EVM signature-verifier contracts
//! consume, so a verifier built to this interface interoperates with them;
//! the name here stays scheme-neutral because the interface is portable.

use crate::types::HASH_LEN;

/// Outcome of a verifier-interface call: a valid signature, a well-formed
/// but rejected one, or an envelope that could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The signature verified. Mirrors returning
    /// `IVerifierInterfaceSignatureVerifier.verify.selector`.
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
