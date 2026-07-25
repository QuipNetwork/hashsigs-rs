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

//! SHRINCS action context: the caller-controlled binding fields hashed into
//! every stateful/stateless action-verify message
//! (`dispatch::stateful_action_message_hash` /
//! `dispatch::stateless_action_message_hash`).

use crate::HASH_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionContext {
    /// Caller-controlled domain separation, normally binding account/program identity.
    pub domain_separator: [u8; HASH_LEN],
    /// Replay-protection nonce encoded as Solidity-style uint256 bytes.
    pub nonce: [u8; HASH_LEN],
    /// Current key version encoded as Solidity-style uint256 bytes.
    pub key_version: [u8; HASH_LEN],
    /// Application-specific action identifier.
    pub action_type: [u8; HASH_LEN],
    /// Hash of the action payload being authorized.
    pub payload_hash: [u8; HASH_LEN],
}
