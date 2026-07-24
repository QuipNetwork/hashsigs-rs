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

//! Historical home of the EVM envelope codec. All of it has relocated to
//! its byte-neutral home: the per-type `to_bytes`/`from_bytes` codecs live on
//! `shrincs::PublicKey`, `shrincs::Signature`, and `sphincs_plus_c::Signature`
//! themselves; the composite envelope codecs
//! (`encode`/`decode_stateful_envelope`, `encode`/`decode_stateless_envelope`,
//! `decode_public_key_commitment`) are now `shrincs::{encode,decode}_*`. This
//! module is now empty and kept only as a placeholder pending its removal.
