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

//! Scheme hashing: domain operations (`ops`), ADRS address words (`address`),
//! the portable-vs-Solana `backend`, and the compile-time scheme-hash `suite`.
//!
//! This is the Rust analogue of Solidity's shared scheme-hash support layer.
//! Primitive components (`uxmss`, `fors_c`, `hypertree`) build on these
//! helpers, while higher-level core and signer modules import the subset they
//! need. EVM-domain hashes such as canonical action-message construction and
//! public-key commitments stay on keccak under every suite and are therefore
//! owned outside this module.

mod ops;
mod address;
pub(crate) mod backend;
pub(crate) mod suite;

pub(crate) use ops::{
    base_w16_digit, base_w_digit, derive32, hash_node, hash_packed, keccak_packed, read_bits32,
    read_bits64, word32, wots_digest_bytes,
};
pub(crate) use address::{
    address_word32, fors_address_word, hypertree_address_word, wots_address_base,
    wots_chain_address_word, AddressWord32,
};
// These three stay `pub` (not `pub(crate)`) because `shrincs::mod`/`shrincs::verifier`
// re-export them as part of the crate's public API (unchanged from their pre-move
// `crate::primitives::ADDRESS_TYPE_*` visibility).
pub use address::{ADDRESS_TYPE_FORS_TREE, ADDRESS_TYPE_TREE, ADDRESS_TYPE_WOTS_HASH};
