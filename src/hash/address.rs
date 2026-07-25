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

//! ADRS address-word builders.

use crate::primitives::HASH_LEN;

pub const ADDRESS_TYPE_WOTS_HASH: u32 = 0;
pub const ADDRESS_TYPE_TREE: u32 = 2;
pub const ADDRESS_TYPE_FORS_TREE: u32 = 3;

/// Full ADRS word fields for `address_word32` (layer / tree / type / keypair /
/// chain / step). Bundled so the helper stays within the positional-arg limit.
#[derive(Clone, Copy)]
pub(crate) struct AddressWord32 {
    pub layer: u32,
    pub tree: u64,
    pub address_type: u32,
    pub keypair: u32,
    pub chain: u32,
    pub step: u32,
}

pub(crate) fn address_word32(addr: AddressWord32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&addr.layer.to_be_bytes());
    out[8..16].copy_from_slice(&addr.tree.to_be_bytes());
    out[16..20].copy_from_slice(&addr.address_type.to_be_bytes());
    out[20..24].copy_from_slice(&addr.keypair.to_be_bytes());
    out[24..28].copy_from_slice(&addr.chain.to_be_bytes());
    out[28..32].copy_from_slice(&addr.step.to_be_bytes());
    out
}

pub(crate) fn wots_address_base(layer: u32, tree: u64, keypair: u32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out
}

pub(crate) fn wots_chain_address_word(
    mut address_base: [u8; HASH_LEN],
    chain_index: u32,
    step: u32,
) -> [u8; HASH_LEN] {
    address_base[24..28].copy_from_slice(&chain_index.to_be_bytes());
    address_base[28..32].copy_from_slice(&step.to_be_bytes());
    address_base
}

pub(crate) fn fors_address_word(
    tree_index: u64,
    leaf_index: u32,
    node_height: u32,
    low_index: u64,
) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS_TYPE_FORS_TREE.to_be_bytes());
    out[20..24].copy_from_slice(&leaf_index.to_be_bytes());
    let low = (u64::from(node_height) << 32) | low_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}

pub(crate) fn hypertree_address_word(
    layer: u32,
    tree_index: u64,
    node_height: u32,
    parent_index: u64,
) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree_index.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS_TYPE_TREE.to_be_bytes());
    let low = (u64::from(node_height) << 32) | parent_index;
    out[24..32].copy_from_slice(&low.to_be_bytes());
    out
}
