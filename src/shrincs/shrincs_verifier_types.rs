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

pub const HASH_LEN: usize = 32;
pub const HASH_SUITE_KECCAK_256: u32 = 1;
#[allow(dead_code)]
pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
pub const HYPERTREE_HEIGHT: u8 = 64;
pub const NUM_HYPERTREE_LAYERS: u8 = 8;
pub const FORS_TREE_HEIGHT: u8 = 14;
pub const NUM_FORS_TREES: u8 = 22;
pub const WOTS_CHAIN_LEN: u16 = 16;
pub const NUM_WOTS_CHAINS: u16 = 64;
/// The 64 base-16 digits reconstructed from a WOTS-C message digest must sum to 480.
pub const WOTS_TARGET_SUM: u32 = 480;

pub const ADDRESS_TYPE_WOTS_HASH: u32 = 0;
pub const ADDRESS_TYPE_TREE: u32 = 2;
pub const ADDRESS_TYPE_FORS_TREE: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Global stateless public seed used for FORS-C, hypertree, and WOTS-C hashing.
    pub pk_seed: Vec<u8>,
    /// Expected final hypertree root.
    pub hypertree_root: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsEntry {
    /// Revealed FORS secret leaf for one signed FORS tree.
    pub secret_leaf: Vec<u8>,
    /// Authentication path from that FORS leaf to that FORS tree root.
    pub auth_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignature {
    /// Randomizer mixed into FORS digest derivation.
    pub randomizer: Vec<u8>,
    /// Counter mixed into FORS digest derivation.
    pub counter: u32,
    /// FORS-C reveals `num_fors_trees - 1` entries; the omitted final tree must select leaf 0.
    pub entries: Vec<ForsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsCSignature {
    /// Randomizer mixed into WOTS-C digest derivation.
    pub randomizer: Vec<u8>,
    /// Counter mixed into WOTS-C digest derivation.
    pub counter: u32,
    /// One chain value per WOTS-C digit.
    pub chains: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypertreeLayerSignature {
    /// Tree index for this hypertree layer.
    pub tree_index: u64,
    /// Leaf index inside this hypertree layer.
    pub leaf_index: u32,
    /// Expected WOTS-C public-key hash for this layer.
    pub wots_c_pk_hash: Vec<u8>,
    /// WOTS-C signature proving `current_root -> wots_c_pk_hash`.
    pub wots_c_signature: WotsCSignature,
    /// Merkle path from `wots_c_pk_hash` to the next layer root.
    pub auth_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatelessSignature {
    /// FORS-C signature that signs the external message and returns the first root.
    pub fors: ForsSignature,
    /// Hypertree layers that carry the FORS root up to the pinned hypertree root.
    pub hypertree: Vec<HypertreeLayerSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationTarget {
    /// Replacement global stateless public seed.
    pub pk_seed: Vec<u8>,
    /// Replacement hypertree root.
    pub hypertree_root: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationContext {
    /// Caller-controlled domain separation, normally binding account/program identity.
    pub domain_separator: [u8; HASH_LEN],
    /// Replay-protection nonce encoded as Solidity-style uint256 bytes.
    pub nonce: [u8; HASH_LEN],
    /// Current key version encoded as Solidity-style uint256 bytes.
    pub key_version: [u8; HASH_LEN],
}

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
