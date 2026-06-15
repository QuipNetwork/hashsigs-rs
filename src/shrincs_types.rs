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

// Encoded stateful public key layout:
// 32-byte pkSeed || 32-byte root || 4-byte maxSignatures.
pub const STATEFUL_PUBLIC_KEY_BYTES: usize = 68;
// Stateful WOTS-C uses 64 chains in the current supported profile.
pub const WOTS_CHAINS_STATEFUL: usize = 64;
// Stateful WOTS-C uses base-16 digits for message expansion.
pub const WOTS_BASE_STATEFUL: u32 = 16;
// The 64 base-16 digits reconstructed from the stateful message digest must
// sum to 480 in the current supported profile.
pub const WOTS_TARGET_SUM_STATEFUL: u32 = 480;

pub const ADDRESS_TYPE_WOTS_HASH: u32 = 0;
pub const ADDRESS_TYPE_TREE: u32 = 2;
pub const ADDRESS_TYPE_FORS_TREE: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterSetId {
    Sphincs256sKeccakQ20,
    Unsupported,
}

impl ParameterSetId {
    pub(crate) fn packed_byte(self) -> u8 {
        match self {
            Self::Sphincs256sKeccakQ20 => 0,
            Self::Unsupported => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamsView {
    /// Parameter profile selected by the caller and declared by the public key.
    pub parameter_set_id: ParameterSetId,
    /// Hash suite identifier bound into action and rotation message hashes.
    pub hash_suite_id: u32,
    /// Maximum stateless signatures accepted for this profile.
    pub stateless_signature_limit: u64,
    /// Hash output length. The supported Solidity profile fixes this to 32.
    pub hash_len: u16,
    /// Total height of the hypertree across all layers.
    pub hypertree_height: u8,
    /// Number of hypertree layers. Each layer has `hypertree_height / num_hypertree_layers` levels.
    pub num_hypertree_layers: u8,
    /// Height of each FORS tree.
    pub fors_tree_height: u8,
    /// Number of FORS trees. FORS-C signs `num_fors_trees - 1` entries.
    pub num_fors_trees: u8,
    /// WOTS-C base. The current profile uses base 16.
    pub chain_len: u16,
    /// Number of WOTS-C chains used by stateless and stateful WOTS-C.
    pub num_wots_chains: u16,
    /// Required sum of reconstructed WOTS-C digits.
    pub wots_target_sum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Parameter profile declared by this public key.
    pub parameter_set_id: ParameterSetId,
    /// Encoded stateful key: `pk_seed || root || max_signatures`.
    pub stateful_public_key: Vec<u8>,
    /// Commitment to the installed hybrid public-key bundle.
    pub public_key_commitment: Vec<u8>,
    /// Global stateless public seed used for FORS-C, hypertree, and WOTS-C hashing.
    pub pk_seed: Vec<u8>,
    /// Expected final hypertree root.
    pub hypertree_root: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatefulPublicKey {
    /// Public seed used by stateful WOTS-C and the unbalanced XMSS-like tree.
    pub pk_seed: [u8; HASH_LEN],
    /// Root of the stateful unbalanced authentication tree.
    pub root: [u8; HASH_LEN],
    /// Highest accepted stateful leaf index.
    pub max_signatures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatefulSignature {
    /// Per-signature randomizer mixed into WOTS digit derivation.
    pub randomizer: [u8; HASH_LEN],
    /// Counter mixed into WOTS digit derivation.
    pub counter: u32,
    /// One WOTS-C chain value per reconstructed digit.
    pub chains: Vec<[u8; HASH_LEN]>,
    /// Unbalanced authentication path. Its length is also the leaf index.
    pub auth_path: Vec<[u8; HASH_LEN]>,
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
pub struct StatefulRotationTarget {
    /// Parameter set declared by the replacement stateful key.
    pub parameter_set_id: ParameterSetId,
    /// Encoded replacement stateful public key.
    pub stateful_public_key: Vec<u8>,
    /// Commitment to the replacement installed public-key bundle.
    pub public_key_commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationTarget {
    /// Parameter set declared by the replacement full key bundle.
    pub parameter_set_id: ParameterSetId,
    /// Replacement encoded stateful public key.
    pub stateful_public_key: Vec<u8>,
    /// Commitment to the replacement installed public-key bundle.
    pub public_key_commitment: Vec<u8>,
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

pub fn default_params_view(parameter_set_id: ParameterSetId) -> ParamsView {
    // Keep this table in lockstep with `ShrincsTypes.defaultParamsView` in Solidity.
    // All downstream verifiers rely on these dimensions for fixed-length checks and bit slicing.
    match parameter_set_id {
        ParameterSetId::Sphincs256sKeccakQ20 => ParamsView {
            parameter_set_id,
            hash_suite_id: HASH_SUITE_KECCAK_256,
            stateless_signature_limit: 1_048_576,
            hash_len: 32,
            hypertree_height: 64,
            num_hypertree_layers: 8,
            fors_tree_height: 14,
            num_fors_trees: 22,
            chain_len: 16,
            num_wots_chains: 64,
            wots_target_sum: WOTS_TARGET_SUM_STATEFUL,
        },
        ParameterSetId::Unsupported => ParamsView {
            parameter_set_id,
            hash_suite_id: 0,
            stateless_signature_limit: 0,
            hash_len: 0,
            hypertree_height: 0,
            num_hypertree_layers: 0,
            fors_tree_height: 0,
            num_fors_trees: 0,
            chain_len: 0,
            num_wots_chains: 0,
            wots_target_sum: 0,
        },
    }
}
