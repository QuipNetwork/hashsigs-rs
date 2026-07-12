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

// HASH_LEN is the 32-byte hash *slot* width shared by every profile: every
// hash-valued wire field is a 32-byte slot (Solidity `bytes32`) regardless of
// the parameter set. A truncated profile emits high-aligned, zero-padded node
// values inside this slot (see HASH_TRUNC_LEN and `mask_hash`).
pub const HASH_LEN: usize = 32;
pub const HASH_SUITE_KECCAK_256: u32 = 1;

// Per-profile SHRINCS/SPHINCS parameter tuple, selected at compile time by
// cargo feature. This mirrors the Solidity
// contracts/profiles/<profile>/SHRINCSParams.sol libraries (one per build
// profile, selected by the `shrincs-profile/` Foundry remapping). Counts size
// arrays and bound loops, so they must be compile-time constants. Every value
// below matches its Solidity `SHRINCSParams` counterpart exactly.
#[cfg(all(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
compile_error!(
    "select at most one SHRINCS 128s profile feature \
     (profile-128s-q18 or profile-128s-q20)"
);

// shrincs-256s (default): contracts/profiles/256s/SHRINCSParams.sol.
#[cfg(not(any(feature = "profile-128s-q18", feature = "profile-128s-q20")))]
mod profile {
    /// Suite-qualified profile identifier, matching the Solidity PROFILE_ID
    /// preimage. Reserved for tooling/vector labelling; T6 binds it into the
    /// public-key commitment tag.
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-256s-keccak";
    /// SPHINCS `n` (HASH_LEN = 32): no truncation, `mask_hash` is a no-op.
    pub const HASH_TRUNC_LEN: usize = 32;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 64;
    pub const NUM_HYPERTREE_LAYERS: u8 = 8;
    pub const FORS_TREE_HEIGHT: u8 = 14;
    pub const NUM_FORS_TREES: u8 = 22;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 64;
    /// Stateful WOTS-C uses 64 chains.
    pub const WOTS_CHAINS_STATEFUL: usize = 64;
    /// Stateful WOTS-C uses base-16 digits for message expansion.
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    /// The 64 base-16 stateful digits must sum to 64 * (16 - 1) / 2 = 480.
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 480;
}

// shrincs-128s-q18: contracts/profiles/128s-q18/SHRINCSParams.sol.
#[cfg(feature = "profile-128s-q18")]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q18-keccak";
    /// SPHINCS `n` = 16: hash outputs are truncated to the high 16 bytes.
    pub const HASH_TRUNC_LEN: usize = 16;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 262_144;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    /// Stateful WOTS-C follows n: 2n = 32 chains.
    pub const WOTS_CHAINS_STATEFUL: usize = 32;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    /// The 32 base-16 stateful digits must sum to 32 * (16 - 1) / 2 = 240.
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 240;
}

// shrincs-128s-q20: contracts/profiles/128s-q20/SHRINCSParams.sol. Shares
// every constant with q18 except the stateless signature budget (2^20).
#[cfg(all(feature = "profile-128s-q20", not(feature = "profile-128s-q18")))]
mod profile {
    #[allow(dead_code)]
    pub const PROFILE_NAME: &str = "shrincs-128s-q20-keccak";
    pub const HASH_TRUNC_LEN: usize = 16;
    // Read by the account stateless-usage cap; allow guards builds that omit
    // that consumer. T6 also reads it for the per-profile budget.
    #[allow(dead_code)]
    pub const STATELESS_SIGNATURE_LIMIT: u64 = 1_048_576;
    pub const HYPERTREE_HEIGHT: u8 = 18;
    pub const NUM_HYPERTREE_LAYERS: u8 = 1;
    pub const FORS_TREE_HEIGHT: u8 = 24;
    pub const NUM_FORS_TREES: u8 = 6;
    pub const WOTS_CHAIN_LEN: u16 = 16;
    pub const NUM_WOTS_CHAINS: u16 = 32;
    pub const WOTS_CHAINS_STATEFUL: usize = 32;
    pub const WOTS_BASE_STATEFUL: u32 = 16;
    pub const WOTS_TARGET_SUM_STATEFUL: u32 = 240;
}

pub use profile::*;

// Encoded stateful public key layout, kept 68 bytes across all profiles:
// 32-byte pkSeed slot || 32-byte root slot || 4-byte maxSignatures.
pub const STATEFUL_PUBLIC_KEY_BYTES: usize = 68;

pub const ADDRESS_TYPE_WOTS_HASH: u32 = 0;
pub const ADDRESS_TYPE_TREE: u32 = 2;
pub const ADDRESS_TYPE_FORS_TREE: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
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
    /// Encoded replacement stateful public key.
    pub stateful_public_key: Vec<u8>,
    /// Commitment to the replacement installed public-key bundle.
    pub public_key_commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationTarget {
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
