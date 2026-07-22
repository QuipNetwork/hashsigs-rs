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

//! Shared SHRINCS wire types and structural constants.

// HASH_LEN is the 32-byte hash *slot* width shared by every profile: every
// hash-valued wire field is a 32-byte slot (Solidity `bytes32`) regardless of
// the parameter set. A truncated profile emits high-aligned, zero-padded node
// values inside this slot (see HASH_TRUNC_LEN and `mask_hash`).
use alloc::vec::Vec;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const HASH_LEN: usize = 32;
pub const HASH_SUITE_KECCAK_256: u32 = 1;
pub const HASH_SUITE_SHA2_256: u32 = 2;

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
    pub secret_leaf: [u8; HASH_LEN],
    /// Authentication path from that FORS leaf to that FORS tree root.
    pub auth_path: Vec<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignature {
    /// Randomizer mixed into FORS digest derivation.
    pub randomizer: [u8; HASH_LEN],
    /// Counter mixed into FORS digest derivation.
    pub counter: u32,
    /// FORS-C reveals `num_fors_trees - 1` entries; the omitted final tree must select leaf 0.
    pub entries: Vec<ForsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsCSignature {
    /// Randomizer mixed into WOTS-C digest derivation.
    pub randomizer: [u8; HASH_LEN],
    /// Counter mixed into WOTS-C digest derivation.
    pub counter: u32,
    /// One chain value per WOTS-C digit.
    pub chains: Vec<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypertreeLayerSignature {
    /// Expected WOTS-C public-key hash for this layer.
    pub wots_c_pk_hash: [u8; HASH_LEN],
    /// WOTS-C signature proving `current_root -> wots_c_pk_hash`.
    pub wots_c_signature: WotsCSignature,
    /// Merkle path from `wots_c_pk_hash` to the next layer root.
    pub auth_path: Vec<[u8; HASH_LEN]>,
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

/// Secret material required to sign at the SPHINCS+C layer alone.
///
/// Lives in `types` (the leaf module) so `fors_c` and `hypertree` can accept
/// it without importing upward from `sphincs_plus_c`. Treat as private key
/// material: anyone with these seeds can produce stateless signatures.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SphincsPlusCSigningKey {
    /// Stateless SK.seed-style material used to derive FORS-C and hypertree WOTS-C secrets.
    pub stateless_sk_seed: [u8; HASH_LEN],
    /// Stateless SK.prf-style material used to derive stateless message randomizers.
    pub stateless_prf_seed: [u8; HASH_LEN],
    /// Global public seed used in FORS-C, hypertree WOTS-C, and Merkle node hashing.
    pub pk_seed: [u8; HASH_LEN],
    /// Top hypertree root committed in the public key.
    pub hypertree_root: [u8; HASH_LEN],
}

impl fmt::Debug for SphincsPlusCSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SphincsPlusCSigningKey")
            .field("stateless_sk_seed", &"<redacted>")
            .field("stateless_prf_seed", &"<redacted>")
            .field("pk_seed", &"<redacted>")
            .field("hypertree_root", &"<redacted>")
            .finish()
    }
}
