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

//! Borsh DTOs for on-chain SPHINCS+C / SHRINCS-hybrid stateless verify.
//!
//! `hashsigs_rs` core wire types (`StatelessSignature`, `ForsSignature`, ...) do
//! not derive Borsh -- they stay untouched so the wire format / golden vectors
//! remain the single source of truth. These DTOs are a compact on-chain-only
//! encoding that convert into the core types before calling
//! `SphincsPlusCVerifier` / `ShrincsVerifier`.

use borsh::{BorshDeserialize, BorshSerialize};
use hashsigs_rs::shrincs::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey as ShrincsPublicKey,
    StatelessSignature, WotsCSignature,
};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ForsEntryDto {
    pub secret_leaf: [u8; 32],
    pub auth_path: Vec<[u8; 32]>,
}

impl From<ForsEntryDto> for ForsEntry {
    fn from(dto: ForsEntryDto) -> Self {
        ForsEntry {
            secret_leaf: dto.secret_leaf,
            auth_path: dto.auth_path,
        }
    }
}

impl From<ForsEntry> for ForsEntryDto {
    fn from(entry: ForsEntry) -> Self {
        ForsEntryDto {
            secret_leaf: entry.secret_leaf,
            auth_path: entry.auth_path,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ForsSignatureDto {
    pub randomizer: [u8; 32],
    pub counter: u32,
    pub entries: Vec<ForsEntryDto>,
}

impl From<ForsSignatureDto> for ForsSignature {
    fn from(dto: ForsSignatureDto) -> Self {
        ForsSignature {
            randomizer: dto.randomizer,
            counter: dto.counter,
            entries: dto.entries.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ForsSignature> for ForsSignatureDto {
    fn from(sig: ForsSignature) -> Self {
        ForsSignatureDto {
            randomizer: sig.randomizer,
            counter: sig.counter,
            entries: sig.entries.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct WotsCSignatureDto {
    pub randomizer: [u8; 32],
    pub counter: u32,
    pub chains: Vec<[u8; 32]>,
}

impl From<WotsCSignatureDto> for WotsCSignature {
    fn from(dto: WotsCSignatureDto) -> Self {
        WotsCSignature {
            randomizer: dto.randomizer,
            counter: dto.counter,
            chains: dto.chains,
        }
    }
}

impl From<WotsCSignature> for WotsCSignatureDto {
    fn from(sig: WotsCSignature) -> Self {
        WotsCSignatureDto {
            randomizer: sig.randomizer,
            counter: sig.counter,
            chains: sig.chains,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct HypertreeLayerSignatureDto {
    pub wots_c_pk_hash: [u8; 32],
    pub wots_c_signature: WotsCSignatureDto,
    pub auth_path: Vec<[u8; 32]>,
}

impl From<HypertreeLayerSignatureDto> for HypertreeLayerSignature {
    fn from(dto: HypertreeLayerSignatureDto) -> Self {
        HypertreeLayerSignature {
            wots_c_pk_hash: dto.wots_c_pk_hash,
            wots_c_signature: dto.wots_c_signature.into(),
            auth_path: dto.auth_path,
        }
    }
}

impl From<HypertreeLayerSignature> for HypertreeLayerSignatureDto {
    fn from(layer: HypertreeLayerSignature) -> Self {
        HypertreeLayerSignatureDto {
            wots_c_pk_hash: layer.wots_c_pk_hash,
            wots_c_signature: layer.wots_c_signature.into(),
            auth_path: layer.auth_path,
        }
    }
}

/// Compact Borsh DTO for `hashsigs_rs::shrincs::StatelessSignature`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StatelessSignatureDto {
    pub fors: ForsSignatureDto,
    pub hypertree: Vec<HypertreeLayerSignatureDto>,
}

impl From<StatelessSignatureDto> for StatelessSignature {
    fn from(dto: StatelessSignatureDto) -> Self {
        StatelessSignature {
            fors: dto.fors.into(),
            hypertree: dto.hypertree.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<StatelessSignature> for StatelessSignatureDto {
    fn from(sig: StatelessSignature) -> Self {
        StatelessSignatureDto {
            fors: sig.fors.into(),
            hypertree: sig.hypertree.into_iter().map(Into::into).collect(),
        }
    }
}

/// Compact Borsh DTO for the SHRINCS hybrid public-key bundle
/// (`hashsigs_rs::shrincs::PublicKey`).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ShrincsPublicKeyDto {
    pub stateful_public_key: Vec<u8>,
    pub public_key_commitment: Vec<u8>,
    pub pk_seed: Vec<u8>,
    pub hypertree_root: Vec<u8>,
}

impl From<ShrincsPublicKeyDto> for ShrincsPublicKey {
    fn from(dto: ShrincsPublicKeyDto) -> Self {
        ShrincsPublicKey {
            stateful_public_key: dto.stateful_public_key,
            public_key_commitment: dto.public_key_commitment,
            pk_seed: dto.pk_seed,
            hypertree_root: dto.hypertree_root,
        }
    }
}

impl From<ShrincsPublicKey> for ShrincsPublicKeyDto {
    fn from(pk: ShrincsPublicKey) -> Self {
        ShrincsPublicKeyDto {
            stateful_public_key: pk.stateful_public_key,
            public_key_commitment: pk.public_key_commitment,
            pk_seed: pk.pk_seed,
            hypertree_root: pk.hypertree_root,
        }
    }
}

/// Compact Borsh DTO for `hashsigs_rs::shrincs::ActionContext` (all fields are
/// fixed 32-byte words, so this is a 1:1 field mapping).
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct ActionContextDto {
    pub domain_separator: [u8; 32],
    pub nonce: [u8; 32],
    pub key_version: [u8; 32],
    pub action_type: [u8; 32],
    pub payload_hash: [u8; 32],
}

impl From<ActionContextDto> for ActionContext {
    fn from(dto: ActionContextDto) -> Self {
        ActionContext {
            domain_separator: dto.domain_separator,
            nonce: dto.nonce,
            key_version: dto.key_version,
            action_type: dto.action_type,
            payload_hash: dto.payload_hash,
        }
    }
}

impl From<ActionContext> for ActionContextDto {
    fn from(context: ActionContext) -> Self {
        ActionContextDto {
            domain_separator: context.domain_separator,
            nonce: context.nonce,
            key_version: context.key_version,
            action_type: context.action_type,
            payload_hash: context.payload_hash,
        }
    }
}
