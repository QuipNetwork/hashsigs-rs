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

//! Test-only fixture helpers for expensive SHRINCS key material.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ShrincsSigningKey;
use super::{
    ForsEntry, ForsSignature, HypertreeLayerSignature, PublicKey, RotationTarget,
    StatefulRotationTarget, StatelessSignature, WotsCSignature, HASH_LEN,
};

pub(crate) const FIXTURE_PATH_ENV: &str = "SHRINCS_TEST_KEY_FIXTURE_PATH";
pub(crate) const KEY_MODE_ENV: &str = "SHRINCS_TEST_KEY_MODE";
pub(crate) const DEFAULT_FIXTURE_DIR: &str = "tests/test_fixtures";
pub(crate) const ACCOUNT_CASES_FIXTURE_PATH_ENV: &str = "SHRINCS_TEST_ACCOUNT_CASES_FIXTURE_PATH";
pub(crate) const KEY_FIXTURE_BASENAME: &str = "account_keys";
pub(crate) const ACCOUNT_CASES_FIXTURE_BASENAME: &str = "account_signature_cases";
pub(crate) const STATEFUL_SIGNER_FIXTURE_PATH_ENV: &str =
    "SHRINCS_TEST_STATEFUL_SIGNER_FIXTURE_PATH";
pub(crate) const STATEFUL_SIGNER_FIXTURE_BASENAME: &str = "stateful_signer_keys";

fn profile_fixture_path(base_name: &str) -> PathBuf {
    PathBuf::from(DEFAULT_FIXTURE_DIR).join(format!(
        "{base_name}.{}.json",
        crate::shrincs::PROFILE_NAME
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestKeyMode {
    Fixture,
    Fresh,
}

impl TestKeyMode {
    pub(crate) fn from_env() -> Self {
        match env::var(KEY_MODE_ENV) {
            Ok(value) if value.eq_ignore_ascii_case("fresh") => Self::Fresh,
            Ok(value) if value.eq_ignore_ascii_case("fixture") => Self::Fixture,
            Ok(value) if value.is_empty() => Self::Fixture,
            Ok(_) | Err(_) => Self::Fixture,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SigningKeyDto {
    pub(crate) stateful_sk_seed: [u8; HASH_LEN],
    pub(crate) stateful_prf_seed: [u8; HASH_LEN],
    pub(crate) stateful_pk_seed: [u8; HASH_LEN],
    pub(crate) stateful_root: [u8; HASH_LEN],
    pub(crate) max_stateful_signatures: u32,
    pub(crate) next_stateful_leaf_index: u32,
    pub(crate) stateless_sk_seed: [u8; HASH_LEN],
    pub(crate) stateless_prf_seed: [u8; HASH_LEN],
    pub(crate) pk_seed: [u8; HASH_LEN],
    pub(crate) hypertree_root: [u8; HASH_LEN],
}

impl From<&ShrincsSigningKey> for SigningKeyDto {
    fn from(value: &ShrincsSigningKey) -> Self {
        Self {
            stateful_sk_seed: value.stateful_sk_seed,
            stateful_prf_seed: value.stateful_prf_seed,
            stateful_pk_seed: value.stateful_pk_seed,
            stateful_root: value.stateful_root,
            max_stateful_signatures: value.max_stateful_signatures,
            next_stateful_leaf_index: value.next_stateful_leaf_index,
            stateless_sk_seed: value.stateless_sk_seed,
            stateless_prf_seed: value.stateless_prf_seed,
            pk_seed: value.pk_seed,
            hypertree_root: value.hypertree_root,
        }
    }
}

impl From<SigningKeyDto> for ShrincsSigningKey {
    fn from(value: SigningKeyDto) -> Self {
        Self {
            stateful_sk_seed: value.stateful_sk_seed,
            stateful_prf_seed: value.stateful_prf_seed,
            stateful_pk_seed: value.stateful_pk_seed,
            stateful_root: value.stateful_root,
            max_stateful_signatures: value.max_stateful_signatures,
            next_stateful_leaf_index: value.next_stateful_leaf_index,
            stateless_sk_seed: value.stateless_sk_seed,
            stateless_prf_seed: value.stateless_prf_seed,
            pk_seed: value.pk_seed,
            hypertree_root: value.hypertree_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicKeyDto {
    pub(crate) stateful_public_key: Vec<u8>,
    pub(crate) public_key_commitment: Vec<u8>,
    pub(crate) pk_seed: Vec<u8>,
    pub(crate) hypertree_root: Vec<u8>,
}

impl From<&PublicKey> for PublicKeyDto {
    fn from(value: &PublicKey) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key.clone(),
            public_key_commitment: value.public_key_commitment.clone(),
            pk_seed: value.pk_seed.clone(),
            hypertree_root: value.hypertree_root.clone(),
        }
    }
}

impl From<PublicKeyDto> for PublicKey {
    fn from(value: PublicKeyDto) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key,
            public_key_commitment: value.public_key_commitment,
            pk_seed: value.pk_seed,
            hypertree_root: value.hypertree_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeyFixtureEntry {
    pub(crate) seed_label: String,
    pub(crate) signing_key: SigningKeyDto,
    pub(crate) public_key: PublicKeyDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeyFixtureFile {
    pub(crate) profile_name: String,
    pub(crate) entries: Vec<KeyFixtureEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForsEntryDto {
    pub(crate) secret_leaf: Vec<u8>,
    pub(crate) auth_path: Vec<Vec<u8>>,
}

impl From<&ForsEntry> for ForsEntryDto {
    fn from(value: &ForsEntry) -> Self {
        Self {
            secret_leaf: value.secret_leaf.to_vec(),
            auth_path: nodes_to_vecs(&value.auth_path),
        }
    }
}

impl From<ForsEntryDto> for ForsEntry {
    fn from(value: ForsEntryDto) -> Self {
        Self {
            secret_leaf: fixture_word(value.secret_leaf),
            auth_path: vecs_to_nodes(value.auth_path),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForsSignatureDto {
    pub(crate) randomizer: Vec<u8>,
    pub(crate) counter: u32,
    pub(crate) entries: Vec<ForsEntryDto>,
}

impl From<&ForsSignature> for ForsSignatureDto {
    fn from(value: &ForsSignature) -> Self {
        Self {
            randomizer: value.randomizer.to_vec(),
            counter: value.counter,
            entries: value.entries.iter().map(ForsEntryDto::from).collect(),
        }
    }
}

impl From<ForsSignatureDto> for ForsSignature {
    fn from(value: ForsSignatureDto) -> Self {
        Self {
            randomizer: fixture_word(value.randomizer),
            counter: value.counter,
            entries: value.entries.into_iter().map(ForsEntry::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WotsCSignatureDto {
    pub(crate) randomizer: Vec<u8>,
    pub(crate) counter: u32,
    pub(crate) chains: Vec<Vec<u8>>,
}

impl From<&WotsCSignature> for WotsCSignatureDto {
    fn from(value: &WotsCSignature) -> Self {
        Self {
            randomizer: value.randomizer.to_vec(),
            counter: value.counter,
            chains: nodes_to_vecs(&value.chains),
        }
    }
}

impl From<WotsCSignatureDto> for WotsCSignature {
    fn from(value: WotsCSignatureDto) -> Self {
        Self {
            randomizer: fixture_word(value.randomizer),
            counter: value.counter,
            chains: vecs_to_nodes(value.chains),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HypertreeLayerSignatureDto {
    pub(crate) wots_c_pk_hash: Vec<u8>,
    pub(crate) wots_c_signature: WotsCSignatureDto,
    pub(crate) auth_path: Vec<Vec<u8>>,
}

impl From<&HypertreeLayerSignature> for HypertreeLayerSignatureDto {
    fn from(value: &HypertreeLayerSignature) -> Self {
        Self {
            wots_c_pk_hash: value.wots_c_pk_hash.to_vec(),
            wots_c_signature: WotsCSignatureDto::from(&value.wots_c_signature),
            auth_path: nodes_to_vecs(&value.auth_path),
        }
    }
}

impl From<HypertreeLayerSignatureDto> for HypertreeLayerSignature {
    fn from(value: HypertreeLayerSignatureDto) -> Self {
        Self {
            wots_c_pk_hash: fixture_word(value.wots_c_pk_hash),
            wots_c_signature: value.wots_c_signature.into(),
            auth_path: vecs_to_nodes(value.auth_path),
        }
    }
}

/// Fixture hash fields are JSON byte lists of exactly `HASH_LEN` bytes.
fn fixture_word(bytes: Vec<u8>) -> [u8; HASH_LEN] {
    bytes
        .try_into()
        .expect("fixture hash field must be exactly HASH_LEN bytes")
}

fn vecs_to_nodes(list: Vec<Vec<u8>>) -> Vec<[u8; HASH_LEN]> {
    list.into_iter().map(fixture_word).collect()
}

fn nodes_to_vecs(nodes: &[[u8; HASH_LEN]]) -> Vec<Vec<u8>> {
    nodes.iter().map(|node| node.to_vec()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatelessSignatureDto {
    pub(crate) fors: ForsSignatureDto,
    pub(crate) hypertree: Vec<HypertreeLayerSignatureDto>,
}

impl From<&StatelessSignature> for StatelessSignatureDto {
    fn from(value: &StatelessSignature) -> Self {
        Self {
            fors: ForsSignatureDto::from(&value.fors),
            hypertree: value
                .hypertree
                .iter()
                .map(HypertreeLayerSignatureDto::from)
                .collect(),
        }
    }
}

impl From<StatelessSignatureDto> for StatelessSignature {
    fn from(value: StatelessSignatureDto) -> Self {
        Self {
            fors: value.fors.into(),
            hypertree: value.hypertree.into_iter().map(HypertreeLayerSignature::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatefulRotationTargetDto {
    pub(crate) stateful_public_key: Vec<u8>,
    pub(crate) public_key_commitment: Vec<u8>,
}

impl From<&StatefulRotationTarget> for StatefulRotationTargetDto {
    fn from(value: &StatefulRotationTarget) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key.clone(),
            public_key_commitment: value.public_key_commitment.clone(),
        }
    }
}

impl From<StatefulRotationTargetDto> for StatefulRotationTarget {
    fn from(value: StatefulRotationTargetDto) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key,
            public_key_commitment: value.public_key_commitment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RotationTargetDto {
    pub(crate) stateful_public_key: Vec<u8>,
    pub(crate) public_key_commitment: Vec<u8>,
    pub(crate) pk_seed: Vec<u8>,
    pub(crate) hypertree_root: Vec<u8>,
}

impl From<&RotationTarget> for RotationTargetDto {
    fn from(value: &RotationTarget) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key.clone(),
            public_key_commitment: value.public_key_commitment.clone(),
            pk_seed: value.pk_seed.clone(),
            hypertree_root: value.hypertree_root.clone(),
        }
    }
}

impl From<RotationTargetDto> for RotationTarget {
    fn from(value: RotationTargetDto) -> Self {
        Self {
            stateful_public_key: value.stateful_public_key,
            public_key_commitment: value.public_key_commitment,
            pk_seed: value.pk_seed,
            hypertree_root: value.hypertree_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountStatelessActionCaseDto {
    pub(crate) public_key: PublicKeyDto,
    pub(crate) action_type: [u8; HASH_LEN],
    pub(crate) payload_hash: [u8; HASH_LEN],
    pub(crate) signature: StatelessSignatureDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountStatefulRotationCaseDto {
    pub(crate) public_key: PublicKeyDto,
    pub(crate) next_target: StatefulRotationTargetDto,
    pub(crate) next_commitment: [u8; HASH_LEN],
    pub(crate) signature: StatelessSignatureDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountFullRotationCaseDto {
    pub(crate) public_key: PublicKeyDto,
    pub(crate) next_target: RotationTargetDto,
    pub(crate) next_commitment: [u8; HASH_LEN],
    pub(crate) signature: StatelessSignatureDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountWrongKeyStatelessActionCaseDto {
    pub(crate) installed_public_key: PublicKeyDto,
    pub(crate) signing_public_key: PublicKeyDto,
    pub(crate) action_type: [u8; HASH_LEN],
    pub(crate) payload_hash: [u8; HASH_LEN],
    pub(crate) signature: StatelessSignatureDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountSignatureFixtureFile {
    pub(crate) profile_name: String,
    pub(crate) stateless_action: AccountStatelessActionCaseDto,
    pub(crate) rotate_stateful: AccountStatefulRotationCaseDto,
    pub(crate) rotate_stateful_boundary: AccountStatefulRotationCaseDto,
    pub(crate) rotate_stateful_tamper: AccountStatefulRotationCaseDto,
    pub(crate) rotate_full: AccountFullRotationCaseDto,
    pub(crate) rotate_full_same_stateless: AccountFullRotationCaseDto,
    pub(crate) stateless_tamper: AccountStatelessActionCaseDto,
    pub(crate) stateless_wrong_key: AccountWrongKeyStatelessActionCaseDto,
}

pub(crate) fn fixture_path() -> PathBuf {
    env::var_os(FIXTURE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| profile_fixture_path(KEY_FIXTURE_BASENAME))
}

pub(crate) fn account_cases_fixture_path() -> PathBuf {
    env::var_os(ACCOUNT_CASES_FIXTURE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| profile_fixture_path(ACCOUNT_CASES_FIXTURE_BASENAME))
}

pub(crate) fn stateful_signer_fixture_path() -> PathBuf {
    env::var_os(STATEFUL_SIGNER_FIXTURE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| profile_fixture_path(STATEFUL_SIGNER_FIXTURE_BASENAME))
}

pub(crate) fn load_fixture_file(path: &Path) -> KeyFixtureFile {
    let json = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read fixture file {}: {error}", path.display())
    });
    serde_json::from_str(&json).unwrap_or_else(|error| {
        panic!("failed to parse fixture file {}: {error}", path.display())
    })
}

pub(crate) fn write_fixture_file(path: &Path, fixture_file: &KeyFixtureFile) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "failed to create fixture directory {}: {error}",
                parent.display()
            )
        });
    }
    let json = serde_json::to_string(fixture_file)
        .expect("fixture file must serialize");
    fs::write(path, json).unwrap_or_else(|error| {
        panic!("failed to write fixture file {}: {error}", path.display())
    });
}

pub(crate) fn load_account_cases_fixture_file(path: &Path) -> AccountSignatureFixtureFile {
    let json = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "failed to read account cases fixture file {}: {error}",
            path.display()
        )
    });
    serde_json::from_str(&json).unwrap_or_else(|error| {
        panic!(
            "failed to parse account cases fixture file {}: {error}",
            path.display()
        )
    })
}

pub(crate) fn write_account_cases_fixture_file(
    path: &Path,
    fixture_file: &AccountSignatureFixtureFile,
) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!(
                "failed to create fixture directory {}: {error}",
                parent.display()
            )
        });
    }
    let json = serde_json::to_string(fixture_file)
        .expect("account cases fixture file must serialize");
    fs::write(path, json).unwrap_or_else(|error| {
        panic!(
            "failed to write account cases fixture file {}: {error}",
            path.display()
        )
    });
}

pub(crate) fn fixture_entry_opt<'a>(
    fixture_file: &'a KeyFixtureFile,
    seed_label: &str,
) -> Option<&'a KeyFixtureEntry> {
    fixture_file
        .entries
        .iter()
        .find(|entry| entry.seed_label == seed_label)
}

pub(crate) fn fixture_pair(entry: &KeyFixtureEntry) -> (ShrincsSigningKey, PublicKey) {
    (
        entry.signing_key.clone().into(),
        entry.public_key.clone().into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::{PROFILE_NAME, ShrincsSigner};

    #[cfg(any(shrincs_profile_128s_q18, shrincs_profile_128s_q20))]
    fn full_key_fixture_specs() -> Vec<(&'static str, u32)> {
        vec![
            ("deterministic keygen seed", 4),
            ("shrincs solidity vector stateful seed", 4),
        ]
    }

    #[cfg(not(any(shrincs_profile_128s_q18, shrincs_profile_128s_q20)))]
    fn full_key_fixture_specs() -> Vec<(&'static str, u32)> {
        vec![
            ("account stateless action seed", 4),
            ("account rotate stateful current seed", 4),
            ("account rotate stateful next seed", 8),
            ("account rotate full current seed", 4),
            ("account rotate full next seed", 8),
            ("account recovery after use seed", 4),
            ("account recovery after use next seed", 8),
            ("account boundary rotate seed", 4),
            ("account boundary rotate next seed", 8),
            ("account same stateless rotate seed", 4),
            ("account same stateless rotate next seed", 8),
            ("account rotate tamper current seed", 4),
            ("account rotate tamper next seed", 8),
            ("account stateless tamper seed", 4),
            ("account stateless wrong-key A", 4),
            ("account stateless wrong-key B", 4),
            ("stateless negative seed", 2),
            ("stateless malformed seed", 2),
            ("stateless empty message seed", 2),
            ("stateless signer seed", 2),
            ("deterministic keygen seed", 4),
            ("public key structure seed", 8),
            ("initial stateful leaf seed", 8),
            ("stateful signer seed", 4),
            ("action signer seed", 4),
            ("explicit leaf helper seed", 4),
            ("stateful exhaustion seed", 1),
            ("stateful negative seed", 4),
            ("action negative seed", 4),
            ("public key negative seed", 4),
            ("shrincs solidity vector stateful seed", 4),
        ]
    }

    fn account_stateful_only_fixture_specs() -> [(&'static str, u32); 5] {
        [
            ("account raw helper seed", 4),
            ("account stateful action seed", 4),
            ("account failed stateful freeze seed", 4),
            ("account wrong-key installed A", 4),
            ("account wrong-key attacker B", 4),
        ]
    }

    use crate::test_support::stateful_only_key;


    fn stateful_signer_fixture_specs() -> Vec<(&'static str, u32)> {
        vec![
            ("stateful signer seed", 4),
            ("action signer seed", 4),
            ("explicit leaf helper seed", 4),
            ("stateful exhaustion seed", 1),
            ("stateful negative seed", 4),
            ("action negative seed", 4),
            ("public key negative seed", 4),
        ]
    }

    #[test]
    #[ignore = "writes checked-in test fixtures on demand"]
    fn write_account_key_fixture_file() {
        let full_key_entries = full_key_fixture_specs()
            .into_iter()
            .map(|(seed_label, max_stateful_signatures)| {
                let (signing_key, public_key) = ShrincsSigner::keygen(
                    seed_label.as_bytes(),
                    max_stateful_signatures,
                )
                .unwrap_or_else(|| {
                    panic!(
                        "fixture keygen failed for seed label {seed_label:?} with max_stateful_signatures={max_stateful_signatures}"
                    )
                });
                KeyFixtureEntry {
                    seed_label: seed_label.to_string(),
                    signing_key: SigningKeyDto::from(&signing_key),
                    public_key: PublicKeyDto::from(&public_key),
                }
            })
            .collect::<Vec<_>>();
        let stateful_only_entries = account_stateful_only_fixture_specs()
            .into_iter()
            .map(|(seed_label, max_stateful_signatures)| {
                let (signing_key, public_key) =
                    stateful_only_key(seed_label.as_bytes(), max_stateful_signatures);
                KeyFixtureEntry {
                    seed_label: seed_label.to_string(),
                    signing_key: SigningKeyDto::from(&signing_key),
                    public_key: PublicKeyDto::from(&public_key),
                }
            })
            .collect::<Vec<_>>();
        let mut entries = Vec::with_capacity(full_key_entries.len() + stateful_only_entries.len());
        entries.extend(full_key_entries);
        entries.extend(stateful_only_entries);

        let fixture_file = KeyFixtureFile {
            profile_name: PROFILE_NAME.to_string(),
            entries,
        };
        write_fixture_file(&fixture_path(), &fixture_file);
    }

    #[test]
    #[ignore = "writes checked-in stateful signer fixtures on demand"]
    fn write_stateful_signer_fixture_file() {
        let entries = stateful_signer_fixture_specs()
            .into_iter()
            .map(|(seed_label, max_stateful_signatures)| {
                let (signing_key, public_key) =
                    stateful_only_key(seed_label.as_bytes(), max_stateful_signatures);
                KeyFixtureEntry {
                    seed_label: seed_label.to_string(),
                    signing_key: SigningKeyDto::from(&signing_key),
                    public_key: PublicKeyDto::from(&public_key),
                }
            })
            .collect();

        let fixture_file = KeyFixtureFile {
            profile_name: PROFILE_NAME.to_string(),
            entries,
        };
        write_fixture_file(&stateful_signer_fixture_path(), &fixture_file);
    }
}
