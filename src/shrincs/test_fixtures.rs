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

use super::signers::types::ShrincsSigningKey;
use super::{PublicKey, HASH_LEN};

pub(crate) const FIXTURE_PATH_ENV: &str = "SHRINCS_TEST_KEY_FIXTURE_PATH";
pub(crate) const KEY_MODE_ENV: &str = "SHRINCS_TEST_KEY_MODE";
pub(crate) const DEFAULT_FIXTURE_PATH: &str = "tests/test_fixtures/account_keys.json";

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

pub(crate) fn fixture_path() -> PathBuf {
    env::var_os(FIXTURE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FIXTURE_PATH))
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
    let json = serde_json::to_string_pretty(fixture_file)
        .expect("fixture file must serialize");
    fs::write(path, json).unwrap_or_else(|error| {
        panic!("failed to write fixture file {}: {error}", path.display())
    });
}

pub(crate) fn fixture_entry<'a>(
    fixture_file: &'a KeyFixtureFile,
    seed_label: &str,
) -> &'a KeyFixtureEntry {
    fixture_file
        .entries
        .iter()
        .find(|entry| entry.seed_label == seed_label)
        .unwrap_or_else(|| panic!("missing fixture entry for seed label {seed_label:?}"))
}

pub(crate) fn fixture_pair(entry: &KeyFixtureEntry) -> (ShrincsSigningKey, PublicKey) {
    (
        entry.signing_key.clone().into(),
        entry.public_key.clone().into(),
    )
}
