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

//! The wire types of the crate as EasyCrypt records, and synthetic samples of
//! each. The record fields carry a prefix for each type, so that no two
//! record types of the specification share a projection name.

use alloc::vec::Vec;

use super::{label_bytes, label_word};
use crate::kat::value::Value;
use crate::shrincs::{PublicKey, Signature as StatefulSignature};
use crate::sphincs_plus_c::{
    ForsEntry, ForsSignature, LayerSignature, Signature as StatelessSignature,
};
use crate::wots_c::Signature as WotsCSignature;
use crate::HASH_LEN;

/// `wots_c::Signature`.
pub(crate) fn wots_sig(s: &WotsCSignature) -> Value {
    Value::Record(alloc::vec![
        ("wc_randomizer", Value::bytes(&s.randomizer)),
        ("wc_counter", Value::int(s.counter)),
        ("wc_chains", Value::words(&s.chains)),
    ])
}

/// `shrincs::Signature`, the stateful UXMSS signature.
pub(crate) fn stateful_sig(s: &StatefulSignature) -> Value {
    Value::Record(alloc::vec![
        ("sf_randomizer", Value::bytes(&s.randomizer)),
        ("sf_counter", Value::int(s.counter)),
        ("sf_chains", Value::words(&s.chains)),
        ("sf_auth_path", Value::words(&s.auth_path)),
    ])
}

/// `sphincs_plus_c::ForsEntry`.
pub(crate) fn fors_entry(e: &ForsEntry) -> Value {
    Value::Record(alloc::vec![
        ("fe_secret_leaf", Value::bytes(&e.secret_leaf)),
        ("fe_auth_path", Value::words(&e.auth_path)),
    ])
}

/// `sphincs_plus_c::ForsSignature`.
pub(crate) fn fors_sig(s: &ForsSignature) -> Value {
    Value::Record(alloc::vec![
        ("fs_randomizer", Value::bytes(&s.randomizer)),
        ("fs_counter", Value::int(s.counter)),
        (
            "fs_entries",
            Value::List(s.entries.iter().map(fors_entry).collect())
        ),
    ])
}

/// `sphincs_plus_c::LayerSignature`.
pub(crate) fn layer_sig(s: &LayerSignature) -> Value {
    Value::Record(alloc::vec![
        ("ls_pk_hash", Value::bytes(&s.wots_c_pk_hash)),
        ("ls_wots", wots_sig(&s.wots_c_signature)),
        ("ls_auth_path", Value::words(&s.auth_path)),
    ])
}

/// `sphincs_plus_c::Signature`, the stateless signature.
pub(crate) fn stateless_sig(s: &StatelessSignature) -> Value {
    Value::Record(alloc::vec![
        ("sl_fors", fors_sig(&s.fors)),
        (
            "sl_layers",
            Value::List(s.hypertree.iter().map(layer_sig).collect())
        ),
    ])
}

/// `shrincs::PublicKey`, the public-key bundle.
pub(crate) fn public_key(pk: &PublicKey) -> Value {
    Value::Record(alloc::vec![
        ("pk_stateful", Value::bytes(&pk.stateful_public_key)),
        ("pk_commitment", Value::bytes(&pk.public_key_commitment)),
        ("pk_seed", Value::bytes(&pk.pk_seed)),
        ("pk_root", Value::bytes(&pk.hypertree_root)),
    ])
}

fn sample_words(label: &str, count: usize) -> Vec<[u8; HASH_LEN]> {
    (0..count)
        .map(|i| label_word(&alloc::format!("{label}/{i}")))
        .collect()
}

pub(crate) fn sample_wots_sig(label: &str, chains: usize) -> WotsCSignature {
    WotsCSignature {
        randomizer: label_word(&alloc::format!("{label}/randomizer")),
        counter: 0x0102_0304,
        chains: sample_words(&alloc::format!("{label}/chains"), chains),
    }
}

pub(crate) fn sample_stateful_sig(label: &str, chains: usize, path: usize) -> StatefulSignature {
    StatefulSignature {
        randomizer: label_word(&alloc::format!("{label}/randomizer")),
        counter: 77,
        chains: sample_words(&alloc::format!("{label}/chains"), chains),
        auth_path: sample_words(&alloc::format!("{label}/path"), path),
    }
}

pub(crate) fn sample_stateless_sig(
    label: &str,
    trees: usize,
    height: usize,
    layers: usize,
    chains: usize,
    subtree: usize,
) -> StatelessSignature {
    StatelessSignature {
        fors: ForsSignature {
            randomizer: label_word(&alloc::format!("{label}/fors")),
            counter: 5,
            entries: (0..trees)
                .map(|t| ForsEntry {
                    secret_leaf: label_word(&alloc::format!("{label}/leaf/{t}")),
                    auth_path: sample_words(&alloc::format!("{label}/fors/{t}"), height),
                })
                .collect(),
        },
        hypertree: (0..layers)
            .map(|l| LayerSignature {
                wots_c_pk_hash: label_word(&alloc::format!("{label}/pkh/{l}")),
                wots_c_signature: sample_wots_sig(&alloc::format!("{label}/wots/{l}"), chains),
                auth_path: sample_words(&alloc::format!("{label}/ht/{l}"), subtree),
            })
            .collect(),
    }
}

pub(crate) fn sample_public_key(label: &str) -> PublicKey {
    PublicKey {
        stateful_public_key: label_bytes(&alloc::format!("{label}/stateful"), 68),
        public_key_commitment: label_bytes(&alloc::format!("{label}/commitment"), 32),
        pk_seed: label_bytes(&alloc::format!("{label}/seed"), 32),
        hypertree_root: label_bytes(&alloc::format!("{label}/root"), 32),
    }
}
