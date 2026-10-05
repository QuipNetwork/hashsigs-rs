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

//! Groups `envelopes` and `toy_envelopes`: every decoder, on canonical input
//! and on input that the decoder must reject. Review Focus 1: truncated,
//! padded, and re-ordered envelopes.
//!
//! The stateless decoders replay at the reduced profile. A full-size
//! stateless envelope has about 55 kilobytes, and the evaluation of the
//! decoder slices it once for each field.

use super::wire::{
    fors_entry, fors_sig, layer_sig, public_key, sample_public_key, sample_stateful_sig,
    sample_stateless_sig, sample_wots_sig, stateful_sig, stateless_sig, wots_sig,
};
use super::{label_bytes, Full};
use crate::kat::group::Group;
use crate::kat::toy::Toy;
use crate::kat::value::Value;
use crate::profile::Profile;
use crate::shrincs::{
    decode_stateful_envelope, decode_stateless_envelope, encode_stateful_envelope,
    encode_stateless_envelope, PublicKey, Signature as StatefulSignature,
};
use crate::sphincs_plus_c::{
    ForsEntry, ForsSignature, LayerSignature, Signature as StatelessSignature,
};
use crate::wots_c::Signature as WotsCSignature;

/// Canonical bytes, then the same bytes cut by one byte, with 32 zero bytes
/// appended, and with one byte of the first head word changed.
fn variants(canonical: &[u8]) -> Vec<Vec<u8>> {
    let mut truncated = canonical.to_vec();
    truncated.pop();
    let mut padded = canonical.to_vec();
    padded.extend_from_slice(&[0; 32]);
    let mut moved = canonical.to_vec();
    moved[31] = moved[31].wrapping_add(32);
    vec![canonical.to_vec(), truncated, padded, moved]
}

fn decode_cases<T>(
    g: &mut Group,
    operator: &'static str,
    canonical: &[u8],
    decode: impl Fn(&[u8]) -> Option<T>,
    value: impl Fn(&T) -> Value,
) {
    for data in variants(canonical) {
        g.call(
            operator,
            vec![Value::bytes(&data)],
            || decode(&data),
            |r| Value::opt(r.as_ref().map(&value)),
        );
    }
}

fn pair(a: Value, b: Value) -> Value {
    Value::Tuple(vec![a, b])
}

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("envelopes");
    let chains = usize::from(Full::NUM_WOTS_CHAINS);
    let wots = sample_wots_sig("env/wots", chains);
    decode_cases(
        &mut g,
        "wots_sig_from_bytes",
        &wots.to_bytes(),
        WotsCSignature::from_bytes::<Full>,
        wots_sig,
    );
    let stateful = sample_stateful_sig("env/sf", chains, 3);
    decode_cases(
        &mut g,
        "stateful_sig_from_bytes",
        &stateful.to_bytes(),
        StatefulSignature::from_bytes::<Full>,
        stateful_sig,
    );
    let pk = sample_public_key("env/pk");
    decode_cases(
        &mut g,
        "public_key_from_bytes",
        &pk.to_bytes(),
        PublicKey::from_bytes,
        public_key,
    );
    let envelope = encode_stateful_envelope(&pk, &stateful);
    let pair_value = |(p, s): &(PublicKey, StatefulSignature)| pair(public_key(p), stateful_sig(s));
    decode_cases(
        &mut g,
        "decode_stateful_envelope",
        &envelope,
        decode_stateful_envelope::<Full>,
        pair_value,
    );
    // Re-ordered: the signature body first, then the public-key body, with
    // the two head offsets swapped. Every field is in range, and the decoder
    // must still reject the encoding, because it is not canonical.
    let pk_body = pk.to_bytes()[32..].to_vec();
    let sig_body = stateful.to_bytes()[32..].to_vec();
    let mut reordered = Vec::new();
    reordered.extend_from_slice(&crate::abi::word_from_usize(64 + sig_body.len()));
    reordered.extend_from_slice(&crate::abi::word_from_usize(64));
    reordered.extend_from_slice(&sig_body);
    reordered.extend_from_slice(&pk_body);
    g.call(
        "decode_stateful_envelope",
        vec![Value::bytes(&reordered)],
        || decode_stateful_envelope::<Full>(&reordered),
        |r| Value::opt(r.as_ref().map(pair_value)),
    );
    // Too many chains: the bound of the decoder.
    let over = sample_stateful_sig("env/over", chains + 1, 1);
    let over_bytes = over.to_bytes();
    g.call(
        "stateful_sig_from_bytes",
        vec![Value::bytes(&over_bytes)],
        || StatefulSignature::from_bytes::<Full>(&over_bytes),
        |r| Value::opt(r.as_ref().map(stateful_sig)),
    );
    for len in [67usize, 68] {
        let encoded = label_bytes("env/stateful-pk", len);
        g.call(
            "decode_stateful_public_key",
            vec![Value::bytes(&encoded)],
            || crate::shrincs::decode_stateful_public_key(&encoded),
            |r| {
                Value::opt(r.map(|k| {
                    Value::Tuple(vec![
                        Value::bytes(&k.pk_seed),
                        Value::bytes(&k.root),
                        Value::int(k.max_signatures),
                    ])
                }))
            },
        );
    }
    g
}

pub(super) fn toy_group() -> Group {
    let mut g = Group::new::<Toy>("toy_envelopes");
    let trees = usize::from(Toy::NUM_FORS_TREES) - 1;
    let height = usize::from(Toy::FORS_TREE_HEIGHT);
    let layers = usize::from(Toy::NUM_HYPERTREE_LAYERS);
    let chains = usize::from(Toy::NUM_WOTS_CHAINS);
    let subtree = usize::from(Toy::HYPERTREE_HEIGHT / Toy::NUM_HYPERTREE_LAYERS);
    let stateless = sample_stateless_sig("toyenv/sl", trees, height, layers, chains, subtree);
    let entry = &stateless.fors.entries[0];
    decode_cases(
        &mut g,
        "fors_entry_from_bytes",
        &entry.to_bytes(),
        ForsEntry::from_bytes::<Toy>,
        fors_entry,
    );
    decode_cases(
        &mut g,
        "fors_sig_from_bytes",
        &stateless.fors.to_bytes(),
        ForsSignature::from_bytes::<Toy>,
        fors_sig,
    );
    let layer = &stateless.hypertree[0];
    decode_cases(
        &mut g,
        "layer_sig_from_bytes",
        &layer.to_bytes(),
        LayerSignature::from_bytes::<Toy>,
        layer_sig,
    );
    decode_cases(
        &mut g,
        "stateless_sig_from_bytes",
        &stateless.to_bytes(),
        StatelessSignature::from_bytes::<Toy>,
        stateless_sig,
    );
    let pk = sample_public_key("toyenv/pk");
    let envelope = encode_stateless_envelope(&pk, &stateless);
    decode_cases(
        &mut g,
        "decode_stateless_envelope",
        &envelope,
        decode_stateless_envelope::<Toy>,
        |(p, s)| pair(public_key(p), stateless_sig(s)),
    );
    // One FORS entry too many, and a layer path one node too long.
    let mut extra_entry = stateless.clone();
    extra_entry.fors.entries.push(entry.clone());
    extra_entry.fors.entries.push(entry.clone());
    let mut long_path = stateless.clone();
    long_path.hypertree[1].auth_path.push(layer.auth_path[0]);
    for s in [extra_entry, long_path] {
        let data = s.to_bytes();
        g.call(
            "stateless_sig_from_bytes",
            vec![Value::bytes(&data)],
            || StatelessSignature::from_bytes::<Toy>(&data),
            |r| Value::opt(r.as_ref().map(stateless_sig)),
        );
    }
    g
}
