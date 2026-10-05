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

//! Group `abi`: the Solidity ABI encoders and the encoding of every wire type.

use super::wire::{
    public_key, sample_public_key, sample_stateful_sig, sample_stateless_sig, sample_wots_sig,
    stateful_sig, stateless_sig, wots_sig,
};
use super::{label_bytes, label_word, Full};
use crate::abi::{
    encode_bytes, encode_bytes32_array, encode_dynamic_array, encode_tuple, pad_len, word_from_u32,
    word_from_usize, Field,
};
use crate::kat::group::Group;
use crate::kat::value::Value;
use crate::shrincs::{encode_stateful_envelope, encode_stateless_envelope};
use crate::sphincs_plus_c::encode_public_key;

fn field_value(field: &Field) -> Value {
    match field {
        Field::Static(word) => Value::Ctor("Static", vec![Value::bytes(word)]),
        Field::Dynamic(bytes) => Value::Ctor("Dynamic", vec![Value::bytes(bytes)]),
    }
}

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("abi");
    let bytes = |r: &Vec<u8>| Value::bytes(r);
    for x in [0u32, 7, u32::MAX] {
        g.call(
            "word_from_u32",
            vec![Value::int(x)],
            || word_from_u32(x),
            |r| Value::bytes(r),
        );
    }
    for x in [0usize, 4096, usize::MAX] {
        g.call(
            "word_from_usize",
            vec![Value::Int(x as u64)],
            || word_from_usize(x),
            |r| Value::bytes(r),
        );
    }
    for len in [0usize, 1, 31, 32, 33, 68] {
        g.call(
            "pad_len",
            vec![Value::Int(len as u64)],
            || pad_len(len),
            |r| Value::Int(*r as u64),
        );
    }
    for len in [0usize, 1, 32, 33, 68] {
        let data = label_bytes("encode_bytes", len);
        g.call(
            "encode_bytes",
            vec![Value::bytes(&data)],
            || encode_bytes(&data),
            bytes,
        );
    }
    for count in [0usize, 1, 3] {
        let items: Vec<[u8; 32]> = (0..count)
            .map(|i| label_word(&format!("b32/{i}")))
            .collect();
        g.call(
            "encode_bytes32_array",
            vec![Value::words(&items)],
            || encode_bytes32_array(&items),
            bytes,
        );
    }
    for sizes in [&[][..], &[32usize][..], &[64, 0, 96][..]] {
        let elements: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(i, n)| label_bytes(&format!("dyn/{i}"), *n))
            .collect();
        g.call(
            "encode_dynamic_array",
            vec![Value::List(
                elements.iter().map(|e| Value::bytes(e)).collect(),
            )],
            || encode_dynamic_array(elements.clone()),
            bytes,
        );
    }
    let tuples: [Vec<Field>; 3] = [
        vec![],
        vec![
            Field::Static(label_word("t/0")),
            Field::Dynamic(label_bytes("t/1", 64)),
        ],
        vec![
            Field::Dynamic(label_bytes("t/2", 32)),
            Field::Static(label_word("t/3")),
            Field::Dynamic(vec![]),
            Field::Dynamic(label_bytes("t/4", 96)),
        ],
    ];
    for fields in tuples {
        let argument = Value::List(fields.iter().map(field_value).collect());
        g.call(
            "encode_tuple",
            vec![argument],
            || encode_tuple(fields),
            bytes,
        );
    }

    let wots = sample_wots_sig("abi/wots", 3);
    g.call(
        "wots_sig_to_bytes",
        vec![wots_sig(&wots)],
        || wots.to_bytes(),
        bytes,
    );
    let stateful = sample_stateful_sig("abi/sf", 3, 2);
    g.call(
        "stateful_sig_to_bytes",
        vec![stateful_sig(&stateful)],
        || stateful.to_bytes(),
        bytes,
    );
    let stateless = sample_stateless_sig("abi/sl", 2, 2, 2, 3, 2);
    for entry in &stateless.fors.entries {
        g.call(
            "fors_entry_to_bytes",
            vec![super::wire::fors_entry(entry)],
            || entry.to_bytes(),
            bytes,
        );
    }
    g.call(
        "fors_sig_to_bytes",
        vec![super::wire::fors_sig(&stateless.fors)],
        || stateless.fors.to_bytes(),
        bytes,
    );
    let layer = &stateless.hypertree[0];
    g.call(
        "layer_sig_to_bytes",
        vec![super::wire::layer_sig(layer)],
        || layer.to_bytes(),
        bytes,
    );
    g.call(
        "stateless_sig_to_bytes",
        vec![stateless_sig(&stateless)],
        || stateless.to_bytes(),
        bytes,
    );
    let pk = sample_public_key("abi/pk");
    g.call(
        "public_key_to_bytes",
        vec![public_key(&pk)],
        || pk.to_bytes(),
        bytes,
    );
    g.call(
        "encode_stateful_envelope",
        vec![public_key(&pk), stateful_sig(&stateful)],
        || encode_stateful_envelope(&pk, &stateful),
        bytes,
    );
    g.call(
        "encode_stateless_envelope",
        vec![public_key(&pk), stateless_sig(&stateless)],
        || encode_stateless_envelope(&pk, &stateless),
        bytes,
    );
    let (seed, root) = (label_word("abi/seed"), label_word("abi/root"));
    g.call(
        "encode_public_key",
        vec![Value::bytes(&seed), Value::bytes(&root)],
        || encode_public_key(seed, root),
        |r| Value::bytes(r),
    );
    g.call(
        "encode_stateful_public_key",
        vec![
            Value::bytes(&seed),
            Value::bytes(&root),
            Value::int(4096u32),
        ],
        || crate::shrincs::encode_stateful_public_key(seed, root, 4096),
        bytes,
    );
    g
}
