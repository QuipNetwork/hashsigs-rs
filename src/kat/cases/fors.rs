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

//! Groups `fors` and `toy_fors`: the FORS-C digest, trees, signing, and
//! verification. The full profile replays verification of a real signature.
//! The reduced profile replays signing.

use super::wire::{fors_entry, fors_sig};
use super::{full_stateless, label_bytes, label_word, Full};
use crate::kat::group::Group;
use crate::kat::toy::Toy;
use crate::kat::value::Value;
use crate::profile::Profile;
use crate::sphincs_plus_c::fors_c::{
    fors_leaf_hash, fors_leaf_secret, fors_tree_root_and_auth_path, kat_access as fors,
    sign_fors_c, signer_fors_digest, verify_fors_c_and_return_root, ForsLeafCoords,
};
use crate::sphincs_plus_c::{keygen, ForsSignature};

fn coords_args(c: ForsLeafCoords) -> Vec<Value> {
    vec![
        Value::Int(c.tree_index),
        Value::int(c.leaf_index),
        Value::int(c.fors_tree),
        Value::int(c.leaf),
    ]
}

fn verify<P: Profile>(
    g: &mut Group,
    pk: &[u8; 32],
    root: &[u8; 32],
    message: &[u8],
    s: &ForsSignature,
) {
    g.call(
        "verify_fors_c",
        vec![
            Value::bytes(pk),
            Value::bytes(root),
            Value::bytes(message),
            fors_sig(s),
        ],
        || verify_fors_c_and_return_root::<P>(pk, root, message, s),
        |r| {
            Value::opt(r.map(|(fors_root, tree, leaf)| {
                Value::Tuple(vec![
                    Value::bytes(&fors_root),
                    Value::Int(tree),
                    Value::int(leaf),
                ])
            }))
        },
    );
}

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("fors");
    let word = |r: &[u8; 32]| Value::bytes(r);
    let (key, message, signature) = full_stateless();
    let pk = *key.public_key.pk_seed.as_bytes();
    let root = *key.public_key.root.as_bytes();
    let fors_signature = &signature.fors;
    let randomizer = fors_signature.randomizer;
    let counter = fors_signature.counter;

    let digest_args = |counter: u32| {
        vec![
            Value::bytes(&pk),
            Value::bytes(&root),
            Value::bytes(&randomizer),
            Value::int(counter),
            Value::bytes(message),
        ]
    };
    for c in [counter, counter + 1] {
        g.call(
            "fors_digest_bytes",
            digest_args(c),
            || fors::digest_bytes::<Full>(&pk, &root, &randomizer, c, message),
            |r| Value::bytes(r),
        );
        g.call(
            "signer_fors_digest",
            digest_args(c),
            || signer_fors_digest::<Full>(&pk, &root, message, &randomizer, c),
            |r| {
                Value::opt(r.as_ref().map(|d| {
                    let signed = usize::from(Full::NUM_FORS_TREES) - 1;
                    Value::Tuple(vec![
                        Value::Int(d.tree_index),
                        Value::int(d.leaf_index),
                        Value::List(
                            d.signed_tree_indices[..signed]
                                .iter()
                                .map(|i| Value::int(*i))
                                .collect(),
                        ),
                        Value::Bool(d.omitted_final_tree_is_zero),
                    ])
                }))
            },
        );
    }
    let digest = g.call(
        "fors_digest",
        vec![
            Value::bytes(&pk),
            Value::bytes(&root),
            Value::bytes(message),
            Value::bytes(&randomizer),
            Value::int(counter),
        ],
        || fors::digest::<Full>(&pk, &root, message, &randomizer, counter),
        |r| {
            Value::opt(r.map(|(tree, leaf, digest)| {
                Value::Tuple(vec![
                    Value::Int(tree),
                    Value::int(leaf),
                    Value::bytes(&digest),
                ])
            }))
        },
    );
    let (tree_index, leaf_index, _) = digest.unwrap_or((0, 0, [0; 64]));

    let sk = label_word("fors/sk");
    let coords = ForsLeafCoords {
        tree_index: 0x00ab_cdef_0123_4567,
        leaf_index: 200,
        fors_tree: 20,
        leaf: 16_383,
    };
    let mut args = vec![Value::bytes(&pk), Value::bytes(&sk)];
    args.extend(coords_args(coords));
    g.call(
        "fors_leaf_secret",
        args.clone(),
        || fors_leaf_secret::<Full>(&pk, &sk, coords),
        word,
    );
    g.call(
        "fors_leaf_hash",
        args,
        || fors_leaf_hash::<Full>(&pk, &sk, coords),
        word,
    );
    let roots: Vec<[u8; 32]> = (0..21)
        .map(|i| label_word(&format!("fors/root/{i}")))
        .collect();
    g.call(
        "fors_public_key_hash",
        vec![
            Value::bytes(&pk),
            Value::Int(tree_index),
            Value::int(leaf_index),
            Value::words(&roots),
        ],
        || fors::public_key_hash::<Full>(&pk, tree_index, leaf_index, &roots),
        word,
    );
    let entry = &fors_signature.entries[3];
    let entry_coords = ForsLeafCoords {
        tree_index,
        leaf_index,
        fors_tree: 3,
        leaf: 0,
    };
    let mut args = vec![Value::bytes(&pk)];
    args.extend(coords_args(entry_coords));
    args.push(fors_entry(entry));
    g.call(
        "fors_entry_root",
        args,
        || fors::entry_root::<Full>(&pk, entry_coords, entry),
        |r| Value::opt(r.map(|w| Value::bytes(&w))),
    );

    verify::<Full>(&mut g, &pk, &root, message, fors_signature);
    verify::<Full>(
        &mut g,
        &pk,
        &root,
        &label_bytes("fors/other", 32),
        fors_signature,
    );
    // Review Focus 4: the next counter does not open leaf zero of the final tree.
    let mut bumped = fors_signature.clone();
    bumped.counter += 1;
    let bumped_digest =
        signer_fors_digest::<Full>(&pk, &root, message, &randomizer, bumped.counter);
    assert!(bumped_digest.is_some_and(|d| !d.omitted_final_tree_is_zero));
    verify::<Full>(&mut g, &pk, &root, message, &bumped);
    let mut fewer = fors_signature.clone();
    fewer.entries.pop();
    verify::<Full>(&mut g, &pk, &root, message, &fewer);
    let mut short_path = fors_signature.clone();
    short_path.entries[5].auth_path.pop();
    verify::<Full>(&mut g, &pk, &root, message, &short_path);
    g
}

pub(super) fn toy_group() -> Group {
    let mut g = Group::new::<Toy>("toy_fors");
    let key = keygen::<Toy, { crate::kat::toy::TOY_LAYERS }>(
        label_word("toy_fors/sk"),
        label_word("toy_fors/prf"),
        label_word("toy_fors/pk"),
    );
    let pk = *key.public_key.pk_seed.as_bytes();
    let sk = *key.secret().as_sk_seed().as_bytes();
    let prf = *key.secret().as_prf_seed().as_bytes();
    let root = *key.public_key.root.as_bytes();
    let coords = ForsLeafCoords {
        tree_index: 2,
        leaf_index: 3,
        fors_tree: 1,
        leaf: 2,
    };
    let mut args = vec![Value::bytes(&pk), Value::bytes(&sk)];
    args.extend(coords_args(coords));
    g.call(
        "fors_tree_root_and_auth_path",
        args,
        || fors_tree_root_and_auth_path::<Toy>(&pk, &sk, coords),
        |(root, secret, path)| {
            Value::Tuple(vec![
                Value::bytes(root),
                Value::bytes(secret),
                Value::words(path),
            ])
        },
    );
    for label in ["toy_fors/message/0", "toy_fors/message/1"] {
        let message = label_bytes(label, 32);
        let signed = g.call(
            "sign_fors_c",
            vec![
                Value::bytes(&sk),
                Value::bytes(&prf),
                Value::bytes(&pk),
                Value::bytes(&root),
                Value::bytes(&message),
            ],
            || sign_fors_c::<Toy>(&key, &message),
            |r| {
                Value::opt(r.as_ref().map(|s| {
                    Value::Tuple(vec![
                        Value::bytes(&s.root),
                        fors_sig(&s.signature),
                        Value::Int(s.tree_index),
                        Value::int(s.leaf_index),
                    ])
                }))
            },
        );
        if let Some(signed) = signed {
            verify::<Toy>(&mut g, &pk, &root, &message, &signed.signature);
        }
    }
    g
}
