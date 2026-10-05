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

//! Groups `hypertree` and `toy_sphincs`: the hypertree, SPHINCS+C key
//! generation, signing, and verification. The full profile replays the
//! verification of a real signature. The reduced profile replays key
//! generation and signing.

use super::wire::{layer_sig, stateless_sig};
use super::{full_stateless, label_bytes, label_word, Full};
use crate::kat::group::Group;
use crate::kat::toy::{Toy, TOY_CHAINS, TOY_LAYERS};
use crate::kat::value::Value;
use crate::profile::Profile;
use crate::sphincs_plus_c::hypertree::{
    hypertree_public_root, kat_access as ht, sign_hypertree, verify_hypertree, HypertreeSeed,
};
use crate::sphincs_plus_c::{fors_c, keygen_from_master_seed, sign, verify, Key, LayerSignature};

fn verify_layers<P: Profile, const NUM_CHAINS: usize>(
    g: &mut Group,
    key: &Key,
    (fors_root, tree, leaf): ([u8; 32], u64, u32),
    layers: &[LayerSignature],
) -> bool {
    let pk = *key.public_key.pk_seed.as_bytes();
    let root = *key.public_key.root.as_bytes();
    g.call(
        "verify_hypertree",
        vec![
            Value::bytes(&pk),
            Value::bytes(&root),
            Value::bytes(&fors_root),
            Value::Int(tree),
            Value::int(leaf),
            Value::List(layers.iter().map(layer_sig).collect()),
        ],
        || {
            verify_hypertree::<P, NUM_CHAINS>(
                &pk,
                &root,
                fors_root,
                HypertreeSeed {
                    tree_index: tree,
                    leaf_index: leaf,
                },
                layers,
            )
        },
        |r| Value::Bool(*r),
    )
}

fn verify_sphincs<P: Profile, const NUM_CHAINS: usize>(
    g: &mut Group,
    key: &Key,
    message: &[u8],
    signature: &crate::sphincs_plus_c::Signature,
) -> bool {
    let pk = *key.public_key.pk_seed.as_bytes();
    let root = *key.public_key.root.as_bytes();
    g.call(
        "sphincs_verify",
        vec![
            Value::bytes(&pk),
            Value::bytes(&root),
            Value::bytes(message),
            stateless_sig(signature),
        ],
        || verify::<P, NUM_CHAINS>(&key.public_key, message, signature),
        |r| Value::Bool(*r),
    )
}

/// The FORS root and hypertree position of a valid signature.
fn fors_position<P: Profile>(
    key: &Key,
    message: &[u8],
    s: &crate::sphincs_plus_c::Signature,
) -> ([u8; 32], u64, u32) {
    fors_c::verify_fors_c_and_return_root::<P>(
        key.public_key.pk_seed.as_bytes(),
        key.public_key.root.as_bytes(),
        message,
        &s.fors,
    )
    .unwrap_or_else(super::grind_failed)
}

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("hypertree");
    let (key, message, signature) = full_stateless();
    let pk = *key.public_key.pk_seed.as_bytes();
    let position = fors_position::<Full>(key, message, signature);

    let layer_seeds = ht::layer_seeds::<Full, 8>(key.secret().as_sk_seed().as_bytes());
    g.call(
        "hypertree_layer_seeds",
        vec![Value::bytes(key.secret().as_sk_seed().as_bytes())],
        || ht::layer_seeds::<Full, 8>(key.secret().as_sk_seed().as_bytes()),
        |r| Value::words(r),
    );
    g.call(
        "hypertree_leaf_seeds",
        vec![
            Value::bytes(&layer_seeds[2]),
            Value::Int(0x0102_0304_0506),
            Value::int(77u32),
        ],
        || ht::leaf_seeds::<Full>(&layer_seeds[2], 0x0102_0304_0506, 77),
        |(a, b)| Value::Tuple(vec![Value::bytes(a), Value::bytes(b)]),
    );
    g.call(
        "hypertree_leaf",
        vec![
            Value::bytes(&pk),
            Value::bytes(&layer_seeds[1]),
            Value::int(1u32),
            Value::Int(9),
            Value::int(3u32),
        ],
        || ht::leaf::<Full>(&pk, &layer_seeds[1], (1, 9, 3)),
        |r| Value::bytes(r),
    );
    let layer = &signature.hypertree[0];
    g.call(
        "hypertree_root_from_path",
        vec![
            Value::bytes(&pk),
            Value::int(0u32),
            Value::Int(position.1),
            Value::int(position.2),
            Value::bytes(&layer.wots_c_pk_hash),
            Value::words(&layer.auth_path),
        ],
        || {
            ht::root_from_path::<Full>(
                &pk,
                (0, position.1, position.2),
                layer.wots_c_pk_hash,
                &layer.auth_path,
            )
        },
        |r| Value::opt(r.map(|w| Value::bytes(&w))),
    );

    assert!(verify_layers::<Full, 64>(
        &mut g,
        key,
        position,
        &signature.hypertree
    ));
    // Review Focus 5: a changed tree index.
    verify_layers::<Full, 64>(
        &mut g,
        key,
        (position.0, position.1 ^ 1, position.2),
        &signature.hypertree,
    );
    verify_layers::<Full, 64>(
        &mut g,
        key,
        (label_word("ht/other"), position.1, position.2),
        &signature.hypertree,
    );
    verify_layers::<Full, 64>(&mut g, key, position, &signature.hypertree[..7]);
    assert!(verify_sphincs::<Full, 64>(&mut g, key, message, signature));
    verify_sphincs::<Full, 64>(&mut g, key, &label_bytes("ht/other-message", 32), signature);
    g
}

pub(super) fn toy_group() -> Group {
    let mut g = Group::new::<Toy>("toy_sphincs");
    let seed = label_bytes("toy_sphincs/seed", 40);
    let key = g.call(
        "keygen_from_master_seed",
        vec![Value::bytes(&seed)],
        || keygen_from_master_seed::<Toy, TOY_LAYERS>(&seed),
        |k| {
            Value::Tuple(vec![
                Value::bytes(k.secret().as_sk_seed().as_bytes()),
                Value::bytes(k.secret().as_prf_seed().as_bytes()),
                Value::bytes(k.public_key.pk_seed.as_bytes()),
                Value::bytes(k.public_key.root.as_bytes()),
            ])
        },
    );
    let sk = *key.secret().as_sk_seed().as_bytes();
    let prf = *key.secret().as_prf_seed().as_bytes();
    let pk = *key.public_key.pk_seed.as_bytes();
    let root = *key.public_key.root.as_bytes();
    g.call(
        "hypertree_public_root",
        vec![Value::bytes(&sk), Value::bytes(&pk)],
        || hypertree_public_root::<Toy, TOY_LAYERS>(&sk, &pk),
        |r| Value::bytes(r),
    );
    let layer_seed = ht::layer_seeds::<Toy, TOY_LAYERS>(&sk)[1];
    for selected in [0u32, 3, 4] {
        g.call(
            "hypertree_subtree",
            vec![
                Value::bytes(&pk),
                Value::bytes(&layer_seed),
                Value::int(1u32),
                Value::Int(0),
                Value::int(selected),
            ],
            || ht::subtree::<Toy>(&pk, &layer_seed, (1, 0, selected)),
            |r| {
                Value::opt(r.as_ref().map(|(root, leaf, path)| {
                    Value::Tuple(vec![
                        Value::bytes(root),
                        Value::bytes(leaf),
                        Value::words(path),
                    ])
                }))
            },
        );
    }
    let fors_root = label_word("toy_sphincs/fors-root");
    let layers = g.call(
        "sign_hypertree",
        vec![
            Value::bytes(&sk),
            Value::bytes(&prf),
            Value::bytes(&pk),
            Value::bytes(&fors_root),
            Value::Int(2),
            Value::int(1u32),
        ],
        || sign_hypertree::<Toy, TOY_LAYERS>(&key, fors_root, 2, 1),
        |r| {
            Value::opt(
                r.as_ref()
                    .map(|ls| Value::List(ls.iter().map(layer_sig).collect())),
            )
        },
    );
    if let Some(layers) = layers {
        assert!(verify_layers::<Toy, TOY_CHAINS>(
            &mut g,
            &key,
            (fors_root, 2, 1),
            &layers
        ));
        // Review Focus 5: a tree index past the top of the hypertree.
        verify_layers::<Toy, TOY_CHAINS>(&mut g, &key, (fors_root, 2 + 16, 1), &layers);
    }
    let message = label_bytes("toy_sphincs/message", 32);
    let signature = g.call(
        "sphincs_sign",
        vec![
            Value::bytes(&sk),
            Value::bytes(&prf),
            Value::bytes(&pk),
            Value::bytes(&root),
            Value::bytes(&message),
        ],
        || sign::<Toy, TOY_LAYERS>(&key, &message),
        |r| Value::opt(r.as_ref().map(stateless_sig)),
    );
    if let Some(signature) = signature {
        assert!(verify_sphincs::<Toy, TOY_CHAINS>(
            &mut g, &key, &message, &signature
        ));
        verify_sphincs::<Toy, TOY_CHAINS>(
            &mut g,
            &key,
            &label_bytes("toy_sphincs/other", 32),
            &signature,
        );
        let mut empty = signature.clone();
        empty.hypertree.clear();
        verify_sphincs::<Toy, TOY_CHAINS>(&mut g, &key, &message, &empty);
    }
    g
}
