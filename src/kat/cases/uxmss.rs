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

//! Group `uxmss`: the unbalanced stateful tree, signing at a leaf, signing
//! with the leaf counter, and verification, at a budget of four leaves.

use super::wire::stateful_sig;
use super::{label_bytes, label_word, Full};
use crate::kat::group::Group;
use crate::kat::value::Value;
use crate::shrincs::uxmss::{
    self, kat_access as sf, sign_stateful_raw, sign_stateful_raw_at_leaf, stateful_empty_tail,
    stateful_parent_hash, stateful_subtree_root, verify_stateful_unsafe_raw,
};
use crate::shrincs::Signature;

const CHAINS: usize = 64;
const MAX: u32 = 4;

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("uxmss");
    let word = |r: &[u8; 32]| Value::bytes(r);
    let sk = label_word("uxmss/sk");
    let prf = label_word("uxmss/prf");
    let pk = label_word("uxmss/pk");
    let message = label_bytes("uxmss/message", 32);
    let (left, right) = (label_word("uxmss/left"), label_word("uxmss/right"));

    g.call(
        "stateful_parent_hash",
        vec![
            Value::bytes(&pk),
            Value::int(3u32),
            Value::bytes(&left),
            Value::bytes(&right),
        ],
        || stateful_parent_hash::<Full>(&pk, 3, left, right),
        word,
    );
    g.call(
        "stateful_empty_tail",
        vec![Value::bytes(&pk), Value::int(MAX)],
        || stateful_empty_tail::<Full>(&pk, MAX),
        word,
    );
    let root = g.call(
        "stateful_subtree_root",
        vec![
            Value::bytes(&sk),
            Value::bytes(&pk),
            Value::int(1u32),
            Value::int(MAX),
        ],
        || stateful_subtree_root::<Full, CHAINS>(&sk, &pk, 1, MAX),
        word,
    );
    for leaf in [1u32, MAX] {
        g.call(
            "stateful_auth_path",
            vec![
                Value::bytes(&sk),
                Value::bytes(&pk),
                Value::int(leaf),
                Value::int(MAX),
            ],
            || sf::auth_path::<Full, CHAINS>(&sk, &pk, leaf, MAX),
            |r| Value::words(r),
        );
    }

    let key = |next: u32| {
        uxmss::Key::new(
            uxmss::PrivateKey::new(uxmss::SkSeed::new(sk), uxmss::PrfSeed::new(prf)),
            uxmss::StructuredPublicKey {
                pk_seed: uxmss::PkSeed::new(pk),
                root: uxmss::Root::new(root),
                max_signatures: MAX,
            },
            next,
        )
    };
    let key_args = || {
        vec![
            Value::bytes(&sk),
            Value::bytes(&prf),
            Value::bytes(&pk),
            Value::int(MAX),
        ]
    };
    let mut signatures = Vec::new();
    for leaf in [0u32, 1, MAX, MAX + 1] {
        let mut args = key_args();
        args.extend([Value::int(leaf), Value::bytes(&message)]);
        let signature = g.call(
            "sign_stateful_at_leaf",
            args,
            || sign_stateful_raw_at_leaf::<Full, CHAINS>(&key(1), leaf, &message),
            |r| Value::opt(r.as_ref().map(stateful_sig)),
        );
        signatures.extend(signature);
    }
    for next in [MAX, MAX + 1] {
        let mut args = key_args();
        args.extend([Value::int(next), Value::bytes(&message)]);
        g.call(
            "sign_stateful_next",
            args,
            || {
                let mut key = key(next);
                sign_stateful_raw::<Full, CHAINS>(&mut key, &message)
                    .map(|s| (s, key.next_leaf_index()))
            },
            |r| {
                Value::opt(
                    r.as_ref()
                        .map(|(s, next)| Value::Tuple(vec![stateful_sig(s), Value::int(*next)])),
                )
            },
        );
    }

    // Leaf 1's path holds the subtree root of leaves 2 to 4, then nothing.
    let leaf_pk = sf::wots_pk_hash::<Full, CHAINS>(&sk, &pk, 1);
    for (leaf, path) in [
        (1u32, &signatures[0].auth_path),
        (2, &signatures[0].auth_path),
        (0, &vec![]),
    ] {
        g.call(
            "root_from_unbalanced_path",
            vec![
                Value::bytes(&pk),
                Value::int(leaf),
                Value::bytes(&leaf_pk),
                Value::words(path),
            ],
            || sf::root_from_path::<Full>(pk, leaf, leaf_pk, path),
            |r| Value::opt(r.map(|w| Value::bytes(&w))),
        );
    }

    let verify = |g: &mut Group, root: [u8; 32], message: &[u8], s: &Signature| {
        let public = uxmss::PublicKey {
            pk_seed: pk,
            root,
            max_signatures: MAX,
        };
        g.call(
            "uxmss_verify",
            vec![
                Value::bytes(&pk),
                Value::bytes(&root),
                Value::int(MAX),
                Value::bytes(message),
                stateful_sig(s),
            ],
            || verify_stateful_unsafe_raw::<Full, CHAINS>(&public, message, s),
            |r| Value::Bool(*r),
        )
    };
    for signature in &signatures {
        assert!(verify(&mut g, root, &message, signature));
    }
    let first = signatures[0].clone();
    verify(&mut g, label_word("uxmss/other-root"), &message, &first);
    verify(&mut g, root, &label_bytes("uxmss/other", 32), &first);
    // Review Focus 2: a path of length 0 and a path of length MAX + 1.
    let mut empty = first.clone();
    empty.auth_path.clear();
    verify(&mut g, root, &message, &empty);
    let mut long = signatures[1].clone();
    long.auth_path.push(label_word("uxmss/extra"));
    verify(&mut g, root, &message, &long);
    let mut short = first;
    short.chains.pop();
    verify(&mut g, root, &message, &short);
    g
}
