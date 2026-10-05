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

//! Group `wots_c`: the WOTS-C chains, public-key hashes, digests, signing
//! (with the grind), and verification, for the stateful (UXMSS) binding and
//! the stateless (hypertree) binding.

use super::wire::{stateful_sig, wots_sig};
use super::{grind_failed, label_bytes, label_word, Full};
use crate::kat::group::Group;
use crate::kat::value::Value;
use crate::shrincs::uxmss::kat_access as sf;
use crate::sphincs_plus_c::hypertree::kat_access as sl;
use crate::sphincs_plus_c::hypertree::{
    stateless_wots_message_digest, stateless_wots_public_key_hash,
};
use crate::wots_c::ChainWalk;

const CHAINS: usize = 64;

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("wots_c");
    let word = |r: &[u8; 32]| Value::bytes(r);
    let opt_word = |r: &Option<[u8; 32]>| Value::opt(r.map(|w| Value::bytes(&w)));
    let sk = label_word("wots/sk");
    let prf = label_word("wots/prf");
    let pk = label_word("wots/pk");
    let message = label_bytes("wots/message", 32);

    // Stateful binding.
    for (leaf, chain) in [(1u32, 0u32), (4096, 63)] {
        g.call(
            "stateful_chain_secret",
            vec![
                Value::bytes(&sk),
                Value::bytes(&pk),
                Value::int(leaf),
                Value::int(chain),
            ],
            || sf::chain_secret::<Full>(&sk, &pk, leaf, chain),
            word,
        );
    }
    let value = label_word("wots/value");
    for (start, steps) in [(0u32, 15u32), (3, 5), (7, 0)] {
        g.call(
            "stateful_chain",
            vec![
                Value::bytes(&pk),
                Value::int(2u32),
                Value::int(5u32),
                Value::bytes(&value),
                Value::int(start),
                Value::int(steps),
            ],
            || {
                sf::chain::<Full>(
                    &pk,
                    2,
                    5,
                    ChainWalk {
                        value,
                        start,
                        steps,
                    },
                )
            },
            word,
        );
    }
    let leaf_pk = g.call(
        "stateful_wots_pk_hash",
        vec![Value::bytes(&sk), Value::bytes(&pk), Value::int(1u32)],
        || sf::wots_pk_hash::<Full, CHAINS>(&sk, &pk, 1),
        word,
    );
    let signature = g.call(
        "sign_stateful_wots_c",
        vec![
            Value::bytes(&sk),
            Value::bytes(&prf),
            Value::bytes(&pk),
            Value::int(1u32),
            Value::bytes(&message),
        ],
        || sf::sign_wots_c::<Full>(&sk, &prf, &pk, 1, &message),
        |r| Value::opt(r.as_ref().map(stateful_sig)),
    );
    let signature = signature.unwrap_or_else(grind_failed);
    let from_sig = |g: &mut Group, message: &[u8], signature: &crate::shrincs::Signature| {
        g.call(
            "stateful_wots_pk_from_sig",
            vec![
                Value::bytes(&pk),
                Value::int(1u32),
                Value::bytes(message),
                stateful_sig(signature),
            ],
            || sf::wots_pk_from_sig::<Full, CHAINS>(pk, 1, message, signature),
            opt_word,
        )
    };
    let recovered = from_sig(&mut g, &message, &signature);
    assert_eq!(
        recovered,
        Some(leaf_pk),
        "a valid WOTS-C signature recovers its key"
    );
    from_sig(&mut g, &label_bytes("wots/other", 32), &signature);
    let mut short = signature.clone();
    short.chains.pop();
    from_sig(&mut g, &message, &short);
    let mut bumped = signature.clone();
    bumped.counter += 1;
    from_sig(&mut g, &message, &bumped);

    // Stateless binding.
    let coords = (3u32, 0x0102_0304_0506u64, 200u32);
    let (layer, tree, keypair) = coords;
    let at = || vec![Value::int(layer), Value::Int(tree), Value::int(keypair)];
    for chain in [0u32, 63] {
        g.call(
            "stateless_wots_c_secret",
            vec![Value::bytes(&sk), Value::int(chain)],
            || sl::wots_secret::<Full>(&sk, chain),
            word,
        );
    }
    for (start, steps) in [(0u32, 15u32), (9, 6)] {
        let mut args = vec![Value::bytes(&pk)];
        args.extend(at());
        args.extend([
            Value::int(17u32),
            Value::bytes(&value),
            Value::int(start),
            Value::int(steps),
        ]);
        g.call(
            "stateless_wots_chain",
            args,
            || sl::wots_chain::<Full>(&pk, (layer, tree, keypair, 17), value, start, steps),
            word,
        );
    }
    let endpoints: Vec<[u8; 32]> = (0..CHAINS)
        .map(|i| label_word(&format!("wots/end/{i}")))
        .collect();
    let mut args = vec![Value::bytes(&pk)];
    args.extend(at());
    args.push(Value::words(&endpoints));
    g.call(
        "stateless_wots_public_key_hash",
        args,
        || stateless_wots_public_key_hash::<Full>(&pk, layer, tree, keypair, &endpoints),
        word,
    );
    let mut args = vec![Value::bytes(&pk), Value::bytes(&sk)];
    args.extend(at());
    let pk_hash = g.call(
        "stateless_wots_c_public_key",
        args,
        || sl::wots_public_key::<Full>(&pk, &sk, coords),
        word,
    );
    let root = label_word("wots/root");
    g.call(
        "stateless_wots_message_digest",
        vec![
            Value::bytes(&pk),
            Value::bytes(&pk_hash),
            Value::bytes(&value),
            Value::int(9u32),
            Value::bytes(&root),
        ],
        || stateless_wots_message_digest::<Full>(&pk, &pk_hash, &value, 9, &root),
        word,
    );
    let mut args = vec![Value::bytes(&pk), Value::bytes(&sk), Value::bytes(&prf)];
    args.extend(at());
    args.extend([Value::bytes(&pk_hash), Value::bytes(&root)]);
    let signature = g.call(
        "sign_stateless_wots_c",
        args,
        || sl::sign_wots_c::<Full>((&pk, &sk, &prf), coords, &pk_hash, &root),
        |r| Value::opt(r.as_ref().map(wots_sig)),
    );
    let signature = signature.unwrap_or_else(grind_failed);
    let verify =
        |g: &mut Group, expected: &[u8; 32], message: [u8; 32], s: &crate::wots_c::Signature| {
            let mut args = vec![Value::bytes(&pk)];
            args.extend(at());
            args.extend([Value::bytes(expected), Value::bytes(&message), wots_sig(s)]);
            g.call(
                "verify_wots_c",
                args,
                || sl::verify_wots_c::<Full, CHAINS>(&pk, coords, expected, message, s),
                |r| Value::Bool(*r),
            )
        };
    assert!(verify(&mut g, &pk_hash, root, &signature));
    verify(&mut g, &label_word("wots/wrong-pk"), root, &signature);
    verify(&mut g, &pk_hash, label_word("wots/wrong-root"), &signature);
    let mut short = signature.clone();
    short.chains.pop();
    verify(&mut g, &pk_hash, root, &short);
    g
}
