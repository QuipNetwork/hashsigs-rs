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

//! Group `addresses`: the ADRS address words.

use super::Full;
use crate::hash::{
    address_word32, fors_address_word, fors_roots_address_word, hypertree_address_word,
    wots_address_base, wots_chain_address_word, wots_pk_address_word, AddressWord32,
};
use crate::kat::group::Group;
use crate::kat::value::Value;

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("addresses");
    let word = |r: &[u8; 32]| Value::bytes(r);
    let full = (0x0102_0304u32, 0x0506_0708_090a_0b0cu64, 0x0d0e_0f10u32);
    for (layer, tree, keypair) in [(0, 0, 0), full, (u32::MAX, u64::MAX, u32::MAX)] {
        g.call(
            "address_word32",
            [
                layer.into(),
                tree,
                3,
                keypair.into(),
                0x1112_1314,
                0x1516_1718,
            ]
            .map(Value::Int)
            .to_vec(),
            || {
                address_word32(AddressWord32 {
                    layer,
                    tree,
                    address_type: 3,
                    keypair,
                    chain: 0x1112_1314,
                    step: 0x1516_1718,
                })
            },
            word,
        );
        let args = vec![Value::int(layer), Value::Int(tree), Value::int(keypair)];
        let base = g.call(
            "wots_address_base",
            args.clone(),
            || wots_address_base(layer, tree, keypair),
            word,
        );
        g.call(
            "wots_pk_address_word",
            args,
            || wots_pk_address_word(layer, tree, keypair),
            word,
        );
        g.call(
            "wots_chain_address_word",
            vec![Value::bytes(&base), Value::int(63u32), Value::int(14u32)],
            || wots_chain_address_word(base, 63, 14),
            word,
        );
        g.call(
            "fors_roots_address_word",
            vec![Value::Int(tree), Value::int(keypair)],
            || fors_roots_address_word(tree, keypair),
            word,
        );
    }
    for (tree, leaf, height, low) in [
        (0u64, 0u32, 0u32, 0u64),
        (7, 255, 14, (21 << 14) + 9),
        (u64::MAX, 3, 1, 1),
    ] {
        g.call(
            "fors_address_word",
            vec![
                Value::Int(tree),
                Value::int(leaf),
                Value::int(height),
                Value::Int(low),
            ],
            || fors_address_word(tree, leaf, height, low),
            word,
        );
    }
    for (layer, tree, height, parent) in [
        (0u32, 0u64, 1u32, 0u64),
        (7, 0x00ff_ffff_ffff_ffff, 8, 0),
        (3, 12, 5, 7),
    ] {
        g.call(
            "hypertree_address_word",
            vec![
                Value::int(layer),
                Value::Int(tree),
                Value::int(height),
                Value::Int(parent),
            ],
            || hypertree_address_word(layer, tree, height, parent),
            word,
        );
    }
    g
}
