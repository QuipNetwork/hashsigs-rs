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

//! Group `helpers`: byte helpers, the profile identity, and `derive32`.

use super::{label_bytes, label_word, Full};
use crate::hash::backend::keccak256v;
use crate::hash::{base_w_digit, derive32, read_bits32, read_bits64, word32, wots_digest_bytes};
use crate::kat::group::Group;
use crate::kat::value::Value;
use crate::profile::Profile;

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("helpers");
    for x in [0u32, 1, 0x0102_0304, u32::MAX] {
        g.call(
            "be32",
            vec![Value::int(x)],
            || x.to_be_bytes(),
            |r| Value::bytes(r),
        );
    }
    for x in [0u64, 0x0102_0304_0506_0708, u64::MAX] {
        g.call(
            "be64",
            vec![Value::int(x)],
            || x.to_be_bytes(),
            |r| Value::bytes(r),
        );
    }
    let input = label_bytes("read_bits", 6);
    for (start, len) in [
        (0, 0),
        (0, 1),
        (3, 13),
        (7, 32),
        (16, 33),
        (40, 8),
        (41, 8),
        (48, 0),
        (60, 0),
    ] {
        g.call(
            "read_bits32",
            vec![Value::bytes(&input), Value::Int(start), Value::int(len)],
            || read_bits32(&input, start as usize, len),
            |r| Value::opt(r.map(Value::int)),
        );
    }
    for (start, len) in [(0, 48), (5, 40), (0, 64), (0, 65), (8, 41)] {
        g.call(
            "read_bits64",
            vec![Value::bytes(&input), Value::Int(start), Value::int(len)],
            || read_bits64(&input, start as usize, len),
            |r| Value::opt(r.map(Value::Int)),
        );
    }
    let digest = label_word("base_w");
    for (w, index) in [(16u16, 0usize), (16, 1), (16, 63), (256, 0), (256, 31)] {
        g.call(
            "base_w_digit",
            vec![
                Value::int(w),
                Value::bytes(&digest),
                Value::Int(index as u64),
            ],
            || base_w_digit(w, &digest, index),
            |r| Value::int(*r),
        );
    }
    g.call(
        "wots_digest_bytes",
        vec![],
        wots_digest_bytes::<Full>,
        |r| Value::Int(*r as u64),
    );
    for len in [31, 32, 33] {
        let data = label_bytes("word32", len);
        g.call(
            "word32",
            vec![Value::bytes(&data)],
            || word32(&data),
            |r| Value::opt(r.map(|w| Value::bytes(&w))),
        );
    }
    let seed = label_bytes("derive32/seed", 40);
    for data in [&b""[..], &[3u8][..], &[0u8; 12][..]] {
        g.call(
            "derive32",
            vec![
                Value::bytes(b"kat-domain"),
                Value::bytes(&seed),
                Value::bytes(data),
            ],
            || derive32::<<Full as Profile>::Suite>(b"kat-domain", &seed, data),
            |r| Value::bytes(r),
        );
    }
    // PROFILE_ID is a build-time constant. This case ties the theory
    // parameter PROFILE_ID to the Keccak hash of PROFILE_NAME.
    g.call(
        "profile_id_matches_name",
        vec![],
        || keccak256v(&[Full::PROFILE_NAME.as_bytes()]) == Full::PROFILE_ID,
        |r| Value::Bool(*r),
    );
    g
}
