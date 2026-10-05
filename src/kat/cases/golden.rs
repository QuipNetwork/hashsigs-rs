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

//! Group `golden`: the committed golden vector of the crate,
//! `tests/test_vectors/shrincs_sphincs_256s_keccak.json.gz`. The generator
//! reads the file and passes its cases here.

use alloc::string::String;
use alloc::vec::Vec;

use super::wire::{public_key, stateful_sig, stateless_sig};
use super::Full;
use crate::kat::group::Group;
use crate::kat::value::Value;
use crate::shrincs::dispatch_access as dispatch;
use crate::shrincs::uxmss::{self, verify_stateful_unsafe_raw};
use crate::shrincs::{PublicKey, Signature as StatefulSignature};
use crate::sphincs_plus_c::Signature as StatelessSignature;

/// One case of the stateful section: a UXMSS key, a message, a signature.
pub struct GoldenStateful {
    /// The case name in the vector file.
    pub name: String,
    /// The UXMSS public seed.
    pub pk_seed: [u8; 32],
    /// The UXMSS root.
    pub root: [u8; 32],
    /// The leaf budget.
    pub max_signatures: u32,
    /// The signed message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: StatefulSignature,
}

/// One case of the stateless section: a public-key bundle, a message, a
/// signature.
pub struct GoldenStateless {
    /// The case name in the vector file.
    pub name: String,
    /// The public-key bundle.
    pub public_key: PublicKey,
    /// The signed message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: StatelessSignature,
}

/// The group `golden`. Returns the group and the names of the cases whose
/// Rust verdict differs from the case name: `valid` must verify, and every
/// other case must not.
pub fn golden_group(
    stateful: &[GoldenStateful],
    stateless: &[GoldenStateless],
) -> (Group, Vec<String>) {
    let mut g = Group::new::<Full>("golden");
    let mut wrong = Vec::new();
    for case in stateful {
        let key = uxmss::PublicKey {
            pk_seed: case.pk_seed,
            root: case.root,
            max_signatures: case.max_signatures,
        };
        let verified = g.call(
            "uxmss_verify",
            vec![
                Value::bytes(&case.pk_seed),
                Value::bytes(&case.root),
                Value::int(case.max_signatures),
                Value::bytes(&case.message),
                stateful_sig(&case.signature),
            ],
            || verify_stateful_unsafe_raw::<Full, 64>(&key, &case.message, &case.signature),
            |r| Value::Bool(*r),
        );
        if verified != (case.name == "valid") {
            wrong.push(alloc::format!("stateful/{}", case.name));
        }
    }
    for case in stateless {
        let mut expected = [0u8; 32];
        if case.public_key.public_key_commitment.len() == 32 {
            expected.copy_from_slice(&case.public_key.public_key_commitment);
        }
        let verified = g.call(
            "verify_stateless_unsafe_raw",
            vec![
                Value::bytes(&expected),
                public_key(&case.public_key),
                Value::bytes(&case.message),
                stateless_sig(&case.signature),
            ],
            || {
                dispatch::verify_stateless_unsafe_raw::<Full, 64>(
                    expected,
                    &case.public_key,
                    &case.message,
                    &case.signature,
                )
            },
            |r| Value::Bool(*r),
        );
        if verified != (case.name == "valid") {
            wrong.push(alloc::format!("stateless/{}", case.name));
        }
    }
    (g, wrong)
}
