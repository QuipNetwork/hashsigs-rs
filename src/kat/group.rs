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

//! A group of known-answer test cases and the Keccak calls behind them.

use alloc::string::String;
use alloc::vec::Vec;

use super::value::Value;
use super::{arm, disarm, Trace};
use crate::profile::Profile;

/// One case: `operator arguments = result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// The operator of the specification that the case applies.
    pub operator: &'static str,
    /// Its arguments, in the parameter order of the specification.
    pub arguments: Vec<Value>,
    /// The result of the Rust code.
    pub result: Value,
}

/// The cases of one replay file, the theory parameters of their profile, and
/// every Keccak call that the Rust code made for them.
#[derive(Debug, Clone, Default)]
pub struct Group {
    /// The file name stem: `Kat_<name>.ec` and `<name>.json`.
    pub name: String,
    /// Theory parameters of the specification, in declaration order.
    pub parameters: Vec<(&'static str, Value)>,
    /// The cases, in the order in which the catalog made them.
    pub cases: Vec<Case>,
    /// The Keccak calls of every case.
    pub trace: Trace,
}

impl Group {
    /// An empty group for the profile `P`.
    pub fn new<P: Profile>(name: &str) -> Self {
        Self {
            name: name.into(),
            parameters: parameters::<P>(),
            ..Self::default()
        }
    }

    /// Run `call` with the recorder armed and record it as a case. Only the
    /// Keccak calls of `call` enter the trace: a key or a signature that a
    /// case takes as input is computed outside `call`.
    pub fn call<R>(
        &mut self,
        operator: &'static str,
        arguments: Vec<Value>,
        call: impl FnOnce() -> R,
        result: impl FnOnce(&R) -> Value,
    ) -> R {
        arm();
        let out = call();
        self.trace.append(&mut disarm());
        self.cases.push(Case {
            operator,
            arguments,
            result: result(&out),
        });
        out
    }
}

/// The theory parameters of the specification at the profile `P`.
fn parameters<P: Profile>() -> Vec<(&'static str, Value)> {
    alloc::vec![
        ("PROFILE_NAME", Value::bytes(P::PROFILE_NAME.as_bytes())),
        ("PROFILE_ID", Value::bytes(&P::PROFILE_ID)),
        ("HASH_TRUNC_LEN", Value::Int(P::HASH_TRUNC_LEN as u64)),
        (
            "STATELESS_SIGNATURE_LIMIT",
            Value::int(P::STATELESS_SIGNATURE_LIMIT)
        ),
        ("HYPERTREE_HEIGHT", Value::int(P::HYPERTREE_HEIGHT)),
        ("NUM_HYPERTREE_LAYERS", Value::int(P::NUM_HYPERTREE_LAYERS)),
        ("FORS_TREE_HEIGHT", Value::int(P::FORS_TREE_HEIGHT)),
        ("NUM_FORS_TREES", Value::int(P::NUM_FORS_TREES)),
        ("WOTS_CHAIN_LEN", Value::int(P::WOTS_CHAIN_LEN)),
        ("NUM_WOTS_CHAINS", Value::int(P::NUM_WOTS_CHAINS)),
        (
            "FORS_C_MAX_GRIND_COUNTER",
            Value::int(P::FORS_C_MAX_GRIND_COUNTER)
        ),
        ("WOTS_TARGET_SUM", Value::int(P::WOTS_TARGET_SUM)),
    ]
}
