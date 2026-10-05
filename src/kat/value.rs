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

//! Values of known-answer test cases: the arguments and results of one call,
//! in a form that the generator in `proofs/easycrypt/kat` renders as an
//! EasyCrypt term and as JSON.

use alloc::vec::Vec;

/// One argument or result of a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `true` or `false`.
    Bool(bool),
    /// A non-negative integer.
    Int(u64),
    /// A byte string, an EasyCrypt `int list` of bytes.
    Bytes(Vec<u8>),
    /// An EasyCrypt list.
    List(Vec<Value>),
    /// An EasyCrypt tuple.
    Tuple(Vec<Value>),
    /// An EasyCrypt option.
    Opt(Option<alloc::boxed::Box<Value>>),
    /// An EasyCrypt record, with its field names.
    Record(Vec<(&'static str, Value)>),
    /// A constructor of an EasyCrypt datatype, with its arguments.
    Ctor(&'static str, Vec<Value>),
}

impl Value {
    /// A byte string.
    pub fn bytes(data: &[u8]) -> Self {
        Self::Bytes(data.to_vec())
    }

    /// A list of byte strings.
    pub fn words<T: AsRef<[u8]>>(items: &[T]) -> Self {
        Self::List(
            items
                .iter()
                .map(|item| Self::bytes(item.as_ref()))
                .collect(),
        )
    }

    /// An integer.
    pub fn int(value: impl Into<u64>) -> Self {
        Self::Int(value.into())
    }

    /// An option.
    pub fn opt(value: Option<Value>) -> Self {
        Self::Opt(value.map(alloc::boxed::Box::new))
    }
}
