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

//! Shared ABI-encoding framing: byte-exact Solidity `abi.encode` head/tail
//! primitives (encode side) and a bounds-checked, fail-closed cursor
//! (decode side), factored out of `envelope.rs` so per-scheme codecs can
//! share the same framing without duplicating it.

use alloc::vec::Vec;
use core::cell::Cell;

use crate::HASH_LEN;

/// One field of a head/tail ABI tuple: either inlined directly in the head
/// (fixed-width Solidity types) or written to the tail with an offset word
/// left in the head (dynamic types: `bytes`, `T[]`, dynamic structs).
pub(crate) enum Field {
    Static([u8; HASH_LEN]),
    Dynamic(Vec<u8>),
}

pub(crate) fn word_from_u32(value: u32) -> [u8; HASH_LEN] {
    let mut word = [0u8; HASH_LEN];
    word[28..].copy_from_slice(&value.to_be_bytes());
    word
}

pub(crate) fn word_from_usize(value: usize) -> [u8; HASH_LEN] {
    let mut word = [0u8; HASH_LEN];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

pub(crate) fn pad_len(len: usize) -> usize {
    (HASH_LEN - len % HASH_LEN) % HASH_LEN
}

/// ABI-encode a dynamic `bytes` value: length word, raw data, zero pad to
/// the next word boundary.
pub(crate) fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let pad = pad_len(data.len());
    let mut out = Vec::with_capacity(HASH_LEN + data.len() + pad);
    out.extend_from_slice(&word_from_usize(data.len()));
    out.extend_from_slice(data);
    out.resize(out.len() + pad, 0);
    out
}

/// ABI-encode a static `bytes32[]`: length word followed by inline 32-byte
/// elements (no per-element offsets — `bytes32` is a static type).
pub(crate) fn encode_bytes32_array(items: &[[u8; HASH_LEN]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HASH_LEN + items.len() * HASH_LEN);
    out.extend_from_slice(&word_from_usize(items.len()));
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// ABI-encode a dynamic array whose element type is itself dynamic (`bytes[]`
/// or an array of dynamic structs): length word, one offset word per element
/// (relative to just past the offset block), then the concatenated element
/// encodings.
pub(crate) fn encode_dynamic_array(elements: Vec<Vec<u8>>) -> Vec<u8> {
    let head_len = elements.len() * HASH_LEN;
    let mut out = Vec::with_capacity(HASH_LEN + head_len);
    out.extend_from_slice(&word_from_usize(elements.len()));
    let mut running = 0usize;
    for element in &elements {
        out.extend_from_slice(&word_from_usize(head_len + running));
        running += element.len();
    }
    for element in elements {
        out.extend_from_slice(&element);
    }
    out
}

/// ABI-encode a head/tail tuple (struct or the top-level parameter list):
/// static fields are inlined in the head at their fixed position, dynamic
/// fields leave an offset word in the head and are appended to the tail in
/// field order.
pub(crate) fn encode_tuple(fields: Vec<Field>) -> Vec<u8> {
    let head_len = fields.len() * HASH_LEN;
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    let mut running = 0usize;
    for field in fields {
        match field {
            Field::Static(word) => head.extend_from_slice(&word),
            Field::Dynamic(bytes) => {
                head.extend_from_slice(&word_from_usize(head_len + running));
                running += bytes.len();
                tail.push(bytes);
            }
        }
    }
    let mut out = head;
    for bytes in tail {
        out.extend_from_slice(&bytes);
    }
    out
}

/// Bounds-checked, fail-closed ABI cursor over a byte slice. Every read
/// returns `None` on truncation, an out-of-range offset/length, or a dirty
/// high-bit/padding pattern instead of panicking or reading adjacent memory.
/// Tracks a high-water mark of successfully read ranges so top-level entry
/// points can reject trailing bytes.
pub(crate) struct AbiReader<'a> {
    data: &'a [u8],
    /// Exclusive end of the farthest byte range successfully read.
    high_water: Cell<usize>,
}

impl<'a> AbiReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            high_water: Cell::new(0),
        }
    }

    fn mark(&self, end: usize) {
        if end > self.high_water.get() {
            self.high_water.set(end);
        }
    }

    /// Accept only when every input byte was covered by a successful read.
    pub(crate) fn finish(&self) -> Option<()> {
        if self.high_water.get() == self.data.len() {
            Some(())
        } else {
            None
        }
    }

    pub(crate) fn slice(&self, pos: usize, len: usize) -> Option<&'a [u8]> {
        let end = pos.checked_add(len)?;
        let out = self.data.get(pos..end)?;
        self.mark(end);
        Some(out)
    }

    pub(crate) fn read_bytes32(&self, pos: usize) -> Option<[u8; HASH_LEN]> {
        self.slice(pos, HASH_LEN)?.try_into().ok()
    }

    pub(crate) fn read_u32(&self, pos: usize) -> Option<u32> {
        let word = self.slice(pos, HASH_LEN)?;
        if word[..28].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u32::from_be_bytes(word[28..32].try_into().ok()?))
    }

    pub(crate) fn read_usize(&self, pos: usize) -> Option<usize> {
        let word = self.slice(pos, HASH_LEN)?;
        if word[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        usize::try_from(u64::from_be_bytes(word[24..32].try_into().ok()?)).ok()
    }

    /// Resolve a head-slot offset word at `head` (relative to `base`) into
    /// the absolute position of the referenced dynamic content.
    pub(crate) fn decode_offset(&self, base: usize, head: usize) -> Option<usize> {
        base.checked_add(self.read_usize(head)?)
    }

    /// Decode a dynamic `bytes` value already located at `start` (an
    /// absolute position, e.g. a `T[]` array element position that already
    /// had its own per-element offset resolved by `decode_dynamic_array`):
    /// length word, raw data, and an all-zero pad check up to the next word
    /// boundary.
    pub(crate) fn read_bytes_at(&self, start: usize) -> Option<Vec<u8>> {
        let len = self.read_usize(start)?;
        let data_start = start.checked_add(HASH_LEN)?;
        let data = self.slice(data_start, len)?;
        let pad = pad_len(len);
        if pad > 0 {
            let padding = self.slice(data_start.checked_add(len)?, pad)?;
            if padding.iter().any(|byte| *byte != 0) {
                return None;
            }
        }
        Some(data.to_vec())
    }

    /// Decode a dynamic `bytes` value whose head-slot offset lives at `head`
    /// (relative to `base`).
    pub(crate) fn decode_bytes(&self, base: usize, head: usize) -> Option<Vec<u8>> {
        let start = self.decode_offset(base, head)?;
        self.read_bytes_at(start)
    }

    /// Decode a dynamic `bytes` value known to carry exactly one hash word.
    pub(crate) fn decode_bytes32_field(&self, base: usize, head: usize) -> Option<[u8; HASH_LEN]> {
        self.decode_bytes(base, head)?.try_into().ok()
    }

    /// Decode a static `bytes32[]`, rejecting lengths above `max_len`.
    pub(crate) fn decode_array_bytes32(
        &self,
        base: usize,
        head: usize,
        max_len: usize,
    ) -> Option<Vec<[u8; HASH_LEN]>> {
        let start = self.decode_offset(base, head)?;
        let len = self.read_usize(start)?;
        if len > max_len {
            return None;
        }
        let elements_base = start.checked_add(HASH_LEN)?;
        let mut out = Vec::with_capacity(len);
        for index in 0..len {
            let pos = elements_base.checked_add(index.checked_mul(HASH_LEN)?)?;
            out.push(self.read_bytes32(pos)?);
        }
        Some(out)
    }

    /// Decode a dynamic `T[]` / `bytes[]`: length capped by `max_len`, then
    /// element offsets required to be sequential (matches `encode_dynamic_array`,
    /// rejects aliased or gapped element payloads).
    pub(crate) fn decode_dynamic_array<T>(
        &self,
        base: usize,
        head: usize,
        max_len: usize,
        mut decode_element: impl FnMut(&Self, usize) -> Option<T>,
    ) -> Option<Vec<T>> {
        let start = self.decode_offset(base, head)?;
        let len = self.read_usize(start)?;
        if len > max_len {
            return None;
        }
        let elements_base = start.checked_add(HASH_LEN)?;
        let offset_table_end = elements_base.checked_add(len.checked_mul(HASH_LEN)?)?;
        let mut starts = Vec::with_capacity(len);
        for index in 0..len {
            let element_head = elements_base.checked_add(index.checked_mul(HASH_LEN)?)?;
            starts.push(self.decode_offset(elements_base, element_head)?);
        }
        let mut out = Vec::with_capacity(len);
        for (index, element_start) in starts.into_iter().enumerate() {
            let expected = if index == 0 {
                offset_table_end
            } else {
                self.high_water.get()
            };
            if element_start != expected {
                return None;
            }
            out.push(decode_element(self, element_start)?);
        }
        Some(out)
    }

    /// Decode a `bytes[]` array: each element is a `bytes` value read
    /// directly at its resolved position (no further offset indirection —
    /// unlike an array of dynamic *structs*, the element type here is
    /// itself the dynamic content).
    pub(crate) fn decode_array_bytes(
        &self,
        base: usize,
        head: usize,
        max_len: usize,
    ) -> Option<Vec<Vec<u8>>> {
        self.decode_dynamic_array(base, head, max_len, |reader, element_start| {
            reader.read_bytes_at(element_start)
        })
    }
}

pub(crate) fn collect_hash_words(items: Vec<Vec<u8>>) -> Option<Vec<[u8; HASH_LEN]>> {
    items.into_iter().map(|item| item.try_into().ok()).collect()
}
