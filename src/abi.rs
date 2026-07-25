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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Two-field dynamic-bytes tuple used as a minimal structured wire type.
    fn encode_pair(a: &[u8], b: &[u8]) -> Vec<u8> {
        encode_tuple(vec![
            Field::Dynamic(encode_bytes(a)),
            Field::Dynamic(encode_bytes(b)),
        ])
    }

    fn decode_pair(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let reader = AbiReader::new(data);
        let a = reader.decode_bytes(0, 0)?;
        let b = reader.decode_bytes(0, HASH_LEN)?;
        reader.finish()?;
        Some((a, b))
    }

    #[test]
    fn encode_bytes_round_trips_through_reader() {
        for payload in [
            &[][..],
            &[0xabu8][..],
            &[0x11u8; 31][..],
            &[0x22u8; 32][..],
            &[0x33u8; 33][..],
            &[0x44u8; 64][..],
        ] {
            let encoded = encode_bytes(payload);
            let reader = AbiReader::new(&encoded);
            let decoded = reader.read_bytes_at(0).expect("valid bytes must decode");
            assert_eq!(decoded, payload);
            reader.finish().expect("full payload must exhaust");
        }
    }

    #[test]
    fn encode_bytes32_array_round_trips() {
        let items = [[0xAAu8; HASH_LEN], [0xBBu8; HASH_LEN], [0xCCu8; HASH_LEN]];
        let encoded = encode_bytes32_array(&items);
        // Wrap as a single-field dynamic tuple so the array lives at an offset.
        let wrapped = encode_tuple(vec![Field::Dynamic(encoded)]);
        let reader = AbiReader::new(&wrapped);
        let decoded = reader
            .decode_array_bytes32(0, 0, items.len())
            .expect("valid array must decode");
        assert_eq!(decoded, items);
        reader.finish().expect("full payload must exhaust");
    }

    #[test]
    fn encode_dynamic_array_of_bytes_round_trips() {
        let elements = [b"alpha".as_slice(), b"bravo".as_slice(), b"".as_slice()];
        let encoded = encode_dynamic_array(elements.iter().map(|e| encode_bytes(e)).collect());
        let wrapped = encode_tuple(vec![Field::Dynamic(encoded)]);
        let reader = AbiReader::new(&wrapped);
        let decoded = reader
            .decode_array_bytes(0, 0, elements.len())
            .expect("valid dynamic array must decode");
        assert_eq!(decoded, elements);
        reader.finish().expect("full payload must exhaust");
    }

    #[test]
    fn encode_tuple_static_and_dynamic_round_trips() {
        let static_word = word_from_u32(0x0BAD_F00D);
        let payload = b"hello-abi";
        let encoded = encode_tuple(vec![
            Field::Static(static_word),
            Field::Dynamic(encode_bytes(payload)),
            Field::Static([0xEEu8; HASH_LEN]),
        ]);
        let reader = AbiReader::new(&encoded);
        assert_eq!(reader.read_u32(0), Some(0x0BAD_F00D));
        let dynamic = reader
            .decode_bytes(0, HASH_LEN)
            .expect("dynamic field must decode");
        assert_eq!(dynamic, payload);
        assert_eq!(reader.read_bytes32(HASH_LEN * 2), Some([0xEEu8; HASH_LEN]));
        reader.finish().expect("full payload must exhaust");
    }

    #[test]
    fn pair_encode_decode_round_trip() {
        let a = b"left-payload";
        let b = b"right-payload-longer";
        let encoded = encode_pair(a, b);
        let (da, db) = decode_pair(&encoded).expect("valid pair must decode");
        assert_eq!(da, a);
        assert_eq!(db, b);
        assert_eq!(encode_pair(&da, &db), encoded);
    }

    #[test]
    fn read_bytes_at_rejects_truncated_buffer() {
        let encoded = encode_bytes(&[0x55u8; 40]);
        for cut in [0usize, 1, 31, 32, encoded.len() - 1] {
            let truncated = &encoded[..cut];
            let reader = AbiReader::new(truncated);
            assert!(
                reader.read_bytes_at(0).is_none(),
                "truncated at {cut} of {} must fail closed",
                encoded.len()
            );
        }
    }

    #[test]
    fn read_u32_rejects_truncated_and_dirty_high_bits() {
        assert!(AbiReader::new(&[0u8; 31]).read_u32(0).is_none());
        let mut dirty = word_from_u32(7);
        dirty[0] = 0x01;
        assert!(AbiReader::new(&dirty).read_u32(0).is_none());
        dirty = word_from_u32(7);
        dirty[27] = 0x01;
        assert!(AbiReader::new(&dirty).read_u32(0).is_none());
        assert_eq!(AbiReader::new(&word_from_u32(7)).read_u32(0), Some(7));
    }

    #[test]
    fn read_usize_rejects_dirty_high_bits() {
        let mut dirty = word_from_usize(42);
        dirty[0] = 0x01;
        assert!(AbiReader::new(&dirty).read_usize(0).is_none());
        dirty = word_from_usize(42);
        dirty[23] = 0x01;
        assert!(AbiReader::new(&dirty).read_usize(0).is_none());
        assert_eq!(AbiReader::new(&word_from_usize(42)).read_usize(0), Some(42));
    }

    #[test]
    fn read_bytes_at_rejects_dirty_padding() {
        // Non-multiple-of-32 payload so pad_len > 0.
        let mut encoded = encode_bytes(&[1, 2, 3]);
        // Layout: length word (32) + 3 data + 29 zero pad.
        let pad_index = HASH_LEN + 3;
        assert_eq!(encoded[pad_index], 0);
        encoded[pad_index] = 0xFF;
        let reader = AbiReader::new(&encoded);
        assert!(
            reader.read_bytes_at(0).is_none(),
            "non-zero padding must fail closed"
        );
        // Last pad byte also counts.
        encoded[pad_index] = 0;
        let last = encoded.len() - 1;
        encoded[last] = 0x01;
        let reader = AbiReader::new(&encoded);
        assert!(reader.read_bytes_at(0).is_none());
    }

    #[test]
    fn decode_array_bytes32_rejects_oversize_length() {
        let items = [[1u8; HASH_LEN], [2u8; HASH_LEN]];
        let wrapped = encode_tuple(vec![Field::Dynamic(encode_bytes32_array(&items))]);
        let reader = AbiReader::new(&wrapped);
        assert!(
            reader.decode_array_bytes32(0, 0, 1).is_none(),
            "declared length above max_len must fail closed"
        );
        let reader = AbiReader::new(&wrapped);
        assert_eq!(
            reader.decode_array_bytes32(0, 0, 2).expect("len==max ok"),
            items
        );
    }

    #[test]
    fn decode_array_bytes_rejects_oversize_declared_length() {
        let elements = [b"one".as_slice(), b"two".as_slice()];
        let encoded = encode_dynamic_array(elements.iter().map(|e| encode_bytes(e)).collect());
        let wrapped = encode_tuple(vec![Field::Dynamic(encoded)]);
        let reader = AbiReader::new(&wrapped);
        assert!(reader.decode_array_bytes(0, 0, 1).is_none());
        // Inflate the length word inside the array body beyond any reasonable max.
        let mut mangled = wrapped.clone();
        // Outer head is one offset word; array length word sits at offset head_len.
        let array_start = HASH_LEN; // single dynamic field offset points at head_len==32
                                    // Overwrite array length with a huge value (still clean high bits).
        mangled[array_start..array_start + HASH_LEN]
            .copy_from_slice(&word_from_usize(usize::MAX / 2));
        let reader = AbiReader::new(&mangled);
        assert!(reader.decode_array_bytes(0, 0, 1024).is_none());
    }

    #[test]
    fn decode_dynamic_array_rejects_aliased_element_offsets() {
        // Two equal-length elements so swapping offsets is a pure alias, not a gap.
        let e0 = encode_bytes(b"aaaa");
        let e1 = encode_bytes(b"bbbb");
        let mut body = encode_dynamic_array(vec![e0.clone(), e1]);
        // body layout: len | off0 | off1 | e0 | e1
        // off0 and off1 are relative to elements_base (= start of off0).
        // Point both offsets at the first element payload (alias).
        let elements_base = HASH_LEN; // after length word
        let offset_table_end = elements_base + 2 * HASH_LEN;
        // off0 stays at offset_table_end; force off1 to the same absolute start.
        body[elements_base + HASH_LEN..elements_base + 2 * HASH_LEN]
            .copy_from_slice(&word_from_usize(offset_table_end - elements_base));
        let wrapped = encode_tuple(vec![Field::Dynamic(body)]);
        let reader = AbiReader::new(&wrapped);
        assert!(
            reader.decode_array_bytes(0, 0, 8).is_none(),
            "aliased element offsets must fail closed"
        );
        // Sanity: unmodified encoding still works.
        let clean = encode_tuple(vec![Field::Dynamic(encode_dynamic_array(vec![
            encode_bytes(b"aaaa"),
            encode_bytes(b"bbbb"),
        ]))]);
        let reader = AbiReader::new(&clean);
        let decoded = reader.decode_array_bytes(0, 0, 8).expect("clean array");
        assert_eq!(decoded, [b"aaaa".as_slice(), b"bbbb".as_slice()]);
    }

    #[test]
    fn decode_dynamic_array_rejects_gapped_element_offsets() {
        let e0 = encode_bytes(b"aaaa");
        let e1 = encode_bytes(b"bbbb");
        let mut body = encode_dynamic_array(vec![e0, e1]);
        let elements_base = HASH_LEN;
        // Bump second element offset by one word (gap / non-sequential).
        let off1 = {
            let word = &body[elements_base + HASH_LEN..elements_base + 2 * HASH_LEN];
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&word[24..]);
            u64::from_be_bytes(buf) as usize
        };
        body[elements_base + HASH_LEN..elements_base + 2 * HASH_LEN]
            .copy_from_slice(&word_from_usize(off1 + HASH_LEN));
        let wrapped = encode_tuple(vec![Field::Dynamic(body)]);
        let reader = AbiReader::new(&wrapped);
        assert!(
            reader.decode_array_bytes(0, 0, 8).is_none(),
            "gapped element offsets must fail closed"
        );
    }

    #[test]
    fn finish_rejects_trailing_bytes_after_successful_read() {
        let mut encoded = encode_bytes(b"payload");
        encoded.push(0x00);
        let reader = AbiReader::new(&encoded);
        assert!(reader.read_bytes_at(0).is_some());
        assert!(
            reader.finish().is_none(),
            "trailing byte after covered range must fail closed"
        );
        // Empty input: high-water 0 == len 0, finish accepts without reads.
        assert_eq!(AbiReader::new(&[]).finish(), Some(()));
        // Non-empty unread input fails finish.
        assert!(AbiReader::new(&[0u8; 32]).finish().is_none());
    }

    #[test]
    fn decode_offset_rejects_out_of_range() {
        // Offset word claims base+huge, beyond buffer.
        let mut buf = word_from_usize(1_000_000);
        // Use as head at 0 with base 0; then try to read bytes there.
        let reader = AbiReader::new(&buf);
        assert!(reader.decode_bytes(0, 0).is_none());
        // Truncated head word itself.
        buf = word_from_usize(0);
        assert!(AbiReader::new(&buf[..31]).decode_offset(0, 0).is_none());
    }

    #[test]
    fn collect_hash_words_requires_exact_hash_len() {
        assert_eq!(
            collect_hash_words(vec![vec![0u8; HASH_LEN]]),
            Some(vec![[0u8; HASH_LEN]])
        );
        assert!(collect_hash_words(vec![vec![0u8; HASH_LEN - 1]]).is_none());
        assert!(collect_hash_words(vec![vec![0u8; HASH_LEN + 1]]).is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod prop {
        use super::*;
        use proptest::prelude::*;

        /// Drive every public AbiReader entrypoint over arbitrary input.
        /// Success or None is fine; the property is that nothing panics.
        fn exercise_reader(data: &[u8]) {
            let reader = AbiReader::new(data);
            let _ = reader.finish();
            let _ = reader.slice(0, data.len().min(64));
            let _ = reader.read_bytes32(0);
            let _ = reader.read_u32(0);
            let _ = reader.read_usize(0);
            let _ = reader.decode_offset(0, 0);
            let _ = reader.read_bytes_at(0);
            let _ = reader.decode_bytes(0, 0);
            let _ = reader.decode_bytes32_field(0, 0);
            let _ = reader.decode_array_bytes32(0, 0, 8);
            let _ = reader.decode_array_bytes(0, 0, 8);
            let _ = reader.decode_dynamic_array(0, 0, 4, |r, start| r.read_bytes_at(start));
            // Also try a non-zero base/head so offset math is exercised.
            if data.len() >= HASH_LEN * 2 {
                let _ = reader.decode_bytes(0, HASH_LEN);
                let _ = reader.decode_array_bytes32(0, HASH_LEN, 4);
                let _ = reader.decode_array_bytes(HASH_LEN, 0, 4);
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn abi_reader_never_panics_on_arbitrary_bytes(
                data in proptest::collection::vec(any::<u8>(), 0..512),
            ) {
                // Must not panic: accept or return None on every path.
                exercise_reader(&data);
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn pair_to_bytes_from_bytes_identity(
                a in proptest::collection::vec(any::<u8>(), 0..96),
                b in proptest::collection::vec(any::<u8>(), 0..96),
            ) {
                let encoded = encode_pair(&a, &b);
                let (da, db) = decode_pair(&encoded)
                    .expect("encoder output must decode");
                prop_assert_eq!(&da, &a);
                prop_assert_eq!(&db, &b);
                prop_assert_eq!(encode_pair(&da, &db), encoded);
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(48))]

            #[test]
            fn bytes32_array_round_trip_identity(
                // Cap length so max_len checks stay honest but cheap.
                items in proptest::collection::vec(any::<[u8; HASH_LEN]>(), 0..12),
            ) {
                let encoded = encode_bytes32_array(&items);
                let wrapped = encode_tuple(vec![Field::Dynamic(encoded)]);
                let reader = AbiReader::new(&wrapped);
                let decoded = reader
                    .decode_array_bytes32(0, 0, items.len())
                    .expect("encoder output must decode");
                prop_assert_eq!(decoded, items);
                prop_assert_eq!(reader.finish(), Some(()));
            }
        }
    }
}
