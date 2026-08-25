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

//! Consolidated `#[cfg(test)]` helpers shared across modules.

use crate::profile::Profile;
use crate::shrincs::PublicKey;
use crate::shrincs::{derive32, Keys, ShrincsSigner};
use crate::sphincs_plus_c;

/// Rebuild an ABI head/tail encoding with a 32-byte unread gap between the
/// head block and the tails: every dynamic-slot offset word in the head is
/// bumped by 32 and 32 junk bytes are inserted after the head, leaving the
/// tail bytes — and therefore the decoded value — untouched. Codec tests
/// assert the canonical-form checks reject this malleated form.
pub(crate) fn insert_abi_head_gap(
    encoded: &[u8],
    head_words: usize,
    dynamic_slots: &[usize],
) -> alloc::vec::Vec<u8> {
    let head_len = head_words * crate::HASH_LEN;
    let mut out = alloc::vec::Vec::with_capacity(encoded.len() + crate::HASH_LEN);
    out.extend_from_slice(&encoded[..head_len]);
    for &slot in dynamic_slots {
        let word_start = slot * crate::HASH_LEN;
        let mut offset_tail = [0u8; 8];
        offset_tail.copy_from_slice(&out[word_start + 24..word_start + 32]);
        let bumped = u64::from_be_bytes(offset_tail) + crate::HASH_LEN as u64;
        out[word_start + 24..word_start + 32].copy_from_slice(&bumped.to_be_bytes());
    }
    out.extend_from_slice(&[0xEE; crate::HASH_LEN]);
    out.extend_from_slice(&encoded[head_len..]);
    out
}

/// Build a signing key that exercises only the stateful subsystem, with a
/// placeholder hypertree root. Avoids compute-infeasible stateless hypertree
/// keygen so it runs on every profile.
pub(crate) fn stateful_only_key<P: Profile, const NUM_CHAINS: usize>(
    seed: &[u8],
    max: u32,
) -> (Keys, PublicKey) {
    let pk_seed = derive32::<P::Suite>(b"shrincs-pk-seed", seed, &[]);
    let hypertree_root = derive32::<P::Suite>(b"placeholder-hypertree-root", seed, &[]);
    let stateless = sphincs_plus_c::Key::new(
        sphincs_plus_c::PrivateKey::new(
            sphincs_plus_c::SkSeed::new(derive32::<P::Suite>(
                b"shrincs-stateless-sk-seed",
                seed,
                &[],
            )),
            sphincs_plus_c::PrfSeed::new(derive32::<P::Suite>(
                b"shrincs-stateless-prf-seed",
                seed,
                &[],
            )),
        ),
        sphincs_plus_c::PublicKey {
            pk_seed: sphincs_plus_c::PkSeed::new(pk_seed),
            root: sphincs_plus_c::Root::new(hypertree_root),
        },
    );
    ShrincsSigner::build_keys::<P, NUM_CHAINS>(seed, max, stateless)
}
