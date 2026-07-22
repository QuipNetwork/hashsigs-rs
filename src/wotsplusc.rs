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


//! Shared WOTS-C chain walk and digit-sum grind primitives.
//!
//! Mirrors Solidity `WOTSPlusC.sol`: one parameterized chain walk used by both
//! the stateless hypertree (`b"wots-c-chain"`) and stateful UXMSS
//! (`b"uxmss-wots-chain"`). Tags and address layouts are caller parameters —
//! they must stay byte-identical to the pre-merge constructions.

use alloc::vec::Vec;

use crate::hash::{hash_node, wots_chain_address_word};
use crate::types::HASH_LEN;

/// Maximum grind counter for WOTS-C target-sum searches (stateless + stateful).
/// Distinct from `profiles::FORS_C_MAX_GRIND_COUNTER` (FORS-only).
pub(crate) const WOTS_C_MAX_GRIND_COUNTER: u32 = 1 << 24;

/// Advance one WOTS-C chain from a revealed value by `steps` hashes.
///
/// `tag` is the domain-separation string (`b"wots-c-chain"` or
/// `b"uxmss-wots-chain"`). `address_word` builds the per-step address from
/// `(chain_index, step)`.
pub(crate) fn wots_chain_walk(
    tag: &[u8],
    pk_seed: &[u8; HASH_LEN],
    address_word: impl Fn(u32) -> [u8; HASH_LEN],
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    for step_offset in 0..steps {
        let step = start + step_offset;
        let addr = address_word(step);
        out = hash_node(&[tag, pk_seed.as_ref(), addr.as_ref(), out.as_ref()]);
    }
    out
}

/// Stateless hypertree WOTS-C chain walk (`b"wots-c-chain"` + ADRS word).
pub(crate) fn stateless_wots_chain_from_address_base(
    pk_seed: &[u8; HASH_LEN],
    address_base: [u8; HASH_LEN],
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    wots_chain_walk(
        b"wots-c-chain",
        pk_seed,
        |step| wots_chain_address_word(address_base, chain_index, step),
        value,
        start,
        steps,
    )
}

/// ADRS coordinates for one stateless WOTS-C chain step-walk.
pub(crate) struct StatelessWotsChainCtx<'a> {
    pub pk_seed: &'a [u8; HASH_LEN],
    pub layer: u32,
    pub tree: u64,
    pub keypair: u32,
    pub chain_index: u32,
}

/// Stateless hypertree WOTS-C chain walk with full ADRS coordinates.
pub(crate) fn stateless_wots_chain(
    ctx: &StatelessWotsChainCtx<'_>,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    use crate::hash::address_word32;
    wots_chain_walk(
        b"wots-c-chain",
        ctx.pk_seed,
        |step| address_word32(ctx.layer, ctx.tree, 0, ctx.keypair, ctx.chain_index, step),
        value,
        start,
        steps,
    )
}

/// Stateful UXMSS WOTS-C chain walk (`b"uxmss-wots-chain"`).
pub(crate) fn stateful_chain_no_mask(
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    use crate::hash::address_word32;
    use crate::types::ADDRESS_TYPE_WOTS_HASH;
    wots_chain_walk(
        b"uxmss-wots-chain",
        pk_seed,
        |step| {
            address_word32(
                0,
                0,
                ADDRESS_TYPE_WOTS_HASH,
                leaf_index,
                chain_index,
                step,
            )
        },
        value,
        start,
        steps,
    )
}

/// Generic digit-sum grind: try counters until digit sum equals `target_sum`.
///
/// `digits_from_counter` returns the base-w digits for a candidate counter.
/// On success, `build_chains` produces the revealed chain values for those digits.
///
/// Sequential fallback (default / `parallel` feature off). Kept byte-identical
/// to the parallel version below: both return the *lowest* winning counter.
#[cfg(not(feature = "parallel"))]
pub(crate) fn grind_digit_sum<D, B, C>(
    max_counter: u32,
    target_sum: u32,
    digits_from_counter: D,
    build_chains: B,
) -> Option<(u32, C)>
where
    D: Fn(u32) -> Option<(u32, Vec<u32>)>,
    B: Fn(&[u32]) -> C,
{
    for counter in 0..max_counter {
        let Some((digit_sum, digits)) = digits_from_counter(counter) else {
            continue;
        };
        if digit_sum != target_sum {
            continue;
        }
        return Some((counter, build_chains(&digits)));
    }
    None
}

/// Parallel grind: shards the counter range across the rayon global pool.
///
/// Uses `find_map_first`, which returns the winner with the *lowest* counter
/// (matching sequential search order) rather than whichever thread finishes
/// first — this keeps signature bytes identical to the sequential grind, at
/// the cost of some parallel speedup (later shards may compute past the
/// eventual winner before the result is known).
#[cfg(feature = "parallel")]
pub(crate) fn grind_digit_sum<D, B, C>(
    max_counter: u32,
    target_sum: u32,
    digits_from_counter: D,
    build_chains: B,
) -> Option<(u32, C)>
where
    D: Fn(u32) -> Option<(u32, Vec<u32>)> + Sync,
    B: Fn(&[u32]) -> C,
{
    use rayon::prelude::*;
    let (counter, digits) = (0..max_counter).into_par_iter().find_map_first(|counter| {
        let (digit_sum, digits) = digits_from_counter(counter)?;
        (digit_sum == target_sum).then_some((counter, digits))
    })?;
    Some((counter, build_chains(&digits)))
}
