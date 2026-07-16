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

//! UXMSS primitive verification logic.

use super::super::profiles::{
    WOTS_BASE_STATEFUL, WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};
use super::hash::{address_word32, base_w16_digit, hash_node, hash_packed};
use super::super::types::{StatefulPublicKey, StatefulSignature, ADDRESS_TYPE_WOTS_HASH, HASH_LEN};

pub(crate) fn verify_stateful_unsafe_raw(
    stateful_key: &StatefulPublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> bool {
    let leaf_index = signature.auth_path.len() as u32;
    if leaf_index == 0 || leaf_index > stateful_key.max_signatures {
        return false;
    }
    if signature.chains.len() != WOTS_CHAINS_STATEFUL {
        return false;
    }

    let Some(pk_hash) = compact_stateful_wots_public_key_from_signature(
        stateful_key.pk_seed,
        leaf_index,
        message,
        signature,
    ) else {
        return false;
    };
    let Some(root) = root_from_unbalanced_path(
        stateful_key.pk_seed,
        leaf_index,
        pk_hash,
        &signature.auth_path,
    ) else {
        return false;
    };
    stateful_key.root == root
}

pub(crate) fn stateful_parent_hash(
    pk_seed: &[u8; HASH_LEN],
    left_leaf_index: u32,
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hash_node(&[
        b"uxmss-node".as_ref(),
        pk_seed.as_ref(),
        left_leaf_index.to_be_bytes().as_ref(),
        left.as_ref(),
        right.as_ref(),
    ])
}

pub(crate) fn stateful_empty_tail(
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
) -> [u8; HASH_LEN] {
    hash_packed(&[
        b"uxmss-empty-tail".as_ref(),
        pk_seed.as_ref(),
        leaf_index.to_be_bytes().as_ref(),
    ])
}

pub(crate) fn stateful_chain_no_mask(
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    let mut out = value;
    for step_offset in 0..steps {
        let address_word = address_word32(
            0,
            0,
            ADDRESS_TYPE_WOTS_HASH,
            leaf_index,
            chain_index,
            start + step_offset,
        );
        out = hash_node(&[
            b"uxmss-wots-chain".as_ref(),
            pk_seed.as_ref(),
            address_word.as_ref(),
            out.as_ref(),
        ]);
    }
    out
}

fn compact_stateful_wots_public_key_from_signature(
    pk_seed: [u8; HASH_LEN],
    leaf_index: u32,
    message: &[u8],
    signature: &StatefulSignature,
) -> Option<[u8; HASH_LEN]> {
    let digest = hash_packed(&[
        b"uxmss-wots-digits".as_ref(),
        pk_seed.as_ref(),
        leaf_index.to_be_bytes().as_ref(),
        signature.randomizer.as_slice(),
        signature.counter.to_be_bytes().as_ref(),
        message,
    ]);

    let mut digit_sum = 0u32;
    let mut segments = Vec::with_capacity(WOTS_CHAINS_STATEFUL * HASH_LEN);
    for chain_index in 0..WOTS_CHAINS_STATEFUL {
        let digit = base_w16_digit(&digest, chain_index);
        digit_sum = digit_sum.checked_add(digit)?;
        let chain_value = *signature.chains.get(chain_index)?;
        let segment = stateful_chain_no_mask(
            &pk_seed,
            leaf_index,
            chain_index as u32,
            chain_value,
            digit,
            WOTS_BASE_STATEFUL - 1 - digit,
        );
        segments.extend_from_slice(&segment);
    }

    if digit_sum != WOTS_TARGET_SUM_STATEFUL {
        return None;
    }
    Some(hash_node(&[
        b"uxmss-wots-pk".as_ref(),
        pk_seed.as_ref(),
        leaf_index.to_be_bytes().as_ref(),
        segments.as_slice(),
    ]))
}

fn root_from_unbalanced_path(
    pk_seed: [u8; HASH_LEN],
    leaf_index: u32,
    leaf: [u8; HASH_LEN],
    auth_path: &[[u8; HASH_LEN]],
) -> Option<[u8; HASH_LEN]> {
    if auth_path.len() != leaf_index as usize || auth_path.is_empty() {
        return None;
    }
    let mut root = stateful_parent_hash(&pk_seed, leaf_index, leaf, *auth_path.first()?);
    for offset in 0..auth_path.len() - 1 {
        root = stateful_parent_hash(
            &pk_seed,
            leaf_index - offset as u32 - 1,
            *auth_path.get(offset + 1)?,
            root,
        );
    }
    Some(root)
}
