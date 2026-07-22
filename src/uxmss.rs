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


//! UXMSS stateful sign and verify (merged from components + signers).

use zeroize::Zeroizing;
use crate::hash::{base_w16_digit, hash_node, hash_packed};
use crate::profiles::{
    WOTS_BASE_STATEFUL, WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};
use crate::types::{StatefulPublicKey, StatefulSignature, HASH_LEN};
use crate::wotsplusc;
use crate::wotsplusc::WOTS_C_MAX_GRIND_COUNTER;

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
    wotsplusc::stateful_chain_no_mask(pk_seed, leaf_index, chain_index, value, start, steps)
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

// ---- signing ----

/// Stateful secret material needed for UXMSS signing (no SHRINCS coupling).
pub(crate) struct StatefulSecret {
    pub sk_seed: [u8; HASH_LEN],
    pub prf_seed: [u8; HASH_LEN],
    pub pk_seed: [u8; HASH_LEN],
    pub max_signatures: u32,
    pub next_leaf_index: u32,
}

pub(crate) fn sign_stateful_raw(
    secret: &mut StatefulSecret,
    message: &[u8],
) -> Option<StatefulSignature> {
    // The verifier derives the stateful leaf index from auth_path.len(), so the
    // signer must advance one leaf at a time and must never reuse a prior leaf.
    let leaf_index = secret.next_leaf_index;
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > secret.max_signatures {
        return None;
    }

    // sign_stateful_raw_at_leaf already computes the identical auth_path (same
    // seeds, leaf_index, and max_signatures), so we must not rebuild it here —
    // stateful_auth_path walks up to max_stateful_signatures nodes and doubled
    // the dominant signing cost.
    let signature = sign_stateful_raw_at_leaf(secret, leaf_index, message)?;
    secret.next_leaf_index = leaf_index.saturating_add(1);
    Some(signature)
}

pub(crate) fn sign_stateful_raw_at_leaf(
    secret: &StatefulSecret,
    leaf_index: u32,
    message: &[u8],
) -> Option<StatefulSignature> {
    // This deterministic entry point is useful for tests and vector generation.
    // Production signing should use `sign_stateful_raw`, which advances the
    // monotonic `next_stateful_leaf_index` and avoids accidental leaf reuse.
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > secret.max_signatures {
        return None;
    }
    let mut signature = sign_stateful_wots_c(
        &secret.sk_seed,
        &secret.prf_seed,
        &secret.pk_seed,
        leaf_index,
        message,
    )?;
    signature.auth_path = stateful_auth_path(
        &secret.sk_seed,
        &secret.pk_seed,
        leaf_index,
        secret.max_signatures,
    );
    Some(signature)
}

pub(crate) fn stateful_subtree_root(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    max_signatures: u32,
) -> [u8; HASH_LEN] {
    // The stateful tree is unbalanced: leaf 1 is the leftmost live leaf, and
    // each parent combines that leaf with the subtree to its right. Build that
    // chain iteratively so large-but-valid budgets do not recurse once per leaf.
    let mut right = stateful_empty_tail(pk_seed, max_signatures);
    for current_leaf in (leaf_index..=max_signatures).rev() {
        let leaf = stateful_wots_pk_hash(sk_seed, pk_seed, current_leaf);
        right = stateful_parent_hash(pk_seed, current_leaf, leaf, right);
    }
    right
}

fn sign_stateful_wots_c(
    sk_seed: &[u8; HASH_LEN],
    prf_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    message: &[u8],
) -> Option<StatefulSignature> {
    // WOTS-C replaces checksum chains with a grinding condition. We keep trying
    // counters until the base-16 message digits sum to the verifier's target.
    //
    // The randomizer is one fixed 32-byte value for this leaf/message pair. The
    // counter changes the digest derived from that randomizer; the randomizer
    // itself does not change inside the grinding loop.
    let randomizer = hash_packed(&[
        b"uxmss-wots-randomizer",
        prf_seed,
        &leaf_index.to_be_bytes(),
        message,
    ]);

    let result = crate::wotsplusc::grind_digit_sum(
        WOTS_C_MAX_GRIND_COUNTER,
        WOTS_TARGET_SUM_STATEFUL,
        |counter| {
            let digest = hash_packed(&[
                b"uxmss-wots-digits",
                pk_seed,
                &leaf_index.to_be_bytes(),
                &randomizer,
                &counter.to_be_bytes(),
                message,
            ]);
            let digits = (0..WOTS_CHAINS_STATEFUL)
                .map(|index| base_w16_digit(&digest, index))
                .collect::<Vec<_>>();
            let digit_sum = digits.iter().copied().try_fold(0u32, |a, b| a.checked_add(b))?;
            Some((digit_sum, digits))
        },
        |digits| {
            digits
                .iter()
                .enumerate()
                .map(|(chain_index, digit)| {
                    let secret = Zeroizing::new(stateful_chain_secret(
                        sk_seed,
                        pk_seed,
                        leaf_index,
                        chain_index as u32,
                    ));
                    stateful_chain_no_mask(
                        pk_seed,
                        leaf_index,
                        chain_index as u32,
                        *secret,
                        0,
                        *digit,
                    )
                })
                .collect::<Vec<_>>()
        },
    )?;
    let (counter, chains) = result;
    Some(StatefulSignature {
        randomizer,
        counter,
        chains,
        auth_path: Vec::new(),
    })
}

fn stateful_chain_secret(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    chain_index: u32,
) -> [u8; HASH_LEN] {
    // The private chain start is deterministic from the stateful secret seed,
    // public seed, leaf, and chain. Including the public seed keeps the same
    // secret seed from producing interchangeable chains under a different key.
    hash_packed(&[
        b"uxmss-wots-chain-secret",
        sk_seed,
        pk_seed,
        &leaf_index.to_be_bytes(),
        &chain_index.to_be_bytes(),
    ])
}

fn stateful_wots_pk_hash(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
) -> [u8; HASH_LEN] {
    // This is the public WOTS-C commitment for one stateful leaf. It is computed
    // by advancing every chain to its endpoint and hashing all endpoints together.
    let mut endpoints = Vec::with_capacity(WOTS_CHAINS_STATEFUL * HASH_LEN);
    for chain_index in 0..WOTS_CHAINS_STATEFUL {
        // The private chain start is zeroized on drop.
        let secret = Zeroizing::new(stateful_chain_secret(
            sk_seed,
            pk_seed,
            leaf_index,
            chain_index as u32,
        ));
        let endpoint = stateful_chain_no_mask(
            pk_seed,
            leaf_index,
            chain_index as u32,
            *secret,
            0,
            WOTS_BASE_STATEFUL - 1,
        );
        endpoints.extend_from_slice(&endpoint);
    }
    hash_node(&[
        b"uxmss-wots-pk",
        pk_seed,
        &leaf_index.to_be_bytes(),
        &endpoints,
    ])
}

fn stateful_auth_path(
    sk_seed: &[u8; HASH_LEN],
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    max_signatures: u32,
) -> Vec<[u8; HASH_LEN]> {
    // The first auth node is the right subtree (or empty tail) beside the signed
    // leaf. Earlier leaves are then supplied from right to left to match the
    // verifier's unbalanced path reconstruction.
    let mut path = Vec::with_capacity(leaf_index as usize);
    if leaf_index < max_signatures {
        path.push(stateful_subtree_root(
            sk_seed,
            pk_seed,
            leaf_index + 1,
            max_signatures,
        ));
    } else {
        path.push(stateful_empty_tail(pk_seed, leaf_index));
    }
    for previous_leaf in (1..leaf_index).rev() {
        path.push(stateful_wots_pk_hash(sk_seed, pk_seed, previous_leaf));
    }
    path
}
