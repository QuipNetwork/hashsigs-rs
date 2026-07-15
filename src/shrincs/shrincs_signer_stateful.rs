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

//! Stateful WOTS-C signing for the fast SHRINCS path.

use super::shrincs_signer_types::{ShrincsSignerResult, ShrincsSigningKey};
use super::shrincs_signer_utils::{
    address_word32, base_w16_digit, hash_node, hash_packed, WOTS_C_MAX_GRIND_COUNTER,
};
use super::verifier::{
    StatefulSignature, ADDRESS_TYPE_WOTS_HASH, HASH_LEN, WOTS_BASE_STATEFUL, WOTS_CHAINS_STATEFUL,
    WOTS_TARGET_SUM_STATEFUL,
};

pub(crate) fn sign_stateful_raw(
    signing_key: &mut ShrincsSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    // The verifier derives the stateful leaf index from auth_path.len(), so the
    // signer must advance one leaf at a time and must never reuse a prior leaf.
    let leaf_index = signing_key.next_stateful_leaf_index;
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > signing_key.max_stateful_signatures {
        return None;
    }

    // sign_stateful_raw_at_leaf already computes the identical auth_path (same
    // seeds, leaf_index, and max_signatures), so we must not rebuild it here —
    // stateful_auth_path walks up to max_stateful_signatures nodes and doubled
    // the dominant signing cost.
    let signature = sign_stateful_raw_at_leaf(signing_key, leaf_index, message)?;
    signing_key.next_stateful_leaf_index = leaf_index.saturating_add(1);
    Some(signature)
}

pub(crate) fn sign_stateful_raw_at_leaf(
    signing_key: &ShrincsSigningKey,
    leaf_index: u32,
    message: &[u8],
) -> ShrincsSignerResult<StatefulSignature> {
    // This deterministic entry point is useful for tests and vector generation.
    // Production signing should use `sign_stateful_raw`, which advances the
    // monotonic `next_stateful_leaf_index` and avoids accidental leaf reuse.
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > signing_key.max_stateful_signatures {
        return None;
    }
    let mut signature = sign_stateful_wots_c(
        &signing_key.stateful_sk_seed,
        &signing_key.stateful_prf_seed,
        &signing_key.stateful_pk_seed,
        leaf_index,
        message,
    )?;
    signature.auth_path = stateful_auth_path(
        &signing_key.stateful_sk_seed,
        &signing_key.stateful_pk_seed,
        leaf_index,
        signing_key.max_stateful_signatures,
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
) -> ShrincsSignerResult<StatefulSignature> {
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

    for counter in 0..WOTS_C_MAX_GRIND_COUNTER {
        // The digest is public-input reproducible: the verifier receives
        // `randomizer` and `counter`, recomputes these digits, and checks that the
        // supplied chain values are at exactly those digit positions.
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
        if digits.iter().sum::<u32>() != WOTS_TARGET_SUM_STATEFUL {
            continue;
        }

        let chains = digits
            .iter()
            .enumerate()
            .map(|(chain_index, digit)| {
                // Reveal the chain value at the selected digit, not the secret
                // start and not the final endpoint. The verifier hashes forward
                // from this value to recover the endpoint.
                let secret =
                    stateful_chain_secret(sk_seed, pk_seed, leaf_index, chain_index as u32);
                stateful_chain_no_mask(pk_seed, leaf_index, chain_index as u32, secret, 0, *digit)
            })
            .collect();

        return Some(StatefulSignature {
            randomizer,
            counter,
            chains,
            auth_path: Vec::new(),
        });
    }

    None
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
        let secret = stateful_chain_secret(sk_seed, pk_seed, leaf_index, chain_index as u32);
        let endpoint = stateful_chain_no_mask(
            pk_seed,
            leaf_index,
            chain_index as u32,
            secret,
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

fn stateful_chain_no_mask(
    pk_seed: &[u8; HASH_LEN],
    leaf_index: u32,
    chain_index: u32,
    value: [u8; HASH_LEN],
    start: u32,
    steps: u32,
) -> [u8; HASH_LEN] {
    // Stateful WOTS-C uses the same unmasked chain hash shape as the verifier.
    // The address word binds the step to the stateful leaf and chain number.
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
        // Stateful (UXMSS) WOTS-C chains are domain-separated from the stateless
        // hypertree chains: the stateful tag is `uxmss-wots-chain` (16 bytes,
        // 112-byte preimage) while the hypertree walk keeps `wots-c-chain`.
        out = hash_node(&[b"uxmss-wots-chain", pk_seed, &address_word, &out]);
    }
    out
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

fn stateful_parent_hash(
    pk_seed: &[u8; HASH_LEN],
    left_leaf_index: u32,
    left: [u8; HASH_LEN],
    right: [u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    // The left leaf index is part of the parent hash because this tree is
    // unbalanced; it tells the verifier which live leaf starts this subtree.
    hash_node(&[
        b"uxmss-node",
        pk_seed,
        &left_leaf_index.to_be_bytes(),
        &left,
        &right,
    ])
}

fn stateful_empty_tail(pk_seed: &[u8; HASH_LEN], leaf_index: u32) -> [u8; HASH_LEN] {
    // The final live leaf pairs with an explicit empty-tail marker. This lets the
    // root represent "there are no more stateful leaves to the right" without
    // inventing a fake WOTS public key.
    hash_packed(&[b"uxmss-empty-tail", pk_seed, &leaf_index.to_be_bytes()])
}
