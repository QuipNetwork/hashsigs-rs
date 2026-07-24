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


//! Stateful UXMSS sign and verify.
//!
//! Unbalanced-tree WOTS-C scheme used by the stateful side of SHRINCS,
//! mirroring Solidity's `UXMSS.sol`. Builds on `wotsplusc`'s shared chain-walk
//! and grind helpers; `shrincs` drives it directly (no `sphincs_plus_c`
//! dependency — the stateful and stateless signers are independent).

use alloc::vec::Vec;

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::primitives::hash::{base_w16_digit, hash_node, hash_packed, word32};
use crate::primitives::profiles::{
    WOTS_BASE_STATEFUL, WOTS_CHAINS_STATEFUL, WOTS_TARGET_SUM_STATEFUL,
};
use crate::types::{StatefulPublicKey, StatefulSignature, HASH_LEN};
use crate::primitives::wotsplusc;
use crate::primitives::wotsplusc::WOTS_C_MAX_GRIND_COUNTER;

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
    let mut segments = crate::primitives::buf::node_buf::<WOTS_CHAINS_STATEFUL>();
    for (chain_index, segment) in segments.iter_mut().enumerate() {
        let digit = base_w16_digit(&digest, chain_index);
        digit_sum = digit_sum.checked_add(digit)?;
        let chain_value = *signature.chains.get(chain_index)?;
        *segment = wotsplusc::stateful_chain_no_mask(
            &pk_seed,
            wotsplusc::StatefulChainCtx {
                leaf_index,
                chain_index: chain_index as u32,
            },
            wotsplusc::ChainWalk {
                value: chain_value,
                start: digit,
                steps: WOTS_BASE_STATEFUL - 1 - digit,
            },
        );
    }

    if digit_sum != WOTS_TARGET_SUM_STATEFUL {
        return None;
    }
    // Vectored preimage: tag ‖ pk_seed ‖ leaf_index ‖ segment_0 ‖ … —
    // byte-identical to the packed form.
    let leaf_be = leaf_index.to_be_bytes();
    let mut parts: [&[u8]; WOTS_CHAINS_STATEFUL + 3] = [&[]; WOTS_CHAINS_STATEFUL + 3];
    parts[0] = b"uxmss-wots-pk";
    parts[1] = pk_seed.as_ref();
    parts[2] = leaf_be.as_ref();
    for (part, segment) in parts[3..].iter_mut().zip(segments.iter()) {
        *part = segment.as_ref();
    }
    Some(hash_node(&parts))
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

// ── Structured, newtyped UXMSS key (the SHRINCS stateful fast path) ──────────
//
// Each 32-byte role is its own type, distinct from the identically-shaped
// `sphincs_plus_c` roles by module path, so the two `pk_seed`s / roots of the
// SHRINCS hybrid cannot be swapped. This `Key` is the stateful half of a
// `shrincs::Keys`. Flat layout (matching the wasm ABI / legacy serialization):
// `Secret = sk_seed(32) ‖ prf_seed(32)` (64 B), `PublicKey =
// pk_seed(32) ‖ root(32) ‖ max_signatures(4 BE)` (68 B), `Key = Secret ‖
// PublicKey ‖ next_leaf_index(4 BE)` (136 B).

/// Secret seed deriving stateful WOTS-C chain secrets.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SkSeed([u8; HASH_LEN]);

/// Secret PRF seed deriving stateful WOTS-C message randomizers.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrfSeed([u8; HASH_LEN]);

/// Public seed used by stateful WOTS-C and the unbalanced tree hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PkSeed([u8; HASH_LEN]);

/// Root of the stateful unbalanced authentication tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root([u8; HASH_LEN]);

impl SkSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl PrfSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl PkSeed {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl Root {
    /// Wrap 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
    /// Wrap a slice, returning `None` for any length other than 32.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(word32(bytes)?))
    }
    /// Borrow the raw bytes for hashing.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for SkSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SkSeed(<redacted>)")
    }
}

impl fmt::Debug for PrfSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfSeed(<redacted>)")
    }
}

/// The secret half of a stateful key: the 64 bytes that are actually secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    /// Derives stateful WOTS-C chain secrets.
    pub sk_seed: SkSeed,
    /// Derives stateful WOTS-C message randomizers.
    pub prf_seed: PrfSeed,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("sk_seed", &"<redacted>")
            .field("prf_seed", &"<redacted>")
            .finish()
    }
}

/// The public half of a stateful key: `pk_seed ‖ root ‖ max_signatures`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Public seed used by stateful WOTS-C and the unbalanced tree.
    pub pk_seed: PkSeed,
    /// Root of the stateful unbalanced authentication tree.
    pub root: Root,
    /// Highest accepted stateful leaf index.
    pub max_signatures: u32,
}

/// A stateful UXMSS key: secret seeds, public bundle, and the monotonic
/// leaf counter that `sign` advances.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    /// Secret seeds.
    pub secret: Secret,
    /// Public seed, root, and budget.
    pub public_key: PublicKey,
    /// Next monotonic leaf index; advanced on each stateful signature.
    pub next_leaf_index: u32,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("secret", &self.secret)
            .field("public_key", &self.public_key)
            .field("next_leaf_index", &self.next_leaf_index)
            .finish()
    }
}

impl PublicKey {
    /// Encoded stateful public key `pk_seed(32) ‖ root(32) ‖ max(4 BE)`,
    /// 68 bytes (`STATEFUL_PUBLIC_KEY_BYTES`).
    pub fn to_bytes(&self) -> [u8; crate::types::STATEFUL_PUBLIC_KEY_BYTES] {
        let mut out = [0u8; crate::types::STATEFUL_PUBLIC_KEY_BYTES];
        out[..HASH_LEN].copy_from_slice(self.pk_seed.as_bytes());
        out[HASH_LEN..HASH_LEN * 2].copy_from_slice(self.root.as_bytes());
        out[HASH_LEN * 2..].copy_from_slice(&self.max_signatures.to_be_bytes());
        out
    }
    /// Parse the 68-byte encoded stateful public key; `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != crate::types::STATEFUL_PUBLIC_KEY_BYTES {
            return None;
        }
        Some(Self {
            pk_seed: PkSeed::from_slice(bytes.get(..HASH_LEN)?)?,
            root: Root::from_slice(bytes.get(HASH_LEN..HASH_LEN * 2)?)?,
            max_signatures: u32::from_be_bytes(word4(bytes.get(HASH_LEN * 2..)?)?),
        })
    }
}

impl From<PublicKey> for StatefulPublicKey {
    fn from(pk: PublicKey) -> Self {
        Self {
            pk_seed: *pk.pk_seed.as_bytes(),
            root: *pk.root.as_bytes(),
            max_signatures: pk.max_signatures,
        }
    }
}

impl From<StatefulPublicKey> for PublicKey {
    fn from(pk: StatefulPublicKey) -> Self {
        Self {
            pk_seed: PkSeed::new(pk.pk_seed),
            root: Root::new(pk.root),
            max_signatures: pk.max_signatures,
        }
    }
}

fn word4(bytes: &[u8]) -> Option<[u8; 4]> {
    if bytes.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Some(out)
}

pub(crate) fn sign_stateful_raw(key: &mut Key, message: &[u8]) -> Option<StatefulSignature> {
    // The verifier derives the stateful leaf index from auth_path.len(), so the
    // signer must advance one leaf at a time and must never reuse a prior leaf.
    let leaf_index = key.next_leaf_index;
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > key.public_key.max_signatures {
        return None;
    }

    // sign_stateful_raw_at_leaf already computes the identical auth_path (same
    // seeds, leaf_index, and max_signatures), so we must not rebuild it here —
    // stateful_auth_path walks up to max_stateful_signatures nodes and doubled
    // the dominant signing cost.
    let signature = sign_stateful_raw_at_leaf(key, leaf_index, message)?;
    key.next_leaf_index = leaf_index.saturating_add(1);
    Some(signature)
}

pub(crate) fn sign_stateful_raw_at_leaf(
    key: &Key,
    leaf_index: u32,
    message: &[u8],
) -> Option<StatefulSignature> {
    // This deterministic entry point is useful for tests and vector generation.
    // Production signing should use `sign_stateful_raw`, which advances the
    // monotonic `next_stateful_leaf_index` and avoids accidental leaf reuse.
    if leaf_index == 0 {
        return None;
    }
    if leaf_index > key.public_key.max_signatures {
        return None;
    }
    let mut signature = sign_stateful_wots_c(
        key.secret.sk_seed.as_bytes(),
        key.secret.prf_seed.as_bytes(),
        key.public_key.pk_seed.as_bytes(),
        leaf_index,
        message,
    )?;
    signature.auth_path = stateful_auth_path(
        key.secret.sk_seed.as_bytes(),
        key.public_key.pk_seed.as_bytes(),
        leaf_index,
        key.public_key.max_signatures,
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

    let result = crate::primitives::wotsplusc::grind_digit_sum(
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
                    wotsplusc::stateful_chain_no_mask(
                        pk_seed,
                        wotsplusc::StatefulChainCtx {
                            leaf_index,
                            chain_index: chain_index as u32,
                        },
                        wotsplusc::ChainWalk {
                            value: *secret,
                            start: 0,
                            steps: *digit,
                        },
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
    let mut endpoints = crate::primitives::buf::node_buf::<WOTS_CHAINS_STATEFUL>();
    for (chain_index, endpoint) in endpoints.iter_mut().enumerate() {
        // The private chain start is zeroized on drop.
        let secret = Zeroizing::new(stateful_chain_secret(
            sk_seed,
            pk_seed,
            leaf_index,
            chain_index as u32,
        ));
        *endpoint = wotsplusc::stateful_chain_no_mask(
            pk_seed,
            wotsplusc::StatefulChainCtx {
                leaf_index,
                chain_index: chain_index as u32,
            },
            wotsplusc::ChainWalk {
                value: *secret,
                start: 0,
                steps: WOTS_BASE_STATEFUL - 1,
            },
        );
    }
    // Vectored preimage, byte-identical to the packed form used by the
    // signature-side reconstruction above.
    let leaf_be = leaf_index.to_be_bytes();
    let mut parts: [&[u8]; WOTS_CHAINS_STATEFUL + 3] = [&[]; WOTS_CHAINS_STATEFUL + 3];
    parts[0] = b"uxmss-wots-pk";
    parts[1] = pk_seed.as_ref();
    parts[2] = leaf_be.as_ref();
    for (part, endpoint) in parts[3..].iter_mut().zip(endpoints.iter()) {
        *part = endpoint.as_ref();
    }
    hash_node(&parts)
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

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn public_key_bytes_round_trip() {
        let pk = PublicKey {
            pk_seed: PkSeed::new([7u8; HASH_LEN]),
            root: Root::new([9u8; HASH_LEN]),
            max_signatures: 1024,
        };
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), crate::types::STATEFUL_PUBLIC_KEY_BYTES);
        // max_signatures is the trailing 4 big-endian bytes.
        assert_eq!(&bytes[HASH_LEN * 2..], &1024u32.to_be_bytes());
        assert_eq!(PublicKey::from_bytes(&bytes), Some(pk));
    }

    #[test]
    fn public_key_bridges_to_and_from_legacy() {
        let pk = PublicKey {
            pk_seed: PkSeed::new([1u8; HASH_LEN]),
            root: Root::new([2u8; HASH_LEN]),
            max_signatures: 8,
        };
        let legacy: StatefulPublicKey = pk.into();
        assert_eq!(legacy.max_signatures, 8);
        assert_eq!(PublicKey::from(legacy), pk);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert_eq!(PublicKey::from_bytes(&[0u8; 67]), None);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret {
            sk_seed: SkSeed::new([3u8; HASH_LEN]),
            prf_seed: PrfSeed::new([4u8; HASH_LEN]),
        };
        let shown = alloc::format!("{secret:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains("03"));
    }
}
