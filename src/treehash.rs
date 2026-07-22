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

//! Streaming Merkle treehash with O(height) stack memory.
//!
//! Classic left-to-right treehash: leaves are generated on the fly and merged
//! via a stack of at most `height + 1` nodes. When a produced node is the
//! sibling of the selected leaf's path at height `h`, it is recorded in the
//! authentication path. Wire-identical to a full level-by-level materialization.

use alloc::vec;
use alloc::vec::Vec;

use crate::types::HASH_LEN;

/// Compute the Merkle root and auth path for `selected_leaf` without storing
/// the full leaf level.
///
/// - `leaf_hash(i)` produces the hash of leaf index `i` (0..2^height).
/// - `parent(node_height, parent_index, left, right)` hashes two children into
///   the parent at the given height/index (domain separation is caller-owned).
///
/// Number of leaves generated per parallel batch when the `parallel` feature
/// is enabled. Leaves within a batch are hashed concurrently; the fold back
/// into the stack always proceeds in strict leaf order, so the resulting
/// root and auth path are identical to the sequential traversal.
#[cfg(feature = "parallel")]
const PARALLEL_LEAF_BATCH: u32 = 256;

/// Memory: stack of ≤ `height + 1` nodes (≤ 25 × 32 B for height 24).
pub(crate) fn treehash_root_and_auth_path<F>(
    height: u32,
    selected_leaf: u32,
    leaf_hash: F,
    mut parent: impl FnMut(u32, u64, [u8; HASH_LEN], [u8; HASH_LEN]) -> [u8; HASH_LEN],
) -> ([u8; HASH_LEN], Vec<[u8; HASH_LEN]>)
where
    F: Fn(u32) -> [u8; HASH_LEN] + Sync,
{
    debug_assert!(height < u32::BITS);
    let leaf_count = 1u32 << height;
    let mut stack: Vec<([u8; HASH_LEN], u32)> = Vec::with_capacity(height as usize + 1);
    let mut auth_path = vec![[0u8; HASH_LEN]; height as usize];

    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        let mut start = 0u32;
        while start < leaf_count {
            let end = start.saturating_add(PARALLEL_LEAF_BATCH).min(leaf_count);
            let batch: Vec<[u8; HASH_LEN]> = (start..end).into_par_iter().map(&leaf_hash).collect();
            for (offset, node) in batch.into_iter().enumerate() {
                fold_leaf(
                    start + offset as u32,
                    node,
                    selected_leaf,
                    &mut stack,
                    &mut auth_path,
                    &mut parent,
                );
            }
            start = end;
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        for i in 0..leaf_count {
            let node = leaf_hash(i);
            fold_leaf(
                i,
                node,
                selected_leaf,
                &mut stack,
                &mut auth_path,
                &mut parent,
            );
        }
    }

    let root = match stack.pop() {
        Some((node, _)) => node,
        // Unreachable for height < 32: leaf_count >= 1 always leaves one node.
        None => [0u8; HASH_LEN],
    };
    (root, auth_path)
}

/// Fold one leaf into the streaming stack, merging equal-height siblings and
/// recording the auth-path sibling whenever a produced node sits next to the
/// selected leaf's path. Shared by both the sequential and batched-parallel
/// leaf-generation loops so the merge order (and therefore the result) is
/// identical between them.
#[inline]
fn fold_leaf(
    i: u32,
    mut node: [u8; HASH_LEN],
    selected_leaf: u32,
    stack: &mut Vec<([u8; HASH_LEN], u32)>,
    auth_path: &mut [[u8; HASH_LEN]],
    parent: &mut impl FnMut(u32, u64, [u8; HASH_LEN], [u8; HASH_LEN]) -> [u8; HASH_LEN],
) {
    let mut node_h = 0u32;
    record_auth_sibling(auth_path, selected_leaf, i, node_h, &node);

    while stack.last().is_some_and(|(_, h)| *h == node_h) {
        let Some((left, _)) = stack.pop() else {
            break;
        };
        let next_h = node_h + 1;
        let parent_index = u64::from(i >> next_h);
        node = parent(next_h, parent_index, left, node);
        node_h = next_h;
        record_auth_sibling(auth_path, selected_leaf, i, node_h, &node);
    }
    stack.push((node, node_h));
}

#[inline]
fn record_auth_sibling(
    auth_path: &mut [[u8; HASH_LEN]],
    selected_leaf: u32,
    rightmost_leaf: u32,
    node_h: u32,
    node: &[u8; HASH_LEN],
) {
    if node_h >= auth_path.len() as u32 {
        return;
    }
    let path_sibling = (selected_leaf >> node_h) ^ 1;
    let node_index = rightmost_leaf >> node_h;
    if path_sibling == node_index {
        if let Some(slot) = auth_path.get_mut(node_h as usize) {
            *slot = *node;
        }
    }
}

/// Naive full-level builder used only as a correctness oracle in tests.
#[cfg(test)]
pub(crate) fn naive_tree_root_and_auth_path(
    height: u32,
    selected_leaf: u32,
    mut leaf_hash: impl FnMut(u32) -> [u8; HASH_LEN],
    mut parent: impl FnMut(u32, u64, [u8; HASH_LEN], [u8; HASH_LEN]) -> [u8; HASH_LEN],
) -> ([u8; HASH_LEN], Vec<[u8; HASH_LEN]>) {
    let leaf_count = 1usize << height;
    let mut level = Vec::with_capacity(leaf_count);
    for i in 0..leaf_count as u32 {
        level.push(leaf_hash(i));
    }
    let mut index = selected_leaf as usize;
    let mut auth_path = Vec::with_capacity(height as usize);

    for node_height in 1..=height {
        let sibling = level.get(index ^ 1).copied().unwrap_or([0u8; HASH_LEN]);
        auth_path.push(sibling);
        let mut parents = Vec::with_capacity(level.len() / 2);
        for (parent_index, pair) in level.chunks_exact(2).enumerate() {
            parents.push(parent(
                node_height,
                parent_index as u64,
                pair[0],
                pair[1],
            ));
        }
        level = parents;
        index >>= 1;
    }

    let root = level.first().copied().unwrap_or([0u8; HASH_LEN]);
    (root, auth_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_node;
    use proptest::prelude::*;

    fn test_parent(
        node_height: u32,
        parent_index: u64,
        left: [u8; HASH_LEN],
        right: [u8; HASH_LEN],
    ) -> [u8; HASH_LEN] {
        hash_node(&[
            b"treehash-test-node".as_ref(),
            &node_height.to_be_bytes(),
            &parent_index.to_be_bytes(),
            left.as_ref(),
            right.as_ref(),
        ])
    }

    fn test_leaf(seed: u64, index: u32) -> [u8; HASH_LEN] {
        hash_node(&[
            b"treehash-test-leaf".as_ref(),
            &seed.to_be_bytes(),
            &index.to_be_bytes(),
        ])
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn streaming_matches_naive_small_trees(
            height in 0u32..=8,
            seed in any::<u64>(),
            selected_raw in any::<u32>(),
        ) {
            let leaf_count = 1u32 << height;
            let selected_leaf = selected_raw % leaf_count;

            let (stream_root, stream_auth) = treehash_root_and_auth_path(
                height,
                selected_leaf,
                |i| test_leaf(seed, i),
                test_parent,
            );
            let (naive_root, naive_auth) = naive_tree_root_and_auth_path(
                height,
                selected_leaf,
                |i| test_leaf(seed, i),
                test_parent,
            );

            prop_assert_eq!(stream_auth.len(), height as usize);
            prop_assert_eq!(stream_root, naive_root);
            prop_assert_eq!(stream_auth, naive_auth);
        }
    }

    #[test]
    fn height_zero_is_single_leaf() {
        let (root, auth) = treehash_root_and_auth_path(0, 0, |_| [0xab; HASH_LEN], test_parent);
        assert_eq!(root, [0xab; HASH_LEN]);
        assert!(auth.is_empty());
    }

    #[test]
    fn height_one_auth_is_sibling() {
        let (root, auth) = treehash_root_and_auth_path(
            1,
            0,
            |i| test_leaf(1, i),
            test_parent,
        );
        let (naive_root, naive_auth) = naive_tree_root_and_auth_path(
            1,
            0,
            |i| test_leaf(1, i),
            test_parent,
        );
        assert_eq!(root, naive_root);
        assert_eq!(auth, naive_auth);
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0], test_leaf(1, 1));
    }
}
