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

//! FORS-C signing.
//!
//! A key owns one FORS forest. The message digest chooses one leaf in each FORS
//! tree and also chooses the starting hypertree coordinates above the FORS layer.
//! Those coordinates are address/domain context for the opened leaves and nodes,
//! not a selector for a separate FORS public key.

use super::super::components::fors_c;
use super::super::profiles::{FORS_C_MAX_GRIND_COUNTER, NUM_FORS_TREES};
use super::types::{ShrincsSignerResult, ShrincsSigningKey};
use super::utils::{hash_node, hash_packed};
use super::super::types::{ForsEntry, ForsSignature, HASH_LEN};

fn stateless_trace_enabled() -> bool {
    matches!(
        std::env::var("SHRINCS_TRACE_STATELESS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

fn stateless_trace_counter_every() -> u32 {
    std::env::var("SHRINCS_TRACE_COUNTER_EVERY")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1 << 20)
}

fn stateless_trace(message: &str) {
    if stateless_trace_enabled() {
        println!("{message}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedForsC {
    /// Aggregate FORS public root reconstructed from the opened tree roots.
    pub root: [u8; HASH_LEN],
    /// Signature payload that the verifier consumes: one secret leaf and auth path
    /// for every signed FORS tree.
    pub signature: ForsSignature,
    /// Layer-0 hypertree tree selected by the FORS message digest.
    pub tree_index: u64,
    /// Layer-0 hypertree leaf selected by the FORS message digest.
    pub leaf_index: u32,
}

pub(crate) fn sign_fors_c(
    signing_key: &ShrincsSigningKey,
    message: &[u8],
) -> ShrincsSignerResult<SignedForsC> {
    stateless_trace(&format!(
        "stateless trace: FORS start message_len={} signed_trees={} max_counter={}",
        message.len(),
        NUM_FORS_TREES as usize - 1,
        FORS_C_MAX_GRIND_COUNTER
    ));
    // FORS-C signs k - 1 trees. The final tree is omitted only when the digest
    // selects leaf zero for that final tree, so the signer grinds the counter
    // until that condition holds.
    let signed_trees = NUM_FORS_TREES as usize - 1;

    // This is the FORS-C local message randomizer. It is deterministic for the
    // same stateless PRF seed and message, matching the SPHINCS-style separation
    // between SK.seed-derived signing secrets and SK.prf-derived randomness.
    let randomizer = hash_packed(&[b"fors-randomizer", &signing_key.stateless_prf_seed, message]);
    stateless_trace("stateless trace: FORS randomizer ready");

    if let Some((counter, digest)) =
        winning_fors_counter_and_digest(signing_key, message, &randomizer, FORS_C_MAX_GRIND_COUNTER)
    {
        stateless_trace(&format!(
            "stateless trace: FORS winner counter={} tree_index={} leaf_index={}",
            counter, digest.tree_index, digest.leaf_index
        ));

        let mut roots = Vec::with_capacity(signed_trees * HASH_LEN);
        let mut entries = Vec::with_capacity(signed_trees);
        for fors_tree in 0..signed_trees {
            if stateless_trace_enabled() && (fors_tree == 0 || fors_tree + 1 == signed_trees) {
                println!(
                    "stateless trace: FORS materializing tree {}/{}",
                    fors_tree + 1,
                    signed_trees
                );
            }
            // For each selected tree, reveal exactly the chosen secret leaf and
            // provide the siblings needed to recompute that tree's root.
            let leaf = digest.signed_tree_indices[fors_tree];
            let (root, secret_leaf, auth_path) = fors_c::fors_tree_root_and_auth_path(
                &signing_key.pk_seed,
                &signing_key.stateless_sk_seed,
                digest.tree_index,
                digest.leaf_index,
                fors_tree as u32,
                leaf,
            );
            roots.extend_from_slice(&root);
            entries.push(ForsEntry {
                secret_leaf: secret_leaf.to_vec(),
                auth_path,
            });
        }

        // The verifier aggregates the reconstructed per-tree roots the same way.
        // The public seed is included so roots from a different FORS key cannot
        // be transplanted into this key.
        return Some(SignedForsC {
            root: hash_node(&[b"fors-pk", &signing_key.pk_seed, &roots]),
            signature: ForsSignature {
                randomizer: randomizer.to_vec(),
                counter,
                entries,
            },
            tree_index: digest.tree_index,
            leaf_index: digest.leaf_index,
        });
    }

    stateless_trace("stateless trace: FORS no winning counter found");
    None
}

fn winning_fors_counter_and_digest(
    signing_key: &ShrincsSigningKey,
    message: &[u8],
    randomizer: &[u8; HASH_LEN],
    limit: u32,
) -> Option<(u32, super::super::components::fors_c::SigningForsDigest)> {
    let trace_enabled = stateless_trace_enabled();
    let trace_every = stateless_trace_counter_every();
    if trace_enabled {
        println!("stateless trace: FORS counter search start limit={limit}");
    }
    for counter in 0..limit {
        if trace_enabled && counter > 0 && counter % trace_every == 0 {
            println!("stateless trace: FORS counter search tried={counter}/{limit}");
        }
        // The counter is public and stored in the signature. Its only job is to
        // find a digest whose omitted final FORS tree opens leaf zero.
        let Some(digest) = fors_c::signer_fors_digest(
            &signing_key.pk_seed,
            &signing_key.hypertree_root,
            message,
            randomizer,
            counter,
        ) else {
            continue;
        };
        if digest.omitted_final_tree_is_zero {
            if trace_enabled {
                println!("stateless trace: FORS counter search success counter={counter}");
            }
            return Some((counter, digest));
        }
    }
    if trace_enabled {
        println!("stateless trace: FORS counter search exhausted limit={limit}");
    }
    None
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    use super::{winning_fors_counter_and_digest, FORS_C_MAX_GRIND_COUNTER, ShrincsSigningKey};
    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    use crate::shrincs::components::public_key::encode_stateful_public_key;
    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    use crate::shrincs::signers::utils::{derive32, hash_packed, public_key_from_components};
    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    use crate::shrincs::signers::uxmss::stateful_subtree_root;

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    fn measurement_key(seed: &[u8], max: u32) -> ShrincsSigningKey {
        println!(
            "measurement setup: deriving stateful-only key profile={} max_stateful_signatures={max}",
            crate::shrincs::PROFILE_NAME
        );
        let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed, &[]);
        let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed, &[]);
        let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed, &[]);
        println!("measurement setup: computing stateful_subtree_root");
        let stateful_root = stateful_subtree_root(
            &stateful_sk_seed,
            &stateful_pk_seed,
            1,
            max,
        );
        println!("measurement setup: stateful_subtree_root ready");
        let pk_seed = derive32(b"shrincs-pk-seed", seed, &[]);
        let hypertree_root = derive32(b"placeholder-hypertree-root", seed, &[]);
        let _public_key = public_key_from_components(
            encode_stateful_public_key(stateful_pk_seed, stateful_root, max),
            pk_seed,
            hypertree_root,
        );
        println!("measurement setup: key material ready");
        ShrincsSigningKey {
            stateful_sk_seed,
            stateful_prf_seed,
            stateful_pk_seed,
            stateful_root,
            max_stateful_signatures: max,
            next_stateful_leaf_index: 1,
            stateless_sk_seed: derive32(b"shrincs-stateless-sk-seed", seed, &[]),
            stateless_prf_seed: derive32(b"shrincs-stateless-prf-seed", seed, &[]),
            pk_seed,
            hypertree_root,
        }
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    fn measurement_env_u32(name: &str, default: u32) -> u32 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(default)
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    fn measurement_progress_interval(samples: u32) -> u32 {
        let default = if samples <= 10 { 1 } else { samples / 10 };
        measurement_env_u32("SHRINCS_FORS_MEASURE_PROGRESS_EVERY", default).max(1)
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    fn measurement_counter_progress_interval(limit: u32) -> u32 {
        let default = (limit / 16).max(1);
        measurement_env_u32("SHRINCS_FORS_MEASURE_COUNTER_PROGRESS_EVERY", default).max(1)
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    fn measured_winning_fors_counter_and_digest(
        signing_key: &ShrincsSigningKey,
        message: &[u8],
        randomizer: &[u8; crate::shrincs::HASH_LEN],
        limit: u32,
        sample_index: u32,
        counter_progress_every: u32,
    ) -> Option<(u32, super::super::super::components::fors_c::SigningForsDigest)> {
        for counter in 0..limit {
            if counter > 0 && counter % counter_progress_every == 0 {
                println!(
                    "counter progress profile={} sample={}/? tried={counter}/{limit}",
                    crate::shrincs::PROFILE_NAME,
                    sample_index + 1
                );
            }
            let Some(digest) = super::super::super::components::fors_c::signer_fors_digest(
                &signing_key.pk_seed,
                &signing_key.hypertree_root,
                message,
                randomizer,
                counter,
            ) else {
                continue;
            };
            if digest.omitted_final_tree_is_zero {
                return Some((counter, digest));
            }
        }
        None
    }

    #[cfg(any(feature = "profile-128s-q18", feature = "profile-128s-q20"))]
    #[test]
    #[ignore = "manual 128s FORS-C success/failure measurement"]
    fn measure_128_fors_signature_success_rate() {
        let samples = measurement_env_u32("SHRINCS_FORS_MEASURE_SAMPLES", 32);
        let limit =
            measurement_env_u32("SHRINCS_FORS_MEASURE_LIMIT", FORS_C_MAX_GRIND_COUNTER);
        let progress_every = measurement_progress_interval(samples);
        let counter_progress_every = measurement_counter_progress_interval(limit);
        println!(
            "starting FORS measurement profile={} samples={samples} limit={limit} progress_every={progress_every} counter_progress_every={counter_progress_every}",
            crate::shrincs::PROFILE_NAME,
        );
        let signing_key = measurement_key(b"fors success-rate measurement key", 4);

        let mut successes = 0u32;
        let mut failures = 0u32;
        let mut max_success_counter = 0u32;
        let mut sum_success_counters = 0u64;

        for i in 0..samples {
            let counter_bytes = i.to_be_bytes();
            let message = hash_packed(&[
                b"fors-success-rate-measurement".as_ref(),
                counter_bytes.as_ref(),
            ]);
            let randomizer = hash_packed(&[
                b"fors-randomizer".as_ref(),
                signing_key.stateless_prf_seed.as_ref(),
                message.as_ref(),
            ]);
            match measured_winning_fors_counter_and_digest(
                &signing_key,
                &message,
                &randomizer,
                limit,
                i,
                counter_progress_every,
            ) {
                Some((counter, _)) => {
                    successes += 1;
                    sum_success_counters += u64::from(counter);
                    max_success_counter = max_success_counter.max(counter);
                }
                None => failures += 1,
            }

            let completed = i + 1;
            if completed % progress_every == 0 || completed == samples {
                println!(
                    "progress profile={} completed={completed}/{samples} successes={successes} failures={failures}",
                    crate::shrincs::PROFILE_NAME
                );
            }
        }

        let success_pct = if samples == 0 {
            0.0
        } else {
            (successes as f64 * 100.0) / samples as f64
        };
        let failure_pct = if samples == 0 {
            0.0
        } else {
            (failures as f64 * 100.0) / samples as f64
        };
        let avg_success_counter = if successes == 0 {
            0.0
        } else {
            sum_success_counters as f64 / successes as f64
        };

        println!(
            "profile={} samples={samples} limit={limit} successes={successes} failures={failures} success_pct={success_pct:.2} failure_pct={failure_pct:.2} avg_success_counter={avg_success_counter:.2} max_success_counter={max_success_counter}",
            crate::shrincs::PROFILE_NAME
        );
    }
}
