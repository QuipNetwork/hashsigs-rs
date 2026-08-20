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

//! Verify-path allocation budget.
//!
//! Enforces the crate's allocation policy (see `src/buf.rs`): signature
//! verification never touches the heap, on every target. On Solana this is
//! load-bearing — the bump allocator never frees, so verify-path heap use
//! would accumulate against the 32 KiB program heap.
//!
//! A counting global allocator wraps the system allocator; signing/keygen run
//! before the measured window (signing allocates wire types by design).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations() -> u64 {
    ALLOCATIONS.load(Ordering::SeqCst)
}

/// Measure `f` and return (result, allocations performed while it ran).
/// The counting allocator is process-global: it counts allocations from every
/// thread, so any allocation on another test thread (setup or a measured
/// window) contaminates a measurement. cargo runs tests in parallel, so each
/// test in this binary holds this lock for its WHOLE body — setup included —
/// to guarantee only one alloc-sensitive test runs at a time.
static MEASURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn measured<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = allocations();
    let result = f();
    (result, allocations() - before)
}

fn assert_verify_budget(what: &str, allocs: u64) {
    assert_eq!(
        allocs, 0,
        "{what} must be heap-free, performed {allocs} allocations"
    );
}

#[cfg_attr(
    any(shrincs_profile_128s_q18, shrincs_profile_128s_q20),
    ignore = "128s signing grinds ~2^24 counters; the allocation budget is profile-independent and enforced by the 256s lanes"
)]
#[cfg_attr(
    feature = "parallel",
    ignore = "rayon allocates task/pool state inside the measured window; the budget applies to the sequential verify path"
)]
#[test]
fn stateless_verify_stays_within_allocation_budget() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SPHINCS+C layer: independent keypair, arbitrary 32-byte message.
    let sk = hashsigs_rs::sphincs_plus_c::keygen([0x11; 32], [0x22; 32], [0x33; 32]);
    let message = [0x44u8; 32];
    let sig = hashsigs_rs::sphincs_plus_c::sign(&sk, &message).expect("sign");

    let (valid, allocs) =
        measured(|| hashsigs_rs::sphincs_plus_c::verify(&sk.public_key, &message, &sig));
    assert!(valid);
    assert_verify_budget("SPHINCS+C stateless verify", allocs);

    // SHRINCS dispatch layer on top (commitment check + action envelope):
    // must obey the same budget.
    use hashsigs_rs::shrincs::{ActionContext, ShrincsSigner, ShrincsVerifier};

    let (signing_key, public_key) =
        ShrincsSigner::keygen(b"alloc-budget shrincs key", 1).expect("keygen");
    let verifier = ShrincsVerifier::new();
    let commitment: [u8; 32] = public_key
        .public_key_commitment
        .as_slice()
        .try_into()
        .expect("32-byte commitment");
    let context = ActionContext {
        domain_separator: [0x51; 32],
        nonce: [0x52; 32],
        key_version: [0x53; 32],
        action_type: [0x54; 32],
        payload_hash: [0x55; 32],
    };
    let action_message = verifier.stateless_action_message_hash(commitment, &context);
    let action_sig =
        ShrincsSigner::sign_stateless_raw(&signing_key, &action_message).expect("sign");

    let (valid, allocs) =
        measured(|| verifier.verify_stateless(commitment, &public_key, &context, &action_sig));
    assert!(valid);
    assert_verify_budget("SHRINCS stateless dispatch verify", allocs);
}

#[cfg_attr(
    any(shrincs_profile_128s_q18, shrincs_profile_128s_q20),
    ignore = "128s signing grinds ~2^24 counters; the allocation budget is profile-independent and enforced by the 256s lanes"
)]
#[cfg_attr(
    feature = "parallel",
    ignore = "rayon allocates task/pool state inside the measured window; the budget applies to the sequential verify path"
)]
#[test]
fn stateful_verify_stays_within_allocation_budget() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Solana's account program runs stateful verify per action; the same
    // zero-alloc budget applies as for the stateless path.
    use hashsigs_rs::shrincs::{ActionContext, ShrincsSigner, ShrincsVerifier};

    let (mut signing_key, public_key) =
        ShrincsSigner::keygen(b"alloc-budget shrincs stateful key", 4).expect("keygen");
    let verifier = ShrincsVerifier::new();
    let commitment: [u8; 32] = public_key
        .public_key_commitment
        .as_slice()
        .try_into()
        .expect("32-byte commitment");
    let context = ActionContext {
        domain_separator: [0x61; 32],
        nonce: [0x62; 32],
        key_version: [0x63; 32],
        action_type: [0x64; 32],
        payload_hash: [0x65; 32],
    };
    let action_sig =
        ShrincsSigner::sign_stateful_action(&mut signing_key, &public_key, &context).expect("sign");

    let (valid, allocs) =
        measured(|| verifier.verify_stateful(commitment, &public_key, &context, &action_sig));
    assert!(valid);
    assert_verify_budget("SHRINCS stateful dispatch verify", allocs);
}
