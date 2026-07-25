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

#![allow(unexpected_cfgs)]
// Panic-prevention lints, mirroring the core `hashsigs-rs` crate root: program
// code must not panic on untrusted input. Scoped to non-test builds so
// `#[cfg(test)]` modules may use unwrap/expect freely.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic_in_result_fn
    )
)]

pub mod messages;
pub mod pda;
pub mod processor;
pub mod rotation;
pub mod state;

use crate::processor::process_instruction;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

// The default allocator the entrypoint macro installs is hard-bounded to the
// 32 KiB minimum heap even when the transaction requested a larger frame via
// ComputeBudgetInstruction::request_heap_frame. With `custom-heap` (default)
// we install an upward-bumping allocator with no compile-time bound; the VM
// enforces the granted frame size (out-of-frame access faults the program),
// so the effective heap is exactly what the transaction requested.
#[cfg(all(
    feature = "custom-heap",
    target_os = "solana",
    not(feature = "no-entrypoint")
))]
mod heap {
    use std::alloc::{GlobalAlloc, Layout};

    struct UnboundedBump;

    // First 8 bytes of the heap region hold the bump cursor.
    const HEAP_START: usize = solana_program::entrypoint::HEAP_START_ADDRESS as usize;

    // SAFETY: `GlobalAlloc` requires `alloc` to return a block satisfying the
    // requested `Layout` (or null) and the allocator to be sound under the
    // platform's concurrency model. A Solana program runs single-threaded in
    // one VM invocation (no data race on the bump cursor), and `HEAP_START`
    // addresses the VM-provided, program-exclusive heap region.
    unsafe impl GlobalAlloc for UnboundedBump {
        // SAFETY: `cursor` points at `HEAP_START`, the first word of the
        // VM-owned heap this program alone accesses; the single-threaded
        // invocation makes the `*cursor` read/write race-free. Aligned-bump
        // overflow is caught by `checked_add`, returning null per contract.
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let cursor = HEAP_START as *mut usize;
            let mut position = *cursor;
            if position == 0 {
                position = HEAP_START + core::mem::size_of::<usize>();
            }
            let aligned = position
                .checked_add(layout.align() - 1)
                .map(|p| p & !(layout.align() - 1));
            let Some(aligned) = aligned else {
                return core::ptr::null_mut();
            };
            let Some(next) = aligned.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            *cursor = next;
            aligned as *mut u8
        }

        // SAFETY: a bump allocator never reclaims individual allocations; the
        // whole heap region is released by the VM at transaction end, so an
        // empty `dealloc` upholds `GlobalAlloc`'s contract (introduces no
        // double-free or use-after-free).
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator: freed memory is reclaimed at transaction end.
        }
    }

    #[global_allocator]
    static ALLOCATOR: UnboundedBump = UnboundedBump;
}
