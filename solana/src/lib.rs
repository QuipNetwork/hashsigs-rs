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

pub mod processor;
pub mod sphincs_plus_c;

use crate::processor::process_instruction;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

// The default allocator the entrypoint macro installs is hard-bounded to the
// 32 KiB minimum heap even when the transaction requested a larger frame via
// ComputeBudgetInstruction::request_heap_frame. With `custom-heap` (default)
// we install an upward-bumping allocator with no compile-time bound; the VM
// enforces the granted frame size (out-of-frame access faults the program),
// so the effective heap is exactly what the transaction requested.
#[cfg(all(feature = "custom-heap", target_os = "solana", not(feature = "no-entrypoint")))]
mod heap {
    use std::alloc::{GlobalAlloc, Layout};

    struct UnboundedBump;

    // First 8 bytes of the heap region hold the bump cursor.
    const HEAP_START: usize = solana_program::entrypoint::HEAP_START_ADDRESS as usize;

    unsafe impl GlobalAlloc for UnboundedBump {
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

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator: freed memory is reclaimed at transaction end.
        }
    }

    #[global_allocator]
    static ALLOCATOR: UnboundedBump = UnboundedBump;
}
