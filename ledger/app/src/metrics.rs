// SPDX-License-Identifier: AGPL-3.0-or-later
//! Measurement build only: same allocator and capacity as the default SDK heap.
use core::alloc::{GlobalAlloc, Layout};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use embedded_alloc::Heap;
use ledger_device_sdk::testing::StackTracker;

#[cfg(feature = "sdk-heap")]
compile_error!("memory-metrics requires --no-default-features (one allocator)");

struct SingleThread;
critical_section::set_impl!(SingleThread);
// Same no-op implementation as the pinned SDK: Rust runs in one app context.
unsafe impl critical_section::Impl for SingleThread {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}
struct MeasuredHeap(Heap);
#[global_allocator]
static HEAP: MeasuredHeap = MeasuredHeap(Heap::empty());
static PEAK: AtomicUsize = AtomicUsize::new(0);
const SIZE: usize = ledger_device_sdk::sys::HEAP_SIZE;
unsafe impl GlobalAlloc for MeasuredHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { self.0.alloc(layout) };
        let used = self.0.used();
        if used > PEAK.load(Ordering::Relaxed) {
            PEAK.store(used, Ordering::Relaxed);
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.0.dealloc(ptr, layout) }
    }
}
pub fn init() {
    static mut MEMORY: [MaybeUninit<u8>; SIZE] = [MaybeUninit::uninit(); SIZE];
    unsafe {
        HEAP.0.init(core::ptr::addr_of_mut!(MEMORY) as usize, SIZE);
    }
    StackTracker::init();
}
pub fn report() -> [u8; 20] {
    unsafe extern "C" {
        static _stack: u8;
        static _estack: u8;
    }
    let stack_size = core::ptr::addr_of!(_estack) as usize - core::ptr::addr_of!(_stack) as usize;
    let mut bytes = [0; 20];
    for (chunk, value) in bytes.chunks_exact_mut(4).zip([
        SIZE,
        PEAK.load(Ordering::Relaxed),
        HEAP.0.used(),
        stack_size,
        StackTracker::get_usage(),
    ]) {
        chunk.copy_from_slice(&(value as u32).to_be_bytes());
    }
    bytes
}
