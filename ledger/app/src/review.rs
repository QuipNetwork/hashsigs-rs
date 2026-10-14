// SPDX-License-Identifier: AGPL-3.0-or-later
//! Choice UI with explicit busy replies. The SDK's synchronous Choice queues
//! an arriving APDU and stops polling touch events; it cannot serve this flow.
use crate::{AppSW, ICON};
use alloc::ffi::CString;
use core::sync::atomic::{AtomicU8, Ordering};
use ledger_device_sdk::{
    io::{Comm, DecodedEventType},
    sys,
};

static DECISION: AtomicU8 = AtomicU8::new(0);
unsafe extern "C" fn choice(approved: bool) {
    DECISION.store(if approved { 2 } else { 1 }, Ordering::Relaxed);
}

pub fn show<const N: usize>(
    comm: &mut Comm<N>,
    title: &str,
    detail: &str,
    yes: &str,
    no: &str,
) -> bool {
    let title = CString::new(title).unwrap();
    let detail = CString::new(detail).unwrap();
    let yes = CString::new(yes).unwrap();
    let no = CString::new(no).unwrap();
    let icon: sys::nbgl_icon_details_t = (&ICON).into();
    DECISION.store(0, Ordering::Relaxed);
    unsafe {
        sys::nbgl_useCaseChoice(
            &icon,
            title.as_ptr(),
            detail.as_ptr(),
            yes.as_ptr(),
            no.as_ptr(),
            Some(choice),
        );
    }
    while DECISION.load(Ordering::Relaxed) == 0 {
        match comm.next_event().into_type() {
            DecodedEventType::Apdu { .. } | DecodedEventType::ApduError(_) => {
                let _ = comm.send(&[], AppSW::BadState);
            }
            _ => {}
        }
    }
    DECISION.load(Ordering::Relaxed) == 2
}
