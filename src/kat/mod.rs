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

//! Known-answer test support for the EasyCrypt development in
//! `proofs/easycrypt` (feature `kat-trace`).
//!
//! While armed, the recorder keeps the input and the digest of every Keccak
//! call of the crate. The EasyCrypt specification keeps Keccak abstract, and
//! each replay file defines it as a lookup table over one recorded trace.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::HASH_LEN;

mod cases;
mod group;
mod toy;
mod value;

pub use cases::{catalog, Builder};
pub use group::{Case, Group};
pub use toy::{Toy, TOY_CHAINS, TOY_LAYERS};
pub use value::Value;

/// Recorded calls: the concatenated input of each call and its digest.
pub type Trace = BTreeMap<Vec<u8>, [u8; HASH_LEN]>;

static ARMED: AtomicBool = AtomicBool::new(false);
static TRACE: Mutex<Trace> = Mutex::new(BTreeMap::new());

fn trace() -> MutexGuard<'static, Trace> {
    // A panic while the lock is held leaves a map that is still well formed.
    TRACE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Clear the trace and start recording.
pub fn arm() {
    trace().clear();
    ARMED.store(true, Ordering::SeqCst);
}

/// Stop recording and return the calls recorded since `arm`.
pub fn disarm() -> Trace {
    ARMED.store(false, Ordering::SeqCst);
    core::mem::take(&mut *trace())
}

/// Called by the hash backend after each Keccak call.
pub(crate) fn record(parts: &[&[u8]], digest: &[u8; HASH_LEN]) {
    if ARMED.load(Ordering::Relaxed) {
        trace().insert(parts.concat(), *digest);
    }
}

#[cfg(test)]
mod tests {
    use super::{arm, disarm};
    use crate::hash::backend::keccak256v;

    // The recorder is process-wide, so other tests that hash while it is
    // armed add entries. Each assertion checks only the inputs of its own test.
    #[test]
    fn armed_recorder_captures_the_input_and_digest_of_each_call() {
        arm();
        let digest = keccak256v(&[b"kat-trace/", b"armed"]);
        let trace = disarm();
        assert_eq!(trace.get(b"kat-trace/armed".as_slice()), Some(&digest));
    }

    #[test]
    fn unarmed_recorder_captures_nothing() {
        let _ = disarm();
        keccak256v(&[b"kat-trace/unarmed"]);
        arm();
        let trace = disarm();
        assert!(!trace.contains_key(b"kat-trace/unarmed".as_slice()));
    }
}
