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


//! Consolidated `#[cfg(test)]` helpers shared across modules.

use crate::shrincs::{derive32, Keys, ShrincsSigner};
use crate::sphincs_plus_c;
use crate::shrincs::PublicKey;

/// Build a signing key that exercises only the stateful subsystem, with a
/// placeholder hypertree root. Avoids compute-infeasible stateless hypertree
/// keygen so it runs on every profile.
pub(crate) fn stateful_only_key(seed: &[u8], max: u32) -> (Keys, PublicKey) {
    let pk_seed = derive32(b"shrincs-pk-seed", seed, &[]);
    let hypertree_root = derive32(b"placeholder-hypertree-root", seed, &[]);
    let stateless = sphincs_plus_c::Key {
        secret: sphincs_plus_c::Secret {
            sk_seed: sphincs_plus_c::SkSeed::new(derive32(b"shrincs-stateless-sk-seed", seed, &[])),
            prf_seed: sphincs_plus_c::PrfSeed::new(derive32(
                b"shrincs-stateless-prf-seed",
                seed,
                &[],
            )),
        },
        public_key: sphincs_plus_c::PublicKey {
            pk_seed: sphincs_plus_c::PkSeed::new(pk_seed),
            root: sphincs_plus_c::Root::new(hypertree_root),
        },
    };
    ShrincsSigner::build_keys(seed, max, stateless)
}
