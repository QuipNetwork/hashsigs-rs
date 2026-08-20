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

// Round-trip the installed npm package. Run from a throwaway project OUTSIDE
// the repository, so the source tree cannot satisfy the import: this is the
// check `npm pack` alone does not do, and the reason a broken published
// package can otherwise pass every other gate.
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { shrincs } = await loadHashSigs();

const seed = new Uint8Array(32).fill(7);
const message = new Uint8Array(32).fill(3);

const keys = shrincs.keygen(seed, 4);
const signature = shrincs.sign(message, keys);
const ok = shrincs.verify(signature, message, keys.publicKeyCommitment);

if (!ok) {
  throw new Error("verify returned false for a freshly produced signature");
}
if (keys.stateful.remaining !== 3) {
  throw new Error(`expected 3 leaves remaining, got ${keys.stateful.remaining}`);
}

console.log("npm smoke OK");
