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

//! The `#[wasm_bindgen]` export layer, stamped out over one profile.
//!
//! [`wasm_profile_surface!`] emits the concrete exported functions and structs
//! that delegate to [`crate::wasm::core`]. It exists because
//! `#[wasm_bindgen]` cannot annotate a generic function: the export boundary
//! demands concrete monomorphic types, so a profile-generic surface has to be
//! monomorphized somewhere, and a macro is the way to do that without copying
//! the logic.
//!
//! The emitted names are fixed, not prefixed by profile, so the macro may be
//! invoked EXACTLY ONCE per crate. That is deliberate: one wasm binary carries
//! one profile. The npm package ships six binaries, one per subpath export, so
//! a browser consumer downloads only the profile it imports. Prefixing the
//! names to fit several profiles into one binary would force every consumer to
//! download all six, and the browser build inlines the wasm as base64, where
//! no bundler can tree-shake the unused ones out. A shipped profile binary is
//! 133-147 KB, or 178-196 KB base64.
//!
//! The doc comments below are load-bearing: `wasm-bindgen` copies them into the
//! generated `.d.ts`, so they are the published TypeScript documentation.

/// Emit the complete `#[wasm_bindgen]` surface for one profile.
///
/// `$profile` is the profile type; `$num_chains` and `$num_layers` are that
/// profile's `NUM_WOTS_CHAINS` and `NUM_HYPERTREE_LAYERS` as `usize` array
/// widths. Passing widths that disagree with the profile is a compile error at
/// the `core` call sites, which bound them against the same trait constants.
macro_rules! wasm_profile_surface {
    ($profile:ty, $num_chains:expr, $num_layers:expr) => {
        // Bound once as named consts: a const generic argument must be a path,
        // a literal, or a braced block, and a named const is the readable one.
        const PROFILE_NUM_CHAINS: usize = $num_chains;
        const PROFILE_NUM_LAYERS: usize = $num_layers;

        /// The SHRINCS profile this wasm build carries, such as
        /// `"shrincs-128s-q18-sha2"`. The npm package ships one binary per
        /// profile under its own subpath export, and every binary exports the
        /// same function names — so this is how a caller confirms it loaded
        /// the profile it meant to import. A signature made under one profile
        /// does not verify under another.
        #[wasm_bindgen(js_name = profileName)]
        pub fn profile_name() -> String {
            <$profile as $crate::profile::Profile>::PROFILE_NAME.to_string()
        }

        /// A generated SPHINCS+C keypair: `secretKey` is the 128-byte flat
        /// serialization; `publicKey` is `pkSeed ‖ hypertreeRoot` (64 bytes,
        /// the verifier-interface key shape `sphincsPlusCVerify` expects).
        #[derive(Debug)]
        #[wasm_bindgen]
        pub struct WasmSphincsPlusCKeys {
            signing_key: $crate::sphincs_plus_c::Key,
        }

        #[wasm_bindgen]
        impl WasmSphincsPlusCKeys {
            #[wasm_bindgen(getter, js_name = secretKey)]
            pub fn secret_key(&self) -> alloc::vec::Vec<u8> {
                self.signing_key.to_bytes().to_vec()
            }

            #[wasm_bindgen(getter, js_name = publicKey)]
            pub fn public_key(&self) -> alloc::vec::Vec<u8> {
                $crate::wasm::core::encode_sphincs_plus_c_public_key(&self.signing_key)
            }
        }

        /// Derive a SPHINCS+C keypair from a 32-byte seed. Deterministic — the
        /// same seed always yields the same key. The stateless sub-seeds use
        /// the SAME domain tags and KDF as `shrincsKeygen`'s stateless half,
        /// so a SPHINCS+C key derived from seed `S` shares its stateless
        /// material with the SHRINCS key derived from the same `S`.
        ///
        /// Divergence from `@noble/post-quantum`: `seed` is REQUIRED (exactly
        /// 32 bytes) — no RNG dependency is pulled into this wasm build, so
        /// there is no "generate a random seed for me" fallback.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with `code` `ERR_BAD_LENGTH` when `seed`
        /// is not exactly 32 bytes.
        #[wasm_bindgen(js_name = sphincsPlusCKeygen)]
        pub fn sphincs_plus_c_keygen(seed: &[u8]) -> Result<WasmSphincsPlusCKeys, JsValue> {
            let signing_key =
                $crate::wasm::core::sphincs_plus_c_keygen::<$profile, PROFILE_NUM_LAYERS>(seed)
                    .map_err($crate::wasm::js_error)?;
            Ok(WasmSphincsPlusCKeys { signing_key })
        }

        /// Sign a 32-byte `message` (typically a pre-computed hash) with a
        /// 128-byte SPHINCS+C `secretKey`. Stateless: never mutates
        /// `secretKey` and never fails except on malformed input. Returns the
        /// stateless signature envelope `sphincsPlusCVerify` accepts.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 128 bytes or `message`
        ///   is not 32 bytes
        /// - `ERR_SIGNING_FAILED` when FORS-C/hypertree grinding fails for the
        ///   supplied key and message
        #[wasm_bindgen(js_name = sphincsPlusCSign)]
        pub fn sphincs_plus_c_sign(
            message: &[u8],
            secret_key: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, JsValue> {
            $crate::wasm::core::sphincs_plus_c_sign::<$profile, PROFILE_NUM_LAYERS>(
                message, secret_key,
            )
            .map_err($crate::wasm::js_error)
        }

        /// Verify a SPHINCS+C stateless signature envelope over the 32-byte
        /// `message` (the pre-computed digest, used directly — not re-hashed;
        /// matching `sphincsPlusCSign`) against a 64-byte
        /// `pkSeed ‖ hypertreeRoot` public key. Never throws — a malformed
        /// envelope or wrong-length key is simply `false`, matching noble's
        /// plain boolean `verify`.
        #[wasm_bindgen(js_name = sphincsPlusCVerify)]
        pub fn sphincs_plus_c_verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
            $crate::wasm::core::sphincs_plus_c_verify::<$profile, PROFILE_NUM_CHAINS>(
                signature, message, public_key,
            )
        }

        /// A generated or imported SHRINCS keypair: `secretKey` is the
        /// 264-byte flat serialization (mutated IN PLACE by `shrincsSign`);
        /// `publicKey` is the 164-byte flat bundle; `publicKeyCommitment` is
        /// the 32-byte value `shrincsVerify` pins.
        #[derive(Debug)]
        #[wasm_bindgen]
        pub struct WasmShrincsKeys {
            signing_key: $crate::shrincs::Keys,
            public_key: $crate::shrincs::PublicKey,
        }

        #[wasm_bindgen]
        impl WasmShrincsKeys {
            #[wasm_bindgen(getter, js_name = secretKey)]
            pub fn secret_key(&self) -> alloc::vec::Vec<u8> {
                $crate::wasm::core::serialize_shrincs_signing_key(&self.signing_key)
            }

            #[wasm_bindgen(getter, js_name = publicKey)]
            pub fn public_key(&self) -> alloc::vec::Vec<u8> {
                $crate::wasm::core::encode_public_key_flat(&self.public_key)
            }

            #[wasm_bindgen(getter, js_name = publicKeyCommitment)]
            pub fn public_key_commitment(&self) -> alloc::vec::Vec<u8> {
                self.public_key.public_key_commitment.clone()
            }

            /// The 64-byte stateless public key (`pkSeed‖hypertreeRoot`) — the
            /// SPHINCS+C key `shrincsVerifyStateless` / `sphincsPlusCVerify`
            /// take. The stateless half of the hybrid key.
            #[wasm_bindgen(getter, js_name = statelessPublicKey)]
            pub fn stateless_public_key(&self) -> alloc::vec::Vec<u8> {
                $crate::wasm::core::encode_stateless_public_key(&self.public_key)
            }
        }

        /// Derive a SHRINCS keypair from a 32-byte seed and a stateful leaf
        /// budget (`maxSignatures`, `1..=4096`; out-of-range throws
        /// `ERR_INVALID_INPUT`). Deterministic — the same seed always yields
        /// the same key. Divergence from `@noble/post-quantum`: `seed` is
        /// REQUIRED (exactly 32 bytes; no RNG dependency is pulled into this
        /// wasm build) and `maxSignatures` has no scheme-level default — the
        /// TS `shrincs.keygen` wrapper supplies 1024 when the caller omits it.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `seed` is not exactly 32 bytes
        /// - `ERR_INVALID_INPUT` when `maxSignatures` is 0 or greater than 4096
        /// - `ERR_KEYGEN_FAILED` when key derivation fails for the supplied
        ///   inputs
        #[wasm_bindgen(js_name = shrincsKeygen)]
        pub fn shrincs_keygen(
            seed: &[u8],
            max_signatures: u32,
        ) -> Result<WasmShrincsKeys, JsValue> {
            let (signing_key, public_key) = $crate::wasm::core::shrincs_keygen::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(seed, max_signatures)
            .map_err($crate::wasm::js_error)?;
            Ok(WasmShrincsKeys {
                signing_key,
                public_key,
            })
        }

        /// Reconstruct a SHRINCS keypair from a previously persisted 264-byte
        /// `secretKey` (for example `keys.secretKey` after several
        /// `shrincsSign` calls). Recomputes both roots and the commitment from
        /// the seeds and rejects any mismatch with `ERR_IMPORT_INVALID` — the
        /// same validation `shrincsSign` performs on every call. Accepts the
        /// exhausted state (`nextStatefulLeafIndex == maxSignatures + 1`):
        /// stateful signing then throws `ERR_STATEFUL_LEAVES_EXHAUSTED`,
        /// stateless still works.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 264 bytes
        /// - `ERR_IMPORT_INVALID` when the counter is out of range or
        ///   recomputed roots do not match the seeds
        #[wasm_bindgen(js_name = shrincsImportSigningKey)]
        pub fn shrincs_import_signing_key(secret_key: &[u8]) -> Result<WasmShrincsKeys, JsValue> {
            let (signing_key, public_key) = $crate::wasm::core::import_secret_key::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(secret_key)
            .map_err($crate::wasm::js_error)?;
            Ok(WasmShrincsKeys {
                signing_key,
                public_key,
            })
        }

        /// Sign a 32-byte `message` (typically a pre-computed hash) with the
        /// next unused stateful leaf. STATEFUL: `secretKey` is re-validated
        /// and then MUTATED IN PLACE with the advanced leaf counter — the
        /// caller's `keys.secretKey` Uint8Array changes after this call.
        /// Throws `ERR_STATEFUL_LEAVES_EXHAUSTED` once every leaf is spent.
        /// Returns the commitment-path envelope
        /// (`PublicKey ‖ StatefulSignature`) `shrincsVerify` expects — the
        /// signature carries the full public key so a verifier holding only
        /// the 32-byte `publicKeyCommitment` can check it.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 264 bytes or `message`
        ///   is not 32 bytes
        /// - `ERR_IMPORT_INVALID` when the secret fails root/counter validation
        /// - `ERR_STATEFUL_LEAVES_EXHAUSTED` when no unused stateful leaf
        ///   remains
        /// - `ERR_SIGNING_FAILED` when WOTS-C grinding fails for the
        ///   leaf/message
        #[wasm_bindgen(js_name = shrincsSign)]
        pub fn shrincs_sign(
            message: &[u8],
            secret_key: &mut [u8],
        ) -> Result<alloc::vec::Vec<u8>, JsValue> {
            $crate::wasm::core::shrincs_sign::<$profile, PROFILE_NUM_CHAINS, PROFILE_NUM_LAYERS>(
                message, secret_key,
            )
            .map_err($crate::wasm::js_error)
        }

        /// Sign a 32-byte `message` (typically a pre-computed hash) via the
        /// stateless recovery path: consumes no leaf and never mutates
        /// `secretKey`, safe to repeat indefinitely.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 264 bytes or `message`
        ///   is not 32 bytes
        /// - `ERR_IMPORT_INVALID` when the secret fails root/counter validation
        /// - `ERR_SIGNING_FAILED` when FORS-C/hypertree grinding fails
        #[wasm_bindgen(js_name = shrincsSignStateless)]
        pub fn shrincs_sign_stateless(
            message: &[u8],
            secret_key: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, JsValue> {
            $crate::wasm::core::shrincs_sign_stateless::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(message, secret_key)
            .map_err($crate::wasm::js_error)
        }

        /// Verify a SHRINCS stateful signature (`shrincsSign`'s output, which
        /// carries the full public key) over the 32-byte `message` against a
        /// 32-byte `publicKeyCommitment` — the commitment-path shape: the
        /// verifier pins only the commitment, decodes the public key the
        /// envelope carries, checks it hashes to that commitment, then
        /// verifies. Never throws — a malformed signature, wrong-length
        /// commitment, or commitment mismatch is simply `false`.
        #[wasm_bindgen(js_name = shrincsVerify)]
        pub fn shrincs_verify(
            signature: &[u8],
            message: &[u8],
            public_key_commitment: &[u8],
        ) -> bool {
            $crate::wasm::core::shrincs_verify::<$profile, PROFILE_NUM_CHAINS>(
                signature,
                message,
                public_key_commitment,
            )
        }

        /// Verify a SHRINCS stateless signature (`shrincsSignStateless`'s
        /// output) over the 32-byte `message` against the 64-byte stateless
        /// public key (`pkSeed‖hypertreeRoot`, the `statelessPublicKey` a
        /// SHRINCS keypair exposes). A stateless SHRINCS signature is a
        /// SPHINCS+C signature, so this IS `sphincsPlusCVerify`. Never throws.
        #[wasm_bindgen(js_name = shrincsVerifyStateless)]
        pub fn shrincs_verify_stateless(
            signature: &[u8],
            message: &[u8],
            stateless_public_key: &[u8],
        ) -> bool {
            sphincs_plus_c_verify(signature, message, stateless_public_key)
        }

        /// Regenerate a fresh stateful chain for a 264-byte `secretKey`,
        /// discarding any relationship to prior stateful signatures (for
        /// example after suspected leaf reuse). `secretKey` is re-validated
        /// and then MUTATED IN PLACE with the new stateful seeds and a reset
        /// leaf counter — the caller's `keys.secretKey` Uint8Array changes
        /// after this call, and its `publicKeyCommitment` changes with it (the
        /// stateless half and `maxSignatures` are untouched). `newSeed` must
        /// be exactly 32 bytes of fresh entropy (matching `keygen`); this wasm
        /// build has no RNG, so the caller must supply it.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 264 bytes or `newSeed`
        ///   is not exactly 32 bytes
        /// - `ERR_IMPORT_INVALID` when the secret fails root/counter validation
        #[wasm_bindgen(js_name = shrincsReset)]
        pub fn shrincs_reset(secret_key: &mut [u8], new_seed: &[u8]) -> Result<(), JsValue> {
            $crate::wasm::core::shrincs_reset::<$profile, PROFILE_NUM_CHAINS, PROFILE_NUM_LAYERS>(
                secret_key, new_seed,
            )
            .map_err($crate::wasm::js_error)
        }

        /// Recompute the 32-byte `publicKeyCommitment` a 264-byte `secretKey`
        /// currently implies. `secretKey` is re-validated; never mutated.
        /// Equivalent to
        /// `shrincsImportSigningKey(secretKey).publicKeyCommitment` without
        /// constructing the intermediate `WasmShrincsKeys`.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with:
        /// - `ERR_BAD_LENGTH` when `secretKey` is not 264 bytes
        /// - `ERR_IMPORT_INVALID` when the secret fails root/counter validation
        #[wasm_bindgen(js_name = shrincsComputePublicKeyCommitment)]
        pub fn shrincs_compute_public_key_commitment(
            secret_key: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, JsValue> {
            $crate::wasm::core::shrincs_compute_public_key_commitment::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(secret_key)
            .map_err($crate::wasm::js_error)
        }

        /// Recover the 32-byte `publicKeyCommitment` a `shrincsSign` envelope
        /// implies, ecrecover-style: decode the envelope's carried public key
        /// and recompute the commitment from it. The envelope's own commitment
        /// field is never trusted — only the recomputed value is returned.
        /// Throws `ERR_ENVELOPE_MALFORMED` if `signature` is not a well-formed
        /// `shrincsSign` envelope.
        ///
        /// # Errors
        ///
        /// Returns a `JsValue` error with `code` `ERR_ENVELOPE_MALFORMED` when
        /// `signature` cannot be decoded as a stateful `shrincsSign` envelope.
        #[wasm_bindgen(js_name = shrincsRecoverPublicKeyCommitment)]
        pub fn shrincs_recover_public_key_commitment(
            signature: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, JsValue> {
            $crate::wasm::core::shrincs_recover_public_key_commitment::<$profile>(signature)
                .map_err($crate::wasm::js_error)
        }
    };
}

pub(crate) use wasm_profile_surface;
