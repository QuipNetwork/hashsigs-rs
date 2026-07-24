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

#![cfg_attr(not(feature = "wasm-bindings"), allow(dead_code, unused_imports))]

//! WASM-oriented surface for `hashsigs-rs`.
//!
//! This module exports a small noble-style API: flat `Uint8Array` free
//! functions (`sphincsPlusC{Keygen,Sign,Verify}`,
//! `shrincs{Keygen,Sign,SignStateless,Verify,VerifyStateless,
//! ImportSigningKey}`) plus `WasmShrincsAccount`, the stateful account
//! wrapper. The account exposes canonical message-hash methods
//! (`statefulActionMessageHash`, `statelessActionMessageHash`,
//! `statefulRotationMessageHash`, `fullRotationMessageHash`) that build the
//! exact message a caller must sign from the account's own state, so callers
//! never assemble that context by hand.

#[cfg(any(test, feature = "wasm-bindings"))]
use crate::verifier::VerifierInterface as _;
use crate::shrincs::{
    ActionContext as CoreActionContext, Keys, PublicKey, RotationContext as CoreRotationContext,
    ShrincsSigner, ShrincsVerifier, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES,
};
// The Uint8Array-native noble-style free functions (sphincsPlusC*/shrincs
// keygen/sign/verify) work directly with the independent SPHINCS+C layer and
// the shared scheme-hash, rather than going through the hex DTO plumbing
// above.
#[cfg(any(test, feature = "wasm-bindings"))]
#[cfg(any(test, feature = "wasm-bindings"))]
use crate::types::SphincsPlusCSigningKey;
#[cfg(any(test, feature = "wasm-bindings"))]
use zeroize::Zeroize;

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

// Machine-readable error codes surfaced to JS as `error.code`. Frozen API once
// published: additions are safe, renames/removals are breaking.
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_BAD_LENGTH: &str = "ERR_BAD_LENGTH";
#[cfg(feature = "wasm-bindings")]
const ERR_ONLY_OWNER: &str = "ERR_ONLY_OWNER";
#[cfg(feature = "wasm-bindings")]
const ERR_RECOVERY_POLICY_REQUIRED: &str = "ERR_RECOVERY_POLICY_REQUIRED";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_INDEX_ROLLBACK: &str = "ERR_STATEFUL_INDEX_ROLLBACK";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_POLICY_FROZEN: &str = "ERR_STATEFUL_POLICY_FROZEN";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_STATEFUL_LEAVES_EXHAUSTED: &str = "ERR_STATEFUL_LEAVES_EXHAUSTED";
#[cfg(feature = "wasm-bindings")]
const ERR_INVALID_SIGNATURE: &str = "ERR_INVALID_SIGNATURE";
#[cfg(feature = "wasm-bindings")]
const ERR_BUDGET_EXHAUSTED: &str = "ERR_BUDGET_EXHAUSTED";
#[cfg(feature = "wasm-bindings")]
const ERR_RECOVERY_NOT_ARMED: &str = "ERR_RECOVERY_NOT_ARMED";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_PATH_DISABLED: &str = "ERR_STATEFUL_PATH_DISABLED";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_LEAF_REJECTED: &str = "ERR_STATEFUL_LEAF_REJECTED";
#[cfg(feature = "wasm-bindings")]
const ERR_MALFORMED_SIGNATURE: &str = "ERR_MALFORMED_SIGNATURE";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_ENVELOPE_MALFORMED: &str = "ERR_ENVELOPE_MALFORMED";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_SIGNING_FAILED: &str = "ERR_SIGNING_FAILED";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_KEYGEN_FAILED: &str = "ERR_KEYGEN_FAILED";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_INVALID_INPUT: &str = "ERR_INVALID_INPUT";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_IMPORT_INVALID: &str = "ERR_IMPORT_INVALID";
#[cfg(any(test, feature = "wasm-bindings"))]
const MAX_RAW_INPUT_BYTES: usize = 1 << 20;
#[cfg(any(test, feature = "wasm-bindings"))]
const MAX_STATEFUL_SIGNATURES_LIMIT: usize = 4096;

/// Error carrier for the wasm boundary: a stable machine-readable `code` plus
/// a human-readable `message`. Messages must never echo raw caller input
/// (seeds and other secrets would leak into logs/telemetry).
#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(Debug)]
struct WasmErr {
    code: &'static str,
    message: String,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(typescript_custom_section)]
const TS_ERROR_CODES: &str = r#"
export type ShrincsErrorCode =
  | "ERR_BAD_LENGTH" | "ERR_ONLY_OWNER"
  | "ERR_RECOVERY_POLICY_REQUIRED" | "ERR_STATEFUL_INDEX_ROLLBACK"
  | "ERR_STATEFUL_POLICY_FROZEN" | "ERR_STATEFUL_LEAVES_EXHAUSTED"
  | "ERR_SIGNING_FAILED" | "ERR_KEYGEN_FAILED" | "ERR_INVALID_INPUT"
  | "ERR_IMPORT_INVALID"
  | "ERR_INVALID_SIGNATURE" | "ERR_BUDGET_EXHAUSTED"
  | "ERR_RECOVERY_NOT_ARMED" | "ERR_STATEFUL_PATH_DISABLED"
  | "ERR_STATEFUL_LEAF_REJECTED" | "ERR_MALFORMED_SIGNATURE"
  | "ERR_ENVELOPE_MALFORMED";
"#;

#[cfg(feature = "wasm-bindings")]
/// Reference SHRINCS account verifier mirroring the on-chain state machine
/// (nonce, key epochs, stateful policy, recovery mode). Malformed input THROWS
/// an `Error` with a `ShrincsErrorCode` on `error.code` (policy violations
/// throw e.g. `ERR_ONLY_OWNER`); cryptographic verification failures return
/// `false`. Call `free()` when done — using a handle after `free()` throws.
#[wasm_bindgen]
pub struct WasmShrincsAccount {
    inner: crate::account::ShrincsAccountVerifierExample,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmShrincsAccount {
    /// Create an account bound to an owner, chain, and contract address, with
    /// the initial public-key commitment installed.
    ///
    /// * `owner` - 32 bytes (bytes32).
    /// * `chain_id` - 32 bytes (bytes32).
    /// * `contract_address` - **20 bytes** (EVM address — NOT bytes32).
    /// * `initial_public_key_commitment` - 32 bytes (bytes32).
    #[wasm_bindgen(constructor)]
    pub fn new(
        owner: &[u8],
        chain_id: &[u8],
        contract_address: &[u8],
        initial_public_key_commitment: &[u8],
    ) -> Result<WasmShrincsAccount, JsValue> {
        let owner = bytes_word32(owner).map_err(js_error)?;
        let chain_id = bytes_word32(chain_id).map_err(js_error)?;
        let contract_address = bytes_fixed::<20>(contract_address).map_err(js_error)?;
        let initial_public_key_commitment =
            bytes_word32(initial_public_key_commitment).map_err(js_error)?;
        Ok(Self {
            inner: crate::account::ShrincsAccountVerifierExample::new(
                owner,
                chain_id,
                contract_address,
                initial_public_key_commitment,
            ),
        })
    }

    /// Read-only snapshot of the account state (all fields public).
    #[wasm_bindgen(js_name = snapshot, unchecked_return_type = "ShrincsAccountSnapshot")]
    pub fn snapshot(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&account_snapshot_dto(&self.inner))
    }

    /// The message a `verifyStatefulAction` signature must cover for the
    /// given `actionType`/`payloadHash`, built from the account's own domain
    /// separator, nonce, and key version — the exact value
    /// `verifyStatefulAction` recomputes internally to check the signature.
    /// Sign the returned bytes with `shrincs.sign()` and pass the result to
    /// `verifyStatefulAction`.
    ///
    /// * `action_type` - 32 bytes (bytes32).
    /// * `payload_hash` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = statefulActionMessageHash)]
    pub fn stateful_action_message_hash(
        &self,
        action_type: &[u8],
        payload_hash: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, JsValue> {
        let action_type = bytes_word32(action_type).map_err(js_error)?;
        let payload_hash = bytes_word32(payload_hash).map_err(js_error)?;
        let context = CoreActionContext {
            domain_separator: self.inner.domainSeparator(),
            nonce: self.inner.nonce(),
            key_version: self.inner.keyVersion(),
            action_type,
            payload_hash,
        };
        Ok(ShrincsVerifier::new()
            .stateful_action_message_hash(self.inner.currentShrincsPublicKey(), &context)
            .to_vec())
    }

    /// The message a `verifyStatelessAction` signature must cover for the
    /// given `actionType`/`payloadHash`, built from the account's own state.
    /// Sign the returned bytes with `shrincs.signStateless()` and pass the
    /// result to `verifyStatelessAction`.
    ///
    /// * `action_type` - 32 bytes (bytes32).
    /// * `payload_hash` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = statelessActionMessageHash)]
    pub fn stateless_action_message_hash(
        &self,
        action_type: &[u8],
        payload_hash: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, JsValue> {
        let action_type = bytes_word32(action_type).map_err(js_error)?;
        let payload_hash = bytes_word32(payload_hash).map_err(js_error)?;
        let context = CoreActionContext {
            domain_separator: self.inner.domainSeparator(),
            nonce: self.inner.nonce(),
            key_version: self.inner.keyVersion(),
            action_type,
            payload_hash,
        };
        Ok(ShrincsVerifier::new()
            .stateless_action_message_hash(self.inner.currentShrincsPublicKey(), &context)
            .to_vec())
    }

    /// The message a `rotateToFreshKey` recovery signature must cover, built
    /// from the account's own state and the replacement keypair's public
    /// key. Sign the returned bytes with `shrincs.signStateless()` and pass
    /// the result to `rotateToFreshKey` alongside the same `next_public_key`.
    ///
    /// * `next_public_key` - the replacement keypair's 164-byte flat
    ///   `publicKey` (as returned by `shrincs.keygen()`); only its leading
    ///   statefulPublicKey(68) and commitment(32) are used.
    #[wasm_bindgen(js_name = statefulRotationMessageHash)]
    pub fn stateful_rotation_message_hash(
        &self,
        next_public_key: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, JsValue> {
        let next_key = stateful_rotation_target_from_public_key(next_public_key).map_err(js_error)?;
        let context = CoreRotationContext {
            domain_separator: self.inner.domainSeparator(),
            nonce: self.inner.nonce(),
            key_version: self.inner.keyVersion(),
        };
        let current_public_key = current_public_key_stub(&self.inner);
        Ok(ShrincsVerifier::new()
            .stateful_rotation_message_hash(
                self.inner.currentShrincsPublicKey(),
                &current_public_key,
                &context,
                &next_key,
            )
            .to_vec())
    }

    /// The message a `rotateFullKey` recovery signature must cover, built
    /// from the account's own state and the replacement keypair's public
    /// key. Sign the returned bytes with `shrincs.signStateless()` and pass
    /// the result to `rotateFullKey` alongside the same `next_public_key`.
    ///
    /// * `next_public_key` - the replacement keypair's 164-byte flat
    ///   `publicKey` (as returned by `shrincs.keygen()`).
    #[wasm_bindgen(js_name = fullRotationMessageHash)]
    pub fn full_rotation_message_hash(
        &self,
        next_public_key: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, JsValue> {
        let next_key = rotation_target_from_public_key(next_public_key).map_err(js_error)?;
        let context = CoreRotationContext {
            domain_separator: self.inner.domainSeparator(),
            nonce: self.inner.nonce(),
            key_version: self.inner.keyVersion(),
        };
        let current_public_key = current_public_key_stub(&self.inner);
        Ok(ShrincsVerifier::new()
            .full_rotation_message_hash(
                self.inner.currentShrincsPublicKey(),
                &current_public_key,
                &context,
                &next_key,
            )
            .to_vec())
    }

    /// Verify a stateful action signature against the account's canonical
    /// action hash and enforce the stateful policy. Resolves on success and
    /// advances account state; THROWS a typed `ShrincsErrorCode` on malformed
    /// input OR on rejection — e.g. `ERR_INVALID_SIGNATURE` for a bad
    /// signature, `ERR_STATEFUL_LEAF_REJECTED` / `ERR_STATEFUL_PATH_DISABLED`
    /// for a policy-blocked leaf.
    ///
    /// * `public_key` - the signer's 164-byte flat `publicKey`; the account
    ///   binds it to its stored commitment.
    /// * `action_type` - 32 bytes (bytes32).
    /// * `payload_hash` - 32 bytes (bytes32).
    /// * `signature` - the signature `shrincs.sign()` returns, over
    ///   `statefulActionMessageHash(actionType, payloadHash)`.
    #[wasm_bindgen(js_name = verifyStatefulAction)]
    pub fn verify_stateful_action(
        &mut self,
        public_key: &[u8],
        action_type: &[u8],
        payload_hash: &[u8],
        signature: &[u8],
    ) -> Result<(), JsValue> {
        // Take the signer's publicKey (bound to the account's commitment by the
        // core verifier) and the plain signature `shrincs.sign()` returns.
        let public_key = public_key_from_flat(public_key).map_err(js_error)?;
        let signature = crate::envelope::decode_stateful_signature_envelope(signature)
            .ok_or_else(malformed_envelope)?;
        let action_type = bytes_word32(action_type).map_err(js_error)?;
        let payload_hash = bytes_word32(payload_hash).map_err(js_error)?;
        self.inner
            .verifyStatefulAction(&public_key, action_type, payload_hash, &signature)
            .map_err(account_error_to_js)
    }

    /// Verify a stateless action signature against the account's canonical
    /// action hash and the per-key stateless budget. Resolves on success and
    /// advances account state; THROWS a typed `ShrincsErrorCode` on malformed
    /// input OR on rejection — e.g. `ERR_INVALID_SIGNATURE`,
    /// `ERR_BUDGET_EXHAUSTED`, `ERR_RECOVERY_NOT_ARMED`.
    ///
    /// * `action_type` - 32 bytes (bytes32).
    /// * `payload_hash` - 32 bytes (bytes32).
    /// * `signature` - the signature `shrincs.signStateless()` returns, over
    ///   `statelessActionMessageHash(actionType, payloadHash)`.
    #[wasm_bindgen(js_name = verifyStatelessAction)]
    pub fn verify_stateless_action(
        &mut self,
        public_key: &[u8],
        action_type: &[u8],
        payload_hash: &[u8],
        signature: &[u8],
    ) -> Result<(), JsValue> {
        // A stateless action signature is a SPHINCS+C signature. Take the
        // signer's 164-byte publicKey (bound to the account's commitment by the
        // core verifier) and the plain signature `shrincs.signStateless()`
        // returns; verification bottoms out in the SPHINCS+C verify.
        let public_key = public_key_from_flat(public_key).map_err(js_error)?;
        let signature = crate::envelope::decode_stateless_signature_envelope(signature)
            .ok_or_else(malformed_envelope)?;
        let action_type = bytes_word32(action_type).map_err(js_error)?;
        let payload_hash = bytes_word32(payload_hash).map_err(js_error)?;
        self.inner
            .verifyStatelessAction(&public_key, action_type, payload_hash, &signature)
            .map_err(account_error_to_js)
    }

    /// Rotate to a fresh stateful key (stateless part retained), authorized by
    /// a stateless recovery signature. Resolves on success; THROWS a typed
    /// `ShrincsErrorCode` on malformed input OR on rejection — e.g.
    /// `ERR_INVALID_SIGNATURE`, `ERR_RECOVERY_POLICY_REQUIRED`,
    /// `ERR_RECOVERY_NOT_ARMED`, `ERR_BUDGET_EXHAUSTED`.
    ///
    /// * `recovery_signature` - the signature `shrincs.signStateless()`
    ///   returns, over `statefulRotationMessageHash(next_public_key)`; it
    ///   carries the current public key that authorizes the rotation.
    /// * `next_public_key` - the replacement keypair's 164-byte flat
    ///   `publicKey`; the stateful rotation target is its leading
    ///   statefulPublicKey(68) and commitment(32).
    #[wasm_bindgen(js_name = rotateToFreshKey)]
    pub fn rotate_to_fresh_key(
        &mut self,
        current_public_key: &[u8],
        recovery_signature: &[u8],
        next_public_key: &[u8],
    ) -> Result<(), JsValue> {
        let current_public_key = public_key_from_flat(current_public_key).map_err(js_error)?;
        let recovery_signature =
            crate::envelope::decode_stateless_signature_envelope(recovery_signature)
                .ok_or_else(malformed_envelope)?;
        let next_key = stateful_rotation_target_from_public_key(next_public_key).map_err(js_error)?;
        self.inner
            .rotateToFreshKey(&current_public_key, &recovery_signature, &next_key)
            .map_err(account_error_to_js)
    }

    /// Rotate the full hybrid key bundle, authorized by a stateless recovery
    /// signature. Resolves on success; THROWS a typed `ShrincsErrorCode` on
    /// malformed input OR on rejection — e.g. `ERR_INVALID_SIGNATURE`,
    /// `ERR_RECOVERY_POLICY_REQUIRED`, `ERR_RECOVERY_NOT_ARMED`,
    /// `ERR_BUDGET_EXHAUSTED`.
    ///
    /// * `recovery_signature` - the signature `shrincs.signStateless()`
    ///   returns, over `fullRotationMessageHash(next_public_key)`; it carries
    ///   the current public key that authorizes the rotation.
    /// * `next_public_key` - the replacement keypair's 164-byte flat
    ///   `publicKey`, which is exactly a RotationTarget
    ///   (statefulPublicKey(68)‖commitment(32)‖pkSeed(32)‖hypertreeRoot(32)).
    #[wasm_bindgen(js_name = rotateFullKey)]
    pub fn rotate_full_key(
        &mut self,
        current_public_key: &[u8],
        recovery_signature: &[u8],
        next_public_key: &[u8],
    ) -> Result<(), JsValue> {
        let current_public_key = public_key_from_flat(current_public_key).map_err(js_error)?;
        let recovery_signature =
            crate::envelope::decode_stateless_signature_envelope(recovery_signature)
                .ok_or_else(malformed_envelope)?;
        let next_key = rotation_target_from_public_key(next_public_key).map_err(js_error)?;
        self.inner
            .rotateFullKey(&current_public_key, &recovery_signature, &next_key)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the monotonic-index stateful policy starting at
    /// `initialLeafIndex`. Throws `ERR_ONLY_OWNER` for any other caller and
    /// `ERR_STATEFUL_POLICY_FROZEN` after the first stateful use in an epoch.
    ///
    /// * `caller` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyMonotonicIndex)]
    pub fn set_stateful_policy_monotonic_index(
        &mut self,
        caller: &[u8],
        initial_leaf_index: u32,
    ) -> Result<(), JsValue> {
        let caller = bytes_word32(caller).map_err(js_error)?;
        self.inner
            .setStatefulPolicyMonotonicIndex(caller, initial_leaf_index)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the recovery-rotation stateful policy. Throws
    /// `ERR_ONLY_OWNER` / `ERR_STATEFUL_POLICY_FROZEN` like the other setters.
    ///
    /// * `caller` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyRecoveryRotation)]
    pub fn set_stateful_policy_recovery_rotation(
        &mut self,
        caller: &[u8],
    ) -> Result<(), JsValue> {
        let caller = bytes_word32(caller).map_err(js_error)?;
        self.inner
            .setStatefulPolicyRecoveryRotation(caller)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the leaf-bitmap stateful policy (caller-selected
    /// leaves, tracked via an on-chain used-leaf bitmap). Throws
    /// `ERR_ONLY_OWNER` / `ERR_STATEFUL_POLICY_FROZEN` like the other
    /// setters.
    ///
    /// * `caller` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyLeafBitmap)]
    pub fn set_stateful_policy_leaf_bitmap(&mut self, caller: &[u8]) -> Result<(), JsValue> {
        let caller = bytes_word32(caller).map_err(js_error)?;
        self.inner
            .setStatefulPolicyLeafBitmap(caller)
            .map_err(account_error_to_js)
    }

    /// Owner-only: enter recovery mode. Requires an active recovery-capable
    /// policy — throws `ERR_RECOVERY_POLICY_REQUIRED` otherwise.
    ///
    /// * `caller` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = enterRecoveryMode)]
    pub fn enter_recovery_mode(&mut self, caller: &[u8]) -> Result<(), JsValue> {
        let caller = bytes_word32(caller).map_err(js_error)?;
        self.inner
            .enterRecoveryMode(caller)
            .map_err(account_error_to_js)
    }

    /// ERC-1271 compatibility view: verify a mode-prefixed action signature
    /// against the account's current state WITHOUT mutating it (no leaf
    /// commit, no nonce advance, no stateless-budget consumption). Resolves
    /// on success; THROWS a typed `ShrincsErrorCode` on rejection —
    /// `ERR_MALFORMED_SIGNATURE` for an empty/unrecognized/malformed
    /// signature bytes, `ERR_INVALID_SIGNATURE` for a well-formed but invalid
    /// or mismatched-hash signature, plus the same policy codes as
    /// `verifyStatefulAction` / `verifyStatelessAction`.
    ///
    /// * `hash` - 32 bytes (bytes32); the hash the signature must authorize.
    /// * `signature` - the mode-prefixed ERC-1271 signature bytes, arbitrary
    ///   length.
    #[wasm_bindgen(js_name = isValidSignature)]
    pub fn is_valid_signature(
        &self,
        hash: &[u8],
        signature: &[u8],
    ) -> Result<(), JsValue> {
        require_max_len(signature, MAX_RAW_INPUT_BYTES).map_err(js_error)?;
        let hash = bytes_word32(hash).map_err(js_error)?;
        self.inner
            .isValidSignature(hash, signature)
            .map_err(account_error_to_js)
    }
}

/// The version of this wasm build, frozen in at compile time from the crate
/// version (`Cargo.toml`). The npm `package.json` version is synced to the
/// same value at build/publish, so for consumers this is simply "the package
/// version, queryable from the running module". Useful for asserting that a
/// vendored or separately-served `.wasm` matches the JS that loaded it.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ── Noble-style Uint8Array API ──────────────────────────────────────────
//
// `sphincsPlusC{Keygen,Sign,Verify}` and `shrincs{Keygen,Sign,SignStateless,
// Verify,VerifyStateless}` are free functions operating on flat byte
// buffers only (no hex strings, no nested DTOs): `keygen` returns a struct
// of Uint8Array getters, `sign`/`verify` take and return Uint8Array
// directly — mirroring the @noble/post-quantum surface shape.
//
// Every sign/verify pair below hashes the caller's arbitrary-length
// the 32-byte `message` directly (the message IS the hash) —
// the ONE message-hashing choice shared across this whole section, so
// `verify(sign(m, keys), m, pk)` round-trips regardless of which function
// produced the signature.

/// 32-byte fixed-width field, byte version of `parse_word32`.
#[cfg(any(test, feature = "wasm-bindings"))]
fn bytes_word32(input: &[u8]) -> Result<[u8; HASH_LEN], WasmErr> {
    bytes_fixed::<HASH_LEN>(input)
}

/// Byte version of `parse_fixed_hex`: exact-length check, no hex decoding.
#[cfg(any(test, feature = "wasm-bindings"))]
fn bytes_fixed<const N: usize>(input: &[u8]) -> Result<[u8; N], WasmErr> {
    if input.len() != N {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("expected {N} bytes for fixed-width field, got {}", input.len()),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(input);
    Ok(out)
}

/// Byte version of `parse_hex_bytes_with_max`'s length ceiling; the input is
/// already raw bytes, so there is nothing to decode.
#[cfg(any(test, feature = "wasm-bindings"))]
fn require_max_len(input: &[u8], max_bytes: usize) -> Result<(), WasmErr> {
    if input.len() > max_bytes {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("input exceeds maximum of {max_bytes} bytes"),
        });
    }
    Ok(())
}

/// The 32-byte message every noble-style sign/verify free function operates
/// on. The message IS the hash: callers pre-hash arbitrary-length data and
/// pass the 32-byte digest, matching the on-chain / envelope verifier, which
/// treats its `hash` argument as the signed message. A wrong length is an
/// error (for signing) or a rejected verify.
#[cfg(any(test, feature = "wasm-bindings"))]
fn message_hash(message: &[u8]) -> Result<[u8; HASH_LEN], WasmErr> {
    bytes_word32(message).map_err(|_| WasmErr {
        code: ERR_BAD_LENGTH,
        message: format!("message must be exactly 32 bytes, got {}", message.len()),
    })
}

/// SPHINCS+C secret key: `statelessSkSeed(32) ‖ statelessPrfSeed(32) ‖
/// pkSeed(32) ‖ hypertreeRoot(32)`, 128 bytes total (the field order of
/// `SphincsPlusCSigningKey`).
#[cfg(any(test, feature = "wasm-bindings"))]
fn serialize_sphincs_plus_c_signing_key(key: &SphincsPlusCSigningKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(128);
    out.extend_from_slice(&key.stateless_sk_seed);
    out.extend_from_slice(&key.stateless_prf_seed);
    out.extend_from_slice(&key.pk_seed);
    out.extend_from_slice(&key.hypertree_root);
    out
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn deserialize_sphincs_plus_c_signing_key(
    bytes: &[u8],
) -> Result<SphincsPlusCSigningKey, WasmErr> {
    if bytes.len() != 128 {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("SPHINCS+C secretKey must be 128 bytes, got {}", bytes.len()),
        });
    }
    Ok(SphincsPlusCSigningKey {
        stateless_sk_seed: bytes_word32(&bytes[0..32])?,
        stateless_prf_seed: bytes_word32(&bytes[32..64])?,
        pk_seed: bytes_word32(&bytes[64..96])?,
        hypertree_root: bytes_word32(&bytes[96..128])?,
    })
}

/// A generated SPHINCS+C keypair: `secretKey` is the 128-byte flat
/// serialization above; `publicKey` is `pkSeed ‖ hypertreeRoot` (64 bytes,
/// the verifier-interface key shape `sphincsPlusCVerify` expects).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub struct WasmSphincsPlusCKeys {
    signing_key: SphincsPlusCSigningKey,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmSphincsPlusCKeys {
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> alloc::vec::Vec<u8> {
        serialize_sphincs_plus_c_signing_key(&self.signing_key)
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(64);
        out.extend_from_slice(&self.signing_key.pk_seed);
        out.extend_from_slice(&self.signing_key.hypertree_root);
        out
    }
}

/// Derive a SPHINCS+C keypair from a 32-byte seed. Deterministic — the same
/// seed always yields the same key. The stateless sub-seeds use the SAME
/// domain tags and KDF as `ShrincsSigner::keygen`'s stateless half
/// (`derive32(domain, seed, &[])`), so a SPHINCS+C key derived from seed `S`
/// shares its stateless material with the SHRINCS key derived from the same
/// `S` — a deliberate coupling; see the wasm-noble delivery report.
///
/// Divergence from `@noble/post-quantum`: `seed` is REQUIRED (exactly 32
/// bytes) — no RNG dependency is pulled into this wasm build, so there is no
/// "generate a random seed for me" fallback.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = sphincsPlusCKeygen)]
pub fn sphincs_plus_c_keygen(seed: &[u8]) -> Result<WasmSphincsPlusCKeys, JsValue> {
    let mut seed = bytes_fixed::<32>(seed).map_err(js_error)?;
    let stateless_sk_seed = crate::shrincs::derive32(b"shrincs-stateless-sk-seed", &seed, &[]);
    let stateless_prf_seed = crate::shrincs::derive32(b"shrincs-stateless-prf-seed", &seed, &[]);
    let pk_seed = crate::shrincs::derive32(b"shrincs-pk-seed", &seed, &[]);
    seed.zeroize();
    let signing_key = crate::sphincs_plus_c::keygen(stateless_sk_seed, stateless_prf_seed, pk_seed)
        .to_legacy_signing_key();
    Ok(WasmSphincsPlusCKeys { signing_key })
}

/// Sign a 32-byte `message` (typically a pre-computed hash) with a
/// 128-byte SPHINCS+C `secretKey`. Stateless: never mutates `secretKey` and
/// never fails except on malformed input. Returns the stateless signature
/// envelope `sphincsPlusCVerify` accepts.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = sphincsPlusCSign)]
pub fn sphincs_plus_c_sign(
    message: &[u8],
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let signing_key = deserialize_sphincs_plus_c_signing_key(secret_key).map_err(js_error)?;
    let full_key = crate::sphincs_plus_c::key::Key::from_legacy_signing_key(&signing_key);
    let hash = message_hash(message).map_err(js_error)?;
    let signature = crate::sphincs_plus_c::sign(&full_key, &hash).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_SIGNING_FAILED,
            message: "stateless signing failed for the supplied key/message".into(),
        })
    })?;
    Ok(crate::envelope::encode_stateless_signature_envelope(&signature))
}

/// Verify a SPHINCS+C stateless signature envelope over `message` (hashed
/// with keccak256, matching `sphincsPlusCSign`) against a 64-byte
/// `pkSeed ‖ hypertreeRoot` public key. Never throws — a malformed envelope
/// or wrong-length key is simply `false`, matching noble's plain boolean
/// `verify`.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = sphincsPlusCVerify)]
pub fn sphincs_plus_c_verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    crate::sphincs_plus_c::verifier::SphincsPlusCVerifier::new()
        .verify_envelope(public_key, &hash, signature)
        == crate::verifier::VerifyOutcome::Valid
}

/// SHRINCS secret key: `statefulSkSeed(32) ‖ statefulPrfSeed(32) ‖
/// statefulPkSeed(32) ‖ statefulRoot(32) ‖ maxStatefulSignatures(u32 BE) ‖
/// nextStatefulLeafIndex(u32 BE) ‖ statelessSkSeed(32) ‖ statelessPrfSeed(32)
/// ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 264 bytes total — `Keys::to_bytes`'s
/// flat layout (`stateful(136) ‖ stateless(128)`), the same field order the
/// legacy `ShrincsSigningKey` used.
#[cfg(any(test, feature = "wasm-bindings"))]
fn serialize_shrincs_signing_key(key: &Keys) -> alloc::vec::Vec<u8> {
    key.to_bytes().to_vec()
}

/// Deserialize the flat layout above WITHOUT validating the roots — callers
/// MUST run the result through `ShrincsSigner::import_signing_key` before
/// trusting it (this only checks the length and slices the fields).
#[cfg(any(test, feature = "wasm-bindings"))]
fn deserialize_shrincs_signing_key(bytes: &[u8]) -> Result<Keys, WasmErr> {
    Keys::from_bytes(bytes).ok_or_else(|| WasmErr {
        code: ERR_BAD_LENGTH,
        message: format!("shrincs secretKey must be 264 bytes, got {}", bytes.len()),
    })
}

/// Flat concatenation of every `PublicKey` field: `statefulPublicKey(68) ‖
/// publicKeyCommitment(32) ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 164 bytes.
/// Not ABI-encoded (unlike `envelope::encode_*`) — a plain fixed-layout byte
/// bundle for the noble-style keygen/import return value.
#[cfg(any(test, feature = "wasm-bindings"))]
fn encode_public_key_flat(public_key: &PublicKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(STATEFUL_PUBLIC_KEY_BYTES + HASH_LEN * 3);
    out.extend_from_slice(&public_key.stateful_public_key);
    out.extend_from_slice(&public_key.public_key_commitment);
    out.extend_from_slice(&public_key.pk_seed);
    out.extend_from_slice(&public_key.hypertree_root);
    out
}


/// Build the `malformed envelope` error the account envelope-decode paths
/// raise when ABI framing cannot be decoded.
#[cfg(feature = "wasm-bindings")]
fn malformed_envelope() -> JsValue {
    js_error(WasmErr {
        code: ERR_ENVELOPE_MALFORMED,
        message: "signature envelope could not be decoded".into(),
    })
}

/// A `PublicKey` carrying only the account's installed `publicKeyCommitment`
/// (the other fields are empty). The rotation message-hash formulas only
/// read `.public_key_commitment` off their `current_public_key` argument
/// (see `shrincs::messages`), so this stub is exactly as much "current
/// public key" as those formulas need — the account itself only stores the
/// commitment, not the full key.
#[cfg(feature = "wasm-bindings")]
fn current_public_key_stub(account: &crate::account::ShrincsAccountVerifierExample) -> PublicKey {
    PublicKey {
        stateful_public_key: alloc::vec::Vec::new(),
        public_key_commitment: account.currentShrincsPublicKey().to_vec(),
        pk_seed: alloc::vec::Vec::new(),
        hypertree_root: alloc::vec::Vec::new(),
    }
}

/// Slice a 164-byte flat publicKey into a `StatefulRotationTarget`
/// (statefulPublicKey(68) then commitment(32); the trailing stateless seed and
/// root are unused for a stateful-only rotation). Mirrors `encode_public_key_flat`.
#[cfg(feature = "wasm-bindings")]
fn stateful_rotation_target_from_public_key(
    bytes: &[u8],
) -> Result<crate::types::StatefulRotationTarget, WasmErr> {
    require_public_key_len(bytes)?;
    Ok(crate::types::StatefulRotationTarget {
        stateful_public_key: bytes[0..STATEFUL_PUBLIC_KEY_BYTES].to_vec(),
        public_key_commitment: bytes[STATEFUL_PUBLIC_KEY_BYTES..STATEFUL_PUBLIC_KEY_BYTES + 32]
            .to_vec(),
    })
}

/// Slice a 164-byte flat publicKey into a full `RotationTarget`
/// (statefulPublicKey(68)‖commitment(32)‖pkSeed(32)‖hypertreeRoot(32)) — the
/// exact `encode_public_key_flat` layout.
/// Decode a 164-byte flat publicKey into the core `PublicKey`
/// (statefulPublicKey(68)‖commitment(32)‖pkSeed(32)‖hypertreeRoot(32)).
#[cfg(feature = "wasm-bindings")]
fn public_key_from_flat(bytes: &[u8]) -> Result<PublicKey, WasmErr> {
    require_public_key_len(bytes)?;
    let c = STATEFUL_PUBLIC_KEY_BYTES;
    Ok(PublicKey {
        stateful_public_key: bytes[0..c].to_vec(),
        public_key_commitment: bytes[c..c + 32].to_vec(),
        pk_seed: bytes[c + 32..c + 64].to_vec(),
        hypertree_root: bytes[c + 64..c + 96].to_vec(),
    })
}

#[cfg(feature = "wasm-bindings")]
fn rotation_target_from_public_key(bytes: &[u8]) -> Result<crate::types::RotationTarget, WasmErr> {
    require_public_key_len(bytes)?;
    let c = STATEFUL_PUBLIC_KEY_BYTES;
    Ok(crate::types::RotationTarget {
        stateful_public_key: bytes[0..c].to_vec(),
        public_key_commitment: bytes[c..c + 32].to_vec(),
        pk_seed: bytes[c + 32..c + 64].to_vec(),
        hypertree_root: bytes[c + 64..c + 96].to_vec(),
    })
}

#[cfg(feature = "wasm-bindings")]
fn require_public_key_len(bytes: &[u8]) -> Result<(), WasmErr> {
    let want = STATEFUL_PUBLIC_KEY_BYTES + 96;
    if bytes.len() != want {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("publicKey must be {want} bytes, got {}", bytes.len()),
        });
    }
    Ok(())
}

/// A generated or imported SHRINCS keypair: `secretKey` is the 264-byte flat
/// serialization above (mutated IN PLACE by `shrincsSign`); `publicKey` is
/// the 164-byte flat bundle above; `publicKeyCommitment` is the 32-byte
/// value `shrincsVerify` / `shrincsVerifyStateless` pin.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub struct WasmShrincsKeys {
    signing_key: Keys,
    public_key: PublicKey,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmShrincsKeys {
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> alloc::vec::Vec<u8> {
        serialize_shrincs_signing_key(&self.signing_key)
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> alloc::vec::Vec<u8> {
        encode_public_key_flat(&self.public_key)
    }

    #[wasm_bindgen(getter, js_name = publicKeyCommitment)]
    pub fn public_key_commitment(&self) -> alloc::vec::Vec<u8> {
        self.public_key.public_key_commitment.clone()
    }

    /// The 64-byte stateless public key (`pkSeed‖hypertreeRoot`) — the SPHINCS+C
    /// key `shrincsVerifyStateless` / `sphincsPlusCVerify` take. The stateless
    /// half of the hybrid key.
    #[wasm_bindgen(getter, js_name = statelessPublicKey)]
    pub fn stateless_public_key(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(64);
        out.extend_from_slice(&self.public_key.pk_seed);
        out.extend_from_slice(&self.public_key.hypertree_root);
        out
    }
}

/// Derive a SHRINCS keypair from a 32-byte seed and a stateful leaf budget
/// (`maxSignatures`, `1..=4096`; out-of-range throws `ERR_INVALID_INPUT`).
/// Deterministic — the same seed always yields the same key. Divergence from
/// `@noble/post-quantum`: `seed` is REQUIRED (exactly 32 bytes; no RNG
/// dependency is pulled into this wasm build) and `maxSignatures` has no
/// scheme-level default — the TS `shrincs.keygen` wrapper supplies 1024 when
/// the caller omits it.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsKeygen)]
pub fn shrincs_keygen(seed: &[u8], max_signatures: u32) -> Result<WasmShrincsKeys, JsValue> {
    let mut seed = bytes_fixed::<32>(seed).map_err(js_error)?;
    if max_signatures == 0 || max_signatures > MAX_STATEFUL_SIGNATURES_LIMIT as u32 {
        return Err(js_error(WasmErr {
            code: ERR_INVALID_INPUT,
            message: format!("maxSignatures must be in 1..={MAX_STATEFUL_SIGNATURES_LIMIT}"),
        }));
    }
    let result = ShrincsSigner::keygen(&seed, max_signatures);
    seed.zeroize();
    let (signing_key, public_key) = result.ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_KEYGEN_FAILED,
            message: "key generation failed for the supplied inputs".into(),
        })
    })?;
    Ok(WasmShrincsKeys { signing_key, public_key })
}

/// Reconstruct a SHRINCS keypair from a previously persisted 264-byte
/// `secretKey` (e.g. `keys.secretKey` after several `shrincsSign` calls).
/// Recomputes both roots and the commitment from the seeds and rejects any
/// mismatch with `ERR_IMPORT_INVALID` — the same validation `shrincsSign`
/// performs on every call. Accepts the exhausted state
/// (`nextStatefulLeafIndex == maxSignatures + 1`): stateful signing then
/// throws `ERR_STATEFUL_LEAVES_EXHAUSTED`, stateless still works.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsImportSigningKey)]
pub fn shrincs_import_signing_key(secret_key: &[u8]) -> Result<WasmShrincsKeys, JsValue> {
    let candidate = deserialize_shrincs_signing_key(secret_key).map_err(js_error)?;
    let (signing_key, public_key) = ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_IMPORT_INVALID,
            message: "secretKey failed validation: counter out of range or roots do not \
                      match the seeds"
                .into(),
        })
    })?;
    Ok(WasmShrincsKeys { signing_key, public_key })
}

/// Sign a 32-byte `message` (typically a pre-computed hash) with the
/// next unused stateful leaf. STATEFUL: `secretKey` is re-validated via
/// `ShrincsSigner::import_signing_key` and then MUTATED IN PLACE with the
/// advanced leaf counter — the caller's `keys.secretKey` Uint8Array changes
/// after this call. Throws `ERR_STATEFUL_LEAVES_EXHAUSTED` once every leaf is
/// spent.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsSign)]
pub fn shrincs_sign(
    message: &[u8],
    secret_key: &mut [u8],
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let candidate = deserialize_shrincs_signing_key(secret_key).map_err(js_error)?;
    let (mut signing_key, _public_key) =
        ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
            js_error(WasmErr {
                code: ERR_IMPORT_INVALID,
                message: "secretKey failed validation: counter out of range or roots do not \
                          match the seeds"
                    .into(),
            })
        })?;
    // Pre-check exhaustion explicitly. Core signals BOTH exhaustion and
    // (astronomically rare) WOTS-C grinding failure as `None`; without this
    // check the two are conflated under one misleading error code.
    if signing_key.stateful.next_leaf_index > signing_key.stateful.public_key.max_signatures {
        return Err(js_error(WasmErr {
            code: ERR_STATEFUL_LEAVES_EXHAUSTED,
            message: "no unused stateful leaf available for this key".into(),
        }));
    }
    let hash = message_hash(message).map_err(js_error)?;
    let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &hash).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_SIGNING_FAILED,
            message: "stateful signing failed for the supplied key/message".into(),
        })
    })?;
    secret_key.copy_from_slice(&serialize_shrincs_signing_key(&signing_key));
    // Return the stateful signature alone; `shrincsVerify` checks it against
    // the signer's publicKey, mirroring the stateless path.
    Ok(crate::envelope::encode_stateful_signature_envelope(&signature))
}

/// Sign a 32-byte `message` (typically a pre-computed hash) via the
/// stateless recovery path: consumes no leaf and never mutates `secretKey`,
/// safe to repeat indefinitely.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsSignStateless)]
pub fn shrincs_sign_stateless(
    message: &[u8],
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let candidate = deserialize_shrincs_signing_key(secret_key).map_err(js_error)?;
    let (signing_key, _public_key) =
        ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
            js_error(WasmErr {
                code: ERR_IMPORT_INVALID,
                message: "secretKey failed validation: counter out of range or roots do not \
                          match the seeds"
                    .into(),
            })
        })?;
    let hash = message_hash(message).map_err(js_error)?;
    let signature = ShrincsSigner::sign_stateless_raw(&signing_key, &hash).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_SIGNING_FAILED,
            message: "stateless signing failed for the supplied key/message".into(),
        })
    })?;
    // A SHRINCS stateless signature IS a SPHINCS+C signature over the message,
    // signed under the keypair's embedded stateless key. Return exactly what
    // `sphincsPlusCSign` returns (the signature-only encoding) so
    // `shrincsVerifyStateless` is a direct `sphincsPlusCVerify`.
    Ok(crate::envelope::encode_stateless_signature_envelope(&signature))
}

/// Verify a SHRINCS stateful signature (`shrincsSign`'s output) over the
/// 32-byte `message` against the 164-byte flat `publicKey` a SHRINCS keypair
/// exposes. Verifies the signature against the supplied key, the same call
/// shape as `shrincsVerifyStateless`. Never throws — a malformed signature or
/// wrong-length key is simply `false`.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerify)]
pub fn shrincs_verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    let Ok(public_key) = public_key_from_flat(public_key) else {
        return false;
    };
    let Some(signature) = crate::envelope::decode_stateful_signature_envelope(signature) else {
        return false;
    };
    let Ok(commitment) = <[u8; HASH_LEN]>::try_from(public_key.public_key_commitment.as_slice())
    else {
        return false;
    };
    ShrincsVerifier::new().verify_stateful_unsafe_raw(commitment, &public_key, &hash, &signature)
}

/// Verify a SHRINCS stateless signature (`shrincsSignStateless`'s output) over
/// the 32-byte `message` against the 64-byte stateless public key
/// (`pkSeed‖hypertreeRoot`, the `statelessPublicKey` a SHRINCS keypair
/// exposes). A stateless SHRINCS signature is a SPHINCS+C signature, so this
/// IS `sphincsPlusCVerify`. Never throws.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStateless)]
pub fn shrincs_verify_stateless(
    signature: &[u8],
    message: &[u8],
    stateless_public_key: &[u8],
) -> bool {
    sphincs_plus_c_verify(signature, message, stateless_public_key)
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ShrincsAccountSnapshot {
    /// Commitment of the currently installed public-key bundle.
    current_shrincs_public_key: String,
    /// Account owner identity (32-byte hex).
    owner: String,
    /// Chain id bound into the account's domain separator.
    chain_id: String,
    /// Contract address bound into the account's domain separator (20-byte hex).
    contract_address: String,
    /// Domain separator mixed into every canonical message hash.
    domain_separator: String,
    /// Anti-replay nonce; advances after each successful state-changing verify.
    nonce: String,
    /// Installed-key epoch, incremented whenever a fresh key bundle is installed.
    key_version: String,
    /// Number of stateless signatures consumed under the current installed key.
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "bigint"))]
    stateless_signatures_used: u64,
    /// Active stateful policy: `"monotonic-index"`, `"recovery-rotation"`, or `"leaf-bitmap"`.
    stateful_policy: String,
    /// Next stateful leaf index the account will accept (monotonic-index policy).
    next_stateful_leaf_index: u32,
    /// Whether the account is in recovery mode.
    recovery_mode: bool,
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_policy_name(policy: crate::account::StatefulPolicy) -> String {
    match policy {
        crate::account::StatefulPolicy::MonotonicIndex => "monotonic-index".to_string(),
        crate::account::StatefulPolicy::RecoveryRotation => "recovery-rotation".to_string(),
        crate::account::StatefulPolicy::LeafBitmap => "leaf-bitmap".to_string(),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn account_snapshot_dto(
    account: &crate::account::ShrincsAccountVerifierExample,
) -> ShrincsAccountSnapshot {
    ShrincsAccountSnapshot {
        current_shrincs_public_key: hex_string(&account.currentShrincsPublicKey()),
        owner: hex_string(&account.owner()),
        chain_id: hex_string(&account.chainId()),
        contract_address: hex_string(&account.contractAddress()),
        domain_separator: hex_string(&account.domainSeparator()),
        nonce: hex_string(&account.nonce()),
        key_version: hex_string(&account.keyVersion()),
        stateless_signatures_used: account.statelessSignaturesUsed(),
        stateful_policy: stateful_policy_name(account.statefulPolicy()),
        next_stateful_leaf_index: account.nextStatefulLeafIndex(),
        recovery_mode: account.recoveryMode(),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(feature = "wasm-bindings")]
fn js_error(err: WasmErr) -> JsValue {
    let e = js_sys::Error::new(&err.message);
    if js_sys::Reflect::set(&e, &JsValue::from_str("code"), &JsValue::from_str(err.code)).is_err() {
        // Reflect::set failed, so the machine-readable code would be lost off the
        // Error object. Fold it into the message so callers never lose it.
        return js_sys::Error::new(&format!("[{}] {}", err.code, err.message)).into();
    }
    e.into()
}

/// Build a serde-boundary error handler tagged with a STATIC argument label
/// (e.g. `"publicKey"`). The label identifies which argument failed to
/// deserialize without ever echoing the caller-supplied value (inputs include
/// secret seeds). Returns a closure so call sites read
/// `.map_err(js_error_from_serde("publicKey"))`.
#[cfg(feature = "wasm-bindings")]
fn js_error_from_serde(label: &'static str) -> impl Fn(serde_wasm_bindgen::Error) -> JsValue {
    move |_error| {
        js_error(WasmErr {
            code: ERR_INVALID_INPUT,
            message: format!("invalid {label}: argument shape or field encoding"),
        })
    }
}

#[cfg(feature = "wasm-bindings")]
fn account_error_to_js(error: crate::account::AccountError) -> JsValue {
    use crate::account::AccountError;
    // Exhaustive: every AccountError variant maps to its own machine-readable
    // code so a rejection is never collapsed. Messages are static (no secrets).
    let (code, message) = match error {
        AccountError::OnlyOwner => (ERR_ONLY_OWNER, "only owner may perform this action"),
        AccountError::RecoveryPolicyRequired => (
            ERR_RECOVERY_POLICY_REQUIRED,
            "the recovery-rotation policy must be active for this operation",
        ),
        AccountError::StatefulIndexRollback => (
            ERR_STATEFUL_INDEX_ROLLBACK,
            "stateful monotonic leaf index rollback is not allowed",
        ),
        AccountError::StatefulPolicyFrozen => (
            ERR_STATEFUL_POLICY_FROZEN,
            "stateful policy changes are frozen after the first successful stateful \
             use in a key epoch",
        ),
        AccountError::InvalidSignature => {
            (ERR_INVALID_SIGNATURE, "signature verification failed")
        }
        AccountError::BudgetExhausted => (
            ERR_BUDGET_EXHAUSTED,
            "the stateless signature budget is exhausted for the current key epoch",
        ),
        AccountError::RecoveryNotArmed => {
            (ERR_RECOVERY_NOT_ARMED, "recovery mode is not armed")
        }
        AccountError::StatefulPathDisabled => (
            ERR_STATEFUL_PATH_DISABLED,
            "the stateful signing path is disabled under the recovery-rotation policy",
        ),
        AccountError::StatefulLeafRejected => (
            ERR_STATEFUL_LEAF_REJECTED,
            "the stateful leaf is not accepted by the active anti-reuse policy",
        ),
        AccountError::MalformedSignature => (
            ERR_MALFORMED_SIGNATURE,
            "the ERC-1271 signature envelope could not be decoded",
        ),
    };
    js_error(WasmErr {
        code,
        message: message.to_string(),
    })
}

#[cfg(feature = "wasm-bindings")]
fn js_value_from_serde<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    // Emit u64/i64 fields (e.g. the hypertree `treeIndex` and
    // `statelessSignaturesUsed`) as JS `BigInt` instead of `number`. The default
    // serializer errors when such a value exceeds 2^53 ("can't be represented as
    // a JavaScript number"), which otherwise breaks stateless signatures whose
    // tree index is large. `from_value` already accepts BigInt back into u64.
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    value.serialize(&serializer).map_err(js_error_from_serde("result"))
}


#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use crate::shrincs::test_fixtures::{
        fixture_entry_opt, fixture_pair, load_fixture_file, stateful_signer_fixture_path,
        TestKeyMode,
    };
    use crate::shrincs::{Keys, PublicKey as SignerPublicKey, ShrincsSigner};
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    /// `Result::unwrap_err()` requires `T: Debug`; the noble keygen structs
    /// deliberately don't derive it (they hold secret material — no reason
    /// to make it panic-message-printable). Extract the error without that
    /// bound.
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn expect_err<T>(result: Result<T, JsValue>) -> JsValue {
        match result {
            Ok(_) => panic!("expected an Err"),
            Err(err) => err,
        }
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn one_u256_hex() -> String {
        let mut out = [0u8; HASH_LEN];
        out[HASH_LEN - 1] = 1;
        hex_string(&out)
    }

    fn signing_key_and_public_key() -> (Keys, SignerPublicKey) {
        ShrincsSigner::keygen(b"wasm verifier test seed", 4).unwrap()
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use crate::test_support::stateful_only_key;

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn stateful_signing_key_and_public_key() -> (Keys, SignerPublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => stateful_only_key(b"wasm verifier test seed", 4),
            TestKeyMode::Fixture => {
                let path = stateful_signer_fixture_path();
                if path.is_file() {
                    let fixture_file = load_fixture_file(&path);
                    assert_eq!(
                        fixture_file.profile_name,
                        crate::shrincs::PROFILE_NAME,
                        "stateful signer fixture profile mismatch",
                    );
                    if let Some(entry) = fixture_entry_opt(&fixture_file, "stateful signer seed") {
                        return fixture_pair(entry);
                    }
                }

                stateful_only_key(b"wasm verifier test seed", 4)
            }
        }
    }

    #[test]
    fn bytes_fixed_rejects_wrong_length_without_echoing_the_value() {
        let err = bytes_fixed::<32>(&[0x42u8; 31]).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
        assert!(!err.message.contains("42"));
        assert!(err.message.contains("31"));

        assert!(bytes_fixed::<32>(&[0x42u8; 32]).is_ok());
        assert!(bytes_word32(&[0u8; 32]).is_ok());
        assert!(bytes_word32(&[0u8; 33]).is_err());
    }

    #[test]
    fn require_max_len_enforces_the_ceiling() {
        assert!(require_max_len(&[0u8; 10], 10).is_ok());
        let err = require_max_len(&[0u8; 11], 10).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
    }

    // ── Noble-style Uint8Array API: round trips at the Rust level ──────────
    // The primary conformance coverage lives in ts/test/ (node, against the
    // real compiled wasm); these pin the pure-Rust logic these free functions
    // wrap. Feature-gated (not `any(test, wasm-bindings)`) because they call
    // the `#[wasm_bindgen]`-annotated free functions directly, which are only
    // defined under `feature = "wasm-bindings"`.

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn sphincs_plus_c_noble_keygen_sign_verify_round_trips_and_rejects_tamper() {
        let seed = [0x11u8; 32];
        let keys = sphincs_plus_c_keygen(&seed).unwrap();
        let secret_key = keys.secret_key();
        let public_key = keys.public_key();
        assert_eq!(secret_key.len(), 128);
        assert_eq!(public_key.len(), 64);

        let message = [0x01u8; 32].to_vec();
        let signature = sphincs_plus_c_sign(&message, &secret_key).unwrap();
        assert!(sphincs_plus_c_verify(&signature, &message, &public_key));
        assert!(!sphincs_plus_c_verify(&signature, &[0xEEu8; 32], &public_key));

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!sphincs_plus_c_verify(&tampered, &message, &public_key));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn sphincs_plus_c_noble_keygen_is_deterministic_for_the_same_seed() {
        let seed = [0x22u8; 32];
        let a = sphincs_plus_c_keygen(&seed).unwrap();
        let b = sphincs_plus_c_keygen(&seed).unwrap();
        assert_eq!(a.secret_key(), b.secret_key());
        assert_eq!(a.public_key(), b.public_key());
    }

    // `error.code` assertions below need `js_sys::Reflect::get` on a real
    // `js_sys::Error`, which only works with an actual JS engine present —
    // it panics ("cannot call wasm-bindgen imported functions on non-wasm
    // targets") under a native `cargo test`. Gated to the wasm32 +
    // wasm-bindgen-test harness, matching the `wasm_account_binding_*` tests
    // below; ts/test/'s node conformance suite covers these same error
    // codes against the real compiled wasm.
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn sphincs_plus_c_noble_keygen_rejects_wrong_length_seed() {
        let err = expect_err(sphincs_plus_c_keygen(&[0u8; 31]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ERR_BAD_LENGTH,
        );
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_keygen_sign_verify_round_trips_and_rejects_tamper() {
        let seed = [0x33u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let public_key = keys.public_key();
        assert_eq!(secret_key.len(), 264);
        assert_eq!(public_key.len(), 164);

        let message = [0x03u8; 32].to_vec();
        let signature = shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(shrincs_verify(&signature, &message, &public_key));
        assert!(!shrincs_verify(&signature, &[0xEEu8; 32], &public_key));

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!shrincs_verify(&tampered, &message, &public_key));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_sign_advances_secret_key_in_place_across_two_signatures() {
        let seed = [0x44u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let public_key = keys.public_key();
        let before = secret_key.clone();

        let message = [0x04u8; 32].to_vec();
        let first = shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(secret_key, before, "secretKey must mutate in place after sign");
        assert!(shrincs_verify(&first, &message, &public_key));

        let after_first = secret_key.clone();
        let second = shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(secret_key, after_first, "secretKey must advance again on the next sign");
        assert_ne!(first, second, "two leaves must yield distinct signatures");
        assert!(shrincs_verify(&second, &message, &public_key));
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn shrincs_noble_sign_throws_when_stateful_leaves_are_exhausted() {
        let seed = [0x55u8; 32];
        let keys = shrincs_keygen(&seed, 1).unwrap();
        let mut secret_key = keys.secret_key();
        let message = [0x06u8; 32].to_vec();

        shrincs_sign(&message, &mut secret_key).unwrap(); // consumes the only leaf
        let err = expect_err(shrincs_sign(&message, &mut secret_key));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ERR_STATEFUL_LEAVES_EXHAUSTED,
        );
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_sign_stateless_never_mutates_and_verifies() {
        let seed = [0x66u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();
        // Stateless verify takes the 64-byte SPHINCS+C key (pkSeed‖hypertreeRoot),
        // not the commitment — a stateless signature is a SPHINCS+C signature.
        let stateless_public_key = keys.stateless_public_key();
        let before = secret_key.clone();

        let message = [0x05u8; 32].to_vec();
        let signature = shrincs_sign_stateless(&message, &secret_key).unwrap();
        assert_eq!(secret_key, before, "stateless sign must not mutate secretKey");
        assert!(shrincs_verify_stateless(&signature, &message, &stateless_public_key));
        assert!(!shrincs_verify_stateless(
            &signature,
            &[0xEEu8; 32],
            &stateless_public_key,
        ));
        // And it is literally the SPHINCS+C verify with that key.
        assert!(sphincs_plus_c_verify(&signature, &message, &stateless_public_key));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_import_signing_key_round_trips() {
        let seed = [0x77u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let imported = shrincs_import_signing_key(&secret_key).unwrap();
        assert_eq!(imported.secret_key(), secret_key);
        assert_eq!(imported.public_key_commitment(), keys.public_key_commitment());
    }

    // Tampered/wrong-length rejection needs `error.code`, which needs a real
    // JS engine (see the comment on `sphincs_plus_c_noble_keygen_rejects_wrong_length_seed`
    // above) — wasm32-gated; the equivalent pure-Rust check without any
    // `js_sys` involvement is `shrincs_signing_key_flat_serialization_round_trips`
    // and `shrincs::signer::tests::import_rejects_tampered_roots` below/in core.
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn shrincs_noble_import_signing_key_rejects_tampered_roots_and_bad_length() {
        let seed = [0x77u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let mut tampered = secret_key.clone();
        tampered[0] ^= 1; // corrupts statefulSkSeed, invalidating statefulRoot
        let err = expect_err(shrincs_import_signing_key(&tampered));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ERR_IMPORT_INVALID,
        );

        let err = expect_err(shrincs_import_signing_key(&secret_key[..263]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ERR_BAD_LENGTH,
        );
    }

    #[test]
    fn shrincs_signing_key_flat_serialization_round_trips() {
        let (key, _) = signing_key_and_public_key();
        let bytes = serialize_shrincs_signing_key(&key);
        assert_eq!(bytes.len(), 264);
        let parsed = deserialize_shrincs_signing_key(&bytes).unwrap();
        assert_eq!(parsed, key);

        let err = deserialize_shrincs_signing_key(&bytes[..263]).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
    }

    #[test]
    fn sphincs_plus_c_signing_key_flat_serialization_round_trips() {
        let (key, _) = signing_key_and_public_key();
        let spk = SphincsPlusCSigningKey {
            stateless_sk_seed: *key.stateless.secret.sk_seed.as_bytes(),
            stateless_prf_seed: *key.stateless.secret.prf_seed.as_bytes(),
            pk_seed: *key.stateless.public_key.pk_seed.as_bytes(),
            hypertree_root: *key.stateless.public_key.root.as_bytes(),
        };
        let bytes = serialize_sphincs_plus_c_signing_key(&spk);
        assert_eq!(bytes.len(), 128);
        let parsed = deserialize_sphincs_plus_c_signing_key(&bytes).unwrap();
        assert_eq!(parsed, spk);

        let err = deserialize_sphincs_plus_c_signing_key(&bytes[..127]).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
    }

    // The account-integration tests below build key material via the CORE
    // `ShrincsSigner` (as the other non-wasm32 tests above do) rather than
    // the noble-style `shrincsKeygen`/`shrincsSign` free functions, and drive
    // `WasmShrincsAccount` entirely through its own message-hash methods
    // (`statefulActionMessageHash`, `statelessActionMessageHash`,
    // `statefulRotationMessageHash`, `fullRotationMessageHash`) plus the
    // `envelope` encoders those methods' signatures decode — the same path a
    // real caller exercises via `shrincs.sign()` / `shrincs.signStateless()`.
    // The noble free functions themselves are covered by the
    // `shrincs_noble_*` / `sphincs_plus_c_noble_*` tests above and by
    // ts/test/'s node conformance suite.

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_tracks_policy_changes() {
        let (_, public_key) = signing_key_and_public_key();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[7u8; 20],
            &public_key.public_key_commitment,
        )
        .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.stateful_policy, "monotonic-index");
        assert!(!snapshot.recovery_mode);

        account.set_stateful_policy_recovery_rotation(&[1u8; HASH_LEN]).unwrap();
        account.enter_recovery_mode(&[1u8; HASH_LEN]).unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.stateful_policy, "recovery-rotation");
        assert!(snapshot.recovery_mode);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_verifies_canonical_stateful_action_end_to_end() {
        let (mut signing_key, public_key) = stateful_signing_key_and_public_key();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
            &public_key.public_key_commitment,
        )
        .unwrap();

        let action_type = [4u8; HASH_LEN];
        let payload_hash = [5u8; HASH_LEN];
        let message = account
            .stateful_action_message_hash(&action_type, &payload_hash)
            .unwrap();
        let core_signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let signature = crate::envelope::encode_stateful_signature_envelope(&core_signature);
        let public_key_flat = encode_public_key_flat(&public_key);

        account
            .verify_stateful_action(&public_key_flat, &action_type, &payload_hash, &signature)
            .expect("valid stateful action verifies");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.next_stateful_leaf_index, 2);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_rotates_full_key_via_canonical_recovery_message() {
        let (current_signing_key, current_public_key) = signing_key_and_public_key();
        let (_, next_public_key) = signing_key_and_public_key();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
            &current_public_key.public_key_commitment,
        )
        .unwrap();

        account.set_stateful_policy_recovery_rotation(&[1u8; HASH_LEN]).unwrap();
        account.enter_recovery_mode(&[1u8; HASH_LEN]).unwrap();

        let next_public_key_flat = encode_public_key_flat(&next_public_key);
        let recovery_message = account
            .full_rotation_message_hash(&next_public_key_flat)
            .unwrap();
        let core_recovery_signature =
            ShrincsSigner::sign_stateless_raw(&current_signing_key, &recovery_message).unwrap();
        let recovery_signature =
            crate::envelope::encode_stateless_envelope(&current_public_key, &core_recovery_signature);

        account
            .rotate_full_key(&recovery_signature, &next_public_key_flat)
            .expect("valid full rotation succeeds");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(
            snapshot.current_shrincs_public_key,
            hex_string(&next_public_key.public_key_commitment)
        );
        assert_eq!(snapshot.key_version, one_u256_hex());
        assert_eq!(snapshot.stateful_policy, "monotonic-index");
        assert!(!snapshot.recovery_mode);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_verifies_canonical_stateless_action_end_to_end() {
        let (signing_key, public_key) = signing_key_and_public_key();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
            &public_key.public_key_commitment,
        )
        .unwrap();

        let action_type = [6u8; HASH_LEN];
        let payload_hash = [7u8; HASH_LEN];
        let message = account
            .stateless_action_message_hash(&action_type, &payload_hash)
            .unwrap();
        let core_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = crate::envelope::encode_stateless_envelope(&public_key, &core_signature);

        account
            .verify_stateless_action(&action_type, &payload_hash, &signature)
            .expect("valid stateless action verifies");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.stateless_signatures_used, 1);
    }
}
