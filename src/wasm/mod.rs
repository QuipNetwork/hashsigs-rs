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
//! This module exports TS-friendly SHRINCS verifier, signer, and account
//! bindings plus canonical account-message helpers.
//! Callers pass hex strings plus plain JS objects that mirror the SHRINCS
//! public-key, signature, and account-context shapes.

#[cfg(any(test, feature = "wasm-bindings"))]
use crate::shrincs::{
    ActionContext as CoreActionContext, ForsEntry as CoreForsEntry,
    ForsSignature as CoreForsSignature,
    HypertreeLayerSignature as CoreHypertreeLayerSignature, PublicKey,
    PublicKey as SigningPublicKey, RotationTarget as CoreRotationTarget, ShrincsSigner,
    ShrincsSigningKey, ShrincsVerifier, StatefulRotationTarget as CoreStatefulRotationTarget,
    StatefulSignature as CoreStatefulSignature,
    StatefulSignature as SigningStatefulSignature,
    StatelessSignature as CoreStatelessSignature,
    StatelessSignature as SigningStatelessSignature, STATEFUL_PUBLIC_KEY_BYTES,
    WotsCSignature as CoreWotsCSignature, FORS_TREE_HEIGHT, HASH_LEN,
    HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS,
    WOTS_CHAINS_STATEFUL,
};
#[cfg(any(test, feature = "wasm-bindings"))]
use zeroize::Zeroize;

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

// Machine-readable error codes surfaced to JS as `error.code`. Frozen API once
// published: additions are safe, renames/removals are breaking.
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_HEX_INVALID: &str = "ERR_HEX_INVALID";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_BAD_LENGTH: &str = "ERR_BAD_LENGTH";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_SEED_TOO_SHORT: &str = "ERR_SEED_TOO_SHORT";
#[cfg(feature = "wasm-bindings")]
const ERR_ONLY_OWNER: &str = "ERR_ONLY_OWNER";
#[cfg(feature = "wasm-bindings")]
const ERR_RECOVERY_POLICY_REQUIRED: &str = "ERR_RECOVERY_POLICY_REQUIRED";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_INDEX_ROLLBACK: &str = "ERR_STATEFUL_INDEX_ROLLBACK";
#[cfg(feature = "wasm-bindings")]
const ERR_STATEFUL_POLICY_FROZEN: &str = "ERR_STATEFUL_POLICY_FROZEN";
#[cfg(feature = "wasm-bindings")]
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
const ERR_SIGNING_FAILED: &str = "ERR_SIGNING_FAILED";
#[cfg(feature = "wasm-bindings")]
const ERR_KEYGEN_FAILED: &str = "ERR_KEYGEN_FAILED";
#[cfg(feature = "wasm-bindings")]
const ERR_INVALID_INPUT: &str = "ERR_INVALID_INPUT";
#[cfg(feature = "wasm-bindings")]
const ERR_HANDLE_DESTROYED: &str = "ERR_HANDLE_DESTROYED";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_FORMAT_VERSION_UNSUPPORTED: &str = "ERR_FORMAT_VERSION_UNSUPPORTED";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_IMPORT_INVALID: &str = "ERR_IMPORT_INVALID";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_LEAF_OUT_OF_RANGE: &str = "ERR_LEAF_OUT_OF_RANGE";

/// Version stamped into every `ShrincsExportedSigningKey`; import rejects
/// anything else. Bump only together with a migration path in
/// `shrincsImportSigningKey`. Frozen semantics once the package is published.
#[cfg(any(test, feature = "wasm-bindings"))]
const SIGNING_KEY_FORMAT_VERSION: u32 = 1;

/// Minimum seed entropy accepted at the WASM boundary. Deliberate hardening
/// DIVERGENCE from core keygen (which accepts any length): TS callers are the
/// ones who pass "0x" or a password. Core keygen is unchanged.
#[cfg(any(test, feature = "wasm-bindings"))]
const MIN_SEED_BYTES: usize = 32;
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
  | "ERR_HEX_INVALID" | "ERR_BAD_LENGTH" | "ERR_ONLY_OWNER"
  | "ERR_RECOVERY_POLICY_REQUIRED" | "ERR_STATEFUL_INDEX_ROLLBACK"
  | "ERR_STATEFUL_POLICY_FROZEN" | "ERR_STATEFUL_LEAVES_EXHAUSTED"
  | "ERR_SIGNING_FAILED" | "ERR_KEYGEN_FAILED" | "ERR_INVALID_INPUT"
  | "ERR_HANDLE_DESTROYED"
  | "ERR_SEED_TOO_SHORT"
  | "ERR_FORMAT_VERSION_UNSUPPORTED" | "ERR_IMPORT_INVALID"
  | "ERR_LEAF_OUT_OF_RANGE"
  | "ERR_INVALID_SIGNATURE" | "ERR_BUDGET_EXHAUSTED"
  | "ERR_RECOVERY_NOT_ARMED" | "ERR_STATEFUL_PATH_DISABLED"
  | "ERR_STATEFUL_LEAF_REJECTED";
"#;

#[cfg(feature = "wasm-bindings")]
/// A live SHRINCS keypair handle. Malformed input (bad hex, wrong length)
/// THROWS an `Error` with a `ShrincsErrorCode` on `error.code`; cryptographic
/// verification failures return `false`. Call `free()` when done — using a
/// handle after `free()` throws.
#[wasm_bindgen]
pub struct WasmShrincsKeypair {
    signing_key: Option<ShrincsSigningKey>,
    public_key: Option<PublicKey>,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmShrincsKeypair {
    /// The public key bundle (all fields public; safe to persist and share).
    #[wasm_bindgen(js_name = publicKey, unchecked_return_type = "ShrincsPublicKey")]
    pub fn public_key(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&public_key_dto(self.public_key_ref()?))
    }

    /// Next monotonic stateful leaf index (non-secret). This is the value to
    /// persist after each `signStatefulRaw` — reading it here does NOT
    /// require materializing secret material via `exportSigningKey`.
    #[wasm_bindgen(getter, js_name = nextStatefulLeafIndex)]
    pub fn next_stateful_leaf_index(&self) -> Result<u32, JsValue> {
        Ok(self.signing_key_ref()?.next_stateful_leaf_index)
    }

    /// Stateful signature budget fixed at keygen (non-secret).
    #[wasm_bindgen(getter, js_name = maxStatefulSignatures)]
    pub fn max_stateful_signatures(&self) -> Result<u32, JsValue> {
        Ok(self.signing_key_ref()?.max_stateful_signatures)
    }

    /// Stateful signatures still available via `signStatefulRaw`:
    /// `max - (next - 1)`, clamped to 0 for an exhausted key.
    #[wasm_bindgen(getter, js_name = remainingStatefulSignatures)]
    pub fn remaining_stateful_signatures(&self) -> Result<u32, JsValue> {
        let signing_key = self.signing_key_ref()?;
        Ok(remaining_stateful(
            signing_key.max_stateful_signatures,
            signing_key.next_stateful_leaf_index,
        ))
    }

    /// Auto-advancing stateful signature: consumes the next unused leaf and
    /// advances the internal counter. Returns `{ signature,
    /// nextStatefulLeafIndex }` — persist `nextStatefulLeafIndex` atomically
    /// BEFORE releasing the signature; it is handed back here precisely so the
    /// persistence obligation and the signature arrive together. Throws
    /// `ERR_STATEFUL_LEAVES_EXHAUSTED` once every leaf is spent (pre-checked)
    /// and `ERR_SIGNING_FAILED` for internal signing failure.
    ///
    /// * `message_hex` - arbitrary-length hex.
    #[wasm_bindgen(js_name = signStatefulRaw, unchecked_return_type = "StatefulSignResult")]
    pub fn sign_stateful_raw(&mut self, message_hex: &str) -> Result<JsValue, JsValue> {
        let message = parse_hex_bytes_with_max(message_hex, MAX_RAW_INPUT_BYTES).map_err(js_error)?;
        let signing_key = self.signing_key_mut()?;
        // Pre-check exhaustion explicitly. Core signals BOTH exhaustion and
        // (astronomically rare) WOTS-C grinding failure as `None`; without
        // this check the two are conflated under one misleading error code.
        if signing_key.next_stateful_leaf_index > signing_key.max_stateful_signatures {
            return Err(js_error(WasmErr {
                code: ERR_STATEFUL_LEAVES_EXHAUSTED,
                message: "no unused stateful leaf available for this key".into(),
            }));
        }
        let signature = ShrincsSigner::sign_stateful_raw(signing_key, &message)
            .ok_or_else(|| {
                js_error(WasmErr {
                    code: ERR_SIGNING_FAILED,
                    message: "stateful signing failed for the supplied key/message".into(),
                })
            })?;
        js_value_from_serde(&StatefulSignResult {
            signature: stateful_signature_dto_from_signer(&signature),
            next_stateful_leaf_index: self.signing_key_ref()?.next_stateful_leaf_index,
        })
    }

    /// Deterministically sign at a caller-supplied leaf (`authPath.length === leaf`).
    /// Does not advance the internal counter — the caller owns leaf selection
    /// (e.g. from an on-chain used-leaf bitmap). Leaves run
    /// `1..=maxStatefulSignatures`; anything else throws
    /// `ERR_LEAF_OUT_OF_RANGE`.
    ///
    /// * `message_hex` - arbitrary-length hex.
    #[wasm_bindgen(js_name = signStatefulRawAt, unchecked_return_type = "StatefulSignature")]
    pub fn sign_stateful_raw_at(&self, message_hex: &str, leaf: u32) -> Result<JsValue, JsValue> {
        let message = parse_hex_bytes_with_max(message_hex, MAX_RAW_INPUT_BYTES).map_err(js_error)?;
        let signing_key = self.signing_key_ref()?;
        // Range-check up front so an out-of-range leaf is reported as what it
        // is, not as "exhausted" (the previous, misleading mapping).
        if leaf < 1 || leaf > signing_key.max_stateful_signatures {
            return Err(js_error(WasmErr {
                code: ERR_LEAF_OUT_OF_RANGE,
                message: format!(
                    "leaf must be in 1..={}, got {leaf}",
                    signing_key.max_stateful_signatures
                ),
            }));
        }
        let signature = ShrincsSigner::sign_stateful_raw_at_leaf(signing_key, leaf, &message)
            .ok_or_else(|| {
                js_error(WasmErr {
                    code: ERR_SIGNING_FAILED,
                    message: "stateful signing failed for the supplied key/leaf/message".into(),
                })
            })?;
        js_value_from_serde(&stateful_signature_dto_from_signer(&signature))
    }

    /// Stateless (recovery-path) signature: consumes no leaf and mutates no
    /// state, safe to repeat indefinitely.
    ///
    /// * `message_hex` - arbitrary-length hex.
    #[wasm_bindgen(js_name = signStatelessRaw, unchecked_return_type = "StatelessSignature")]
    pub fn sign_stateless_raw(&self, message_hex: &str) -> Result<JsValue, JsValue> {
        let message = parse_hex_bytes_with_max(message_hex, MAX_RAW_INPUT_BYTES).map_err(js_error)?;
        let signature =
            ShrincsSigner::sign_stateless_raw(self.signing_key_ref()?, &message).ok_or_else(|| {
                js_error(WasmErr {
                    code: ERR_SIGNING_FAILED,
                    message: "stateless signing failed for the supplied key/message".into(),
                })
            })?;
        js_value_from_serde(&stateless_signature_dto_from_signer(&signature))
    }

    /// Serialize the full signing key. ⚠️ Includes SECRET seed material —
    /// anyone holding it can sign. Never log it or persist it to untrusted
    /// storage. Does not mutate the keypair.
    ///
    /// The versioned counterpart of `shrincsImportSigningKey` (`formatVersion`
    /// is checked on import). To carry signing state across restarts: export
    /// after every stateful signature, persist atomically, and restore with
    /// `shrincsImportSigningKey` — never with bare `shrincsKeygen(seed)`,
    /// which resets the leaf counter and causes one-time-leaf reuse.
    ///
    /// This is intentionally marked `Unsafe` at the JS boundary because it
    /// crosses the wasm/JS trust boundary with the full private signing state.
    /// Prefer keeping the live keypair handle in wasm memory and call this only
    /// for explicit backup or migration flows.
    #[wasm_bindgen(
        js_name = exportSigningKeyUnsafe,
        unchecked_return_type = "ShrincsExportedSigningKey"
    )]
    pub fn export_signing_key_unsafe(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&signing_key_dto(self.signing_key_ref()?))
    }

    /// Legacy alias for `exportSigningKeyUnsafe()`. Kept for compatibility, but
    /// new code should call the explicit `Unsafe` form to acknowledge that this
    /// materializes the full private signing state into JS-visible values.
    #[wasm_bindgen(js_name = exportSigningKey, unchecked_return_type = "ShrincsExportedSigningKey")]
    pub fn export_signing_key(&self) -> Result<JsValue, JsValue> {
        self.export_signing_key_unsafe()
    }

    /// Best-effort explicit wipe. Clears the in-memory signing state early and
    /// permanently invalidates this handle; subsequent method calls throw
    /// `ERR_HANDLE_DESTROYED`.
    #[wasm_bindgen(js_name = destroy)]
    pub fn destroy(&mut self) {
        self.public_key = None;
        self.signing_key = None;
    }
}

#[cfg(feature = "wasm-bindings")]
impl WasmShrincsKeypair {
    fn signing_key_ref(&self) -> Result<&ShrincsSigningKey, JsValue> {
        self.signing_key.as_ref().ok_or_else(destroyed_handle_error)
    }

    fn signing_key_mut(&mut self) -> Result<&mut ShrincsSigningKey, JsValue> {
        self.signing_key.as_mut().ok_or_else(destroyed_handle_error)
    }

    fn public_key_ref(&self) -> Result<&PublicKey, JsValue> {
        self.public_key.as_ref().ok_or_else(destroyed_handle_error)
    }
}

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
    /// * `owner_hex` - 32-byte hex (bytes32).
    /// * `chain_id_hex` - 32-byte hex (bytes32).
    /// * `contract_address_hex` - **20-byte** hex (EVM address — NOT bytes32).
    /// * `initial_public_key_commitment_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(constructor)]
    pub fn new(
        owner_hex: &str,
        chain_id_hex: &str,
        contract_address_hex: &str,
        initial_public_key_commitment_hex: &str,
    ) -> Result<WasmShrincsAccount, JsValue> {
        let owner = parse_word32(owner_hex).map_err(js_error)?;
        let chain_id = parse_word32(chain_id_hex).map_err(js_error)?;
        let contract_address = parse_address20(contract_address_hex).map_err(js_error)?;
        let initial_public_key_commitment =
            parse_word32(initial_public_key_commitment_hex).map_err(js_error)?;
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

    /// Verify a stateful action signature against the account's canonical
    /// action hash and enforce the stateful policy. Resolves on success and
    /// advances account state; THROWS a typed `ShrincsErrorCode` on malformed
    /// input OR on rejection — e.g. `ERR_INVALID_SIGNATURE` for a bad
    /// signature, `ERR_STATEFUL_LEAF_REJECTED` / `ERR_STATEFUL_PATH_DISABLED`
    /// for a policy-blocked leaf.
    ///
    /// * `action_type_hex` - 32-byte hex (bytes32).
    /// * `payload_hash_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = verifyStatefulAction)]
    pub fn verify_stateful_action(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
        action_type_hex: &str,
        payload_hash_hex: &str,
        #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
    ) -> Result<(), JsValue> {
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
        let signature: StatefulSignature =
            serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
        let public_key = parse_public_key(&public_key).map_err(js_error)?;
        let action_type = parse_word32(action_type_hex).map_err(js_error)?;
        let payload_hash = parse_word32(payload_hash_hex).map_err(js_error)?;
        let signature = parse_stateful_signature(&signature).map_err(js_error)?;
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
    /// * `action_type_hex` - 32-byte hex (bytes32).
    /// * `payload_hash_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = verifyStatelessAction)]
    pub fn verify_stateless_action(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
        action_type_hex: &str,
        payload_hash_hex: &str,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
    ) -> Result<(), JsValue> {
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
        let signature: StatelessSignature =
            serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
        let public_key = parse_public_key(&public_key).map_err(js_error)?;
        let action_type = parse_word32(action_type_hex).map_err(js_error)?;
        let payload_hash = parse_word32(payload_hash_hex).map_err(js_error)?;
        let signature = parse_stateless_signature(&signature).map_err(js_error)?;
        self.inner
            .verifyStatelessAction(&public_key, action_type, payload_hash, &signature)
            .map_err(account_error_to_js)
    }

    /// Rotate to a fresh stateful key (stateless part retained), authorized by
    /// a stateless recovery signature. Resolves on success; THROWS a typed
    /// `ShrincsErrorCode` on malformed input OR on rejection — e.g.
    /// `ERR_INVALID_SIGNATURE`, `ERR_RECOVERY_POLICY_REQUIRED`,
    /// `ERR_RECOVERY_NOT_ARMED`, `ERR_BUDGET_EXHAUSTED`.
    #[wasm_bindgen(js_name = rotateToFreshKey)]
    pub fn rotate_to_fresh_key(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] recovery_signature: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatefulRotationTarget")] next_key: JsValue,
    ) -> Result<(), JsValue> {
        let current_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(current_public_key)
                .map_err(js_error_from_serde("currentPublicKey"))?;
        let recovery_signature: StatelessSignature =
            serde_wasm_bindgen::from_value(recovery_signature)
                .map_err(js_error_from_serde("recoverySignature"))?;
        let next_key: StatefulRotationTarget =
            serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
        let current_public_key = parse_public_key(&current_public_key).map_err(js_error)?;
        let recovery_signature =
            parse_stateless_signature(&recovery_signature).map_err(js_error)?;
        let next_key = parse_stateful_rotation_target(&next_key).map_err(js_error)?;
        self.inner
            .rotateToFreshKey(&current_public_key, &recovery_signature, &next_key)
            .map_err(account_error_to_js)
    }

    /// Rotate the full hybrid key bundle, authorized by a stateless recovery
    /// signature. Resolves on success; THROWS a typed `ShrincsErrorCode` on
    /// malformed input OR on rejection — e.g. `ERR_INVALID_SIGNATURE`,
    /// `ERR_RECOVERY_POLICY_REQUIRED`, `ERR_RECOVERY_NOT_ARMED`,
    /// `ERR_BUDGET_EXHAUSTED`.
    #[wasm_bindgen(js_name = rotateFullKey)]
    pub fn rotate_full_key(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] recovery_signature: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RotationTarget")] next_key: JsValue,
    ) -> Result<(), JsValue> {
        let current_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(current_public_key)
                .map_err(js_error_from_serde("currentPublicKey"))?;
        let recovery_signature: StatelessSignature =
            serde_wasm_bindgen::from_value(recovery_signature)
                .map_err(js_error_from_serde("recoverySignature"))?;
        let next_key: RotationTarget =
            serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
        let current_public_key = parse_public_key(&current_public_key).map_err(js_error)?;
        let recovery_signature =
            parse_stateless_signature(&recovery_signature).map_err(js_error)?;
        let next_key = parse_rotation_target(&next_key).map_err(js_error)?;
        self.inner
            .rotateFullKey(&current_public_key, &recovery_signature, &next_key)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the monotonic-index stateful policy starting at
    /// `initialLeafIndex`. Throws `ERR_ONLY_OWNER` for any other caller and
    /// `ERR_STATEFUL_POLICY_FROZEN` after the first stateful use in an epoch.
    ///
    /// * `caller_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyMonotonicIndex)]
    pub fn set_stateful_policy_monotonic_index(
        &mut self,
        caller_hex: &str,
        initial_leaf_index: u32,
    ) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .setStatefulPolicyMonotonicIndex(caller, initial_leaf_index)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the recovery-rotation stateful policy. Throws
    /// `ERR_ONLY_OWNER` / `ERR_STATEFUL_POLICY_FROZEN` like the other setters.
    ///
    /// * `caller_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyRecoveryRotation)]
    pub fn set_stateful_policy_recovery_rotation(
        &mut self,
        caller_hex: &str,
    ) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .setStatefulPolicyRecoveryRotation(caller)
            .map_err(account_error_to_js)
    }

    /// Owner-only: adopt the leaf-bitmap stateful policy (caller-selected
    /// leaves, pairs with `signStatefulRawAt`). Throws `ERR_ONLY_OWNER` /
    /// `ERR_STATEFUL_POLICY_FROZEN` like the other setters.
    ///
    /// * `caller_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = setStatefulPolicyLeafBitmap)]
    pub fn set_stateful_policy_leaf_bitmap(&mut self, caller_hex: &str) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .setStatefulPolicyLeafBitmap(caller)
            .map_err(account_error_to_js)
    }

    /// Owner-only: enter recovery mode. Requires an active recovery-capable
    /// policy — throws `ERR_RECOVERY_POLICY_REQUIRED` otherwise.
    ///
    /// * `caller_hex` - 32-byte hex (bytes32).
    #[wasm_bindgen(js_name = enterRecoveryMode)]
    pub fn enter_recovery_mode(&mut self, caller_hex: &str) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .enterRecoveryMode(caller)
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

/// Derive a SHRINCS keypair from `seedHex`. Deterministic: the same seed
/// always yields the same key, so the seed IS the key — supply at least 32
/// bytes of cryptographically secure entropy and guard it like one. Seeds
/// under 32 bytes are rejected with `ERR_SEED_TOO_SHORT`.
/// `maxStatefulSignatures` fixes the stateful leaf budget for the key's
/// lifetime and must be in `1..=4096`; out-of-range values throw
/// `ERR_INVALID_INPUT`. Throws `ERR_KEYGEN_FAILED` only on internal failure.
///
/// * `seed_hex` - hex, at least 32 bytes.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsKeygen)]
pub fn shrincs_keygen(
    seed_hex: &str,
    max_stateful_signatures: u32,
) -> Result<WasmShrincsKeypair, JsValue> {
    // Budget range is caller input, not a crypto failure: reject it as ERR_INVALID_INPUT
    // rather than letting keygen's None surface as the internal ERR_KEYGEN_FAILED.
    if max_stateful_signatures == 0
        || max_stateful_signatures > MAX_STATEFUL_SIGNATURES_LIMIT as u32
    {
        return Err(js_error(WasmErr {
            code: ERR_INVALID_INPUT,
            message: format!(
                "maxStatefulSignatures must be in 1..={MAX_STATEFUL_SIGNATURES_LIMIT}"
            ),
        }));
    }
    let mut seed_material =
        parse_hex_bytes_with_max(seed_hex, MAX_RAW_INPUT_BYTES).map_err(js_error)?;
    // Wipe the secret seed before returning on the too-short branch: an early
    // return here must not leave un-zeroized seed material behind.
    if let Err(err) = validate_seed_length(&seed_material) {
        seed_material.zeroize();
        return Err(js_error(err));
    }
    let result = ShrincsSigner::keygen(&seed_material, max_stateful_signatures);
    seed_material.zeroize();
    // keygen only returns None for the budget range already rejected above, so this
    // fallback is defensive and should be unreachable in practice.
    let (signing_key, public_key) = result.ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_KEYGEN_FAILED,
            message: "key generation failed for the supplied inputs".into(),
        })
    })?;
    Ok(WasmShrincsKeypair {
        signing_key: Some(signing_key),
        public_key: Some(
            parse_public_key(&public_key_dto_from_signer(&public_key)).map_err(js_error)?,
        ),
    })
}

/// Reconstruct a keypair from `exportSigningKey()` output. Checks
/// `formatVersion`, bounds-checks the counter (`1 ≤ nextStatefulLeafIndex ≤
/// maxStatefulSignatures + 1` — the top value is a legitimately exhausted
/// key: stateful signing throws `ERR_STATEFUL_LEAVES_EXHAUSTED`, stateless
/// still works), recomputes both roots and the commitment from the seeds, and
/// rejects any mismatch with `ERR_IMPORT_INVALID`. ⚠️ The input contains
/// SECRET seed material — treat the whole object as a private key. Import
/// validates internal consistency only; it cannot detect a STALE blob —
/// persist the export atomically after every stateful signature, and never
/// restore it from anything but that store (a stale counter causes
/// one-time-leaf reuse, which is forgeable).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsImportSigningKey)]
pub fn shrincs_import_signing_key(
    #[wasm_bindgen(unchecked_param_type = "ShrincsExportedSigningKey")] exported: JsValue,
) -> Result<WasmShrincsKeypair, JsValue> {
    let mut exported: ShrincsExportedSigningKey = serde_wasm_bindgen::from_value(exported)
        .map_err(js_error_from_serde("exportedSigningKey"))?;
    if exported.format_version != SIGNING_KEY_FORMAT_VERSION {
        let actual = exported.format_version;
        zeroize_exported_signing_key(&mut exported);
        return Err(js_error(WasmErr {
            code: ERR_FORMAT_VERSION_UNSUPPORTED,
            message: format!(
                "unsupported signing-key format version {} (expected {})",
                actual, SIGNING_KEY_FORMAT_VERSION
            ),
        }));
    }
    let candidate = match parse_exported_signing_key(&exported) {
        Ok(candidate) => candidate,
        Err(err) => {
            zeroize_exported_signing_key(&mut exported);
            return Err(js_error(err));
        }
    };
    zeroize_exported_signing_key(&mut exported);
    let (signing_key, public_key) =
        ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
            js_error(WasmErr {
                code: ERR_IMPORT_INVALID,
                message: "exported key failed validation: counter out of range \
                          or roots do not match the seeds"
                    .into(),
            })
        })?;
    Ok(WasmShrincsKeypair {
        signing_key: Some(signing_key),
        public_key: Some(parse_public_key(&public_key_dto_from_signer(&public_key))
            .map_err(js_error)?),
    })
}

/// `signing_key_dto` in reverse. `parse_word32` length-checks every field;
/// error messages never echo values — eight of these fields are secrets.
#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_exported_signing_key(
    input: &ShrincsExportedSigningKey,
) -> Result<ShrincsSigningKey, WasmErr> {
    Ok(ShrincsSigningKey {
        stateful_sk_seed: parse_word32(&input.stateful_sk_seed)?,
        stateful_prf_seed: parse_word32(&input.stateful_prf_seed)?,
        stateful_pk_seed: parse_word32(&input.stateful_pk_seed)?,
        stateful_root: parse_word32(&input.stateful_root)?,
        max_stateful_signatures: input.max_stateful_signatures,
        next_stateful_leaf_index: input.next_stateful_leaf_index,
        stateless_sk_seed: parse_word32(&input.stateless_sk_seed)?,
        stateless_prf_seed: parse_word32(&input.stateless_prf_seed)?,
        pk_seed: parse_word32(&input.pk_seed)?,
        hypertree_root: parse_word32(&input.hypertree_root)?,
    })
}

/// Canonical message hash a stateful action signature must sign for the given
/// commitment and context. Returns 32-byte hex.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulActionMessageHash)]
pub fn shrincs_stateful_action_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<String, JsValue> {
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    stateful_action_message_hash_inner(expected_public_key_commitment_hex, &context)
        .map_err(js_error)
}

/// Canonical message hash a stateless action signature must sign for the given
/// commitment and context. Returns 32-byte hex.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatelessActionMessageHash)]
pub fn shrincs_stateless_action_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<String, JsValue> {
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    stateless_action_message_hash_inner(expected_public_key_commitment_hex, &context)
        .map_err(js_error)
}

/// Canonical message hash authorizing a fresh-stateful-key rotation
/// (`rotateToFreshKey`). Returns 32-byte hex.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulRotationMessageHash)]
pub fn shrincs_stateful_rotation_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulRotationTarget")] next_key: JsValue,
) -> Result<String, JsValue> {
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key)
            .map_err(js_error_from_serde("currentPublicKey"))?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let next_key: StatefulRotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
    stateful_rotation_message_hash_inner(
        expected_public_key_commitment_hex,
        &current_public_key,
        &context,
        &next_key,
    )
    .map_err(js_error)
}

/// Canonical message hash authorizing a full key-bundle rotation
/// (`rotateFullKey`). Returns 32-byte hex.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsFullRotationMessageHash)]
pub fn shrincs_full_rotation_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationTarget")] next_key: JsValue,
) -> Result<String, JsValue> {
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key)
            .map_err(js_error_from_serde("currentPublicKey"))?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let next_key: RotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
    full_rotation_message_hash_inner(
        expected_public_key_commitment_hex,
        &current_public_key,
        &context,
        &next_key,
    )
    .map_err(js_error)
}

/// Verify a stateful signature over raw message bytes. Returns `true`/`false`
/// for a cryptographically valid/invalid signature; THROWS only on malformed
/// input (bad hex / wrong-length fields), never for an invalid signature.
/// Stateless wrapper — enforces no account policy (no leaf-reuse tracking).
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
/// * `message_hex` - arbitrary-length hex.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulRaw)]
pub fn shrincs_verify_stateful_raw(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateful_raw_inner(
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

/// Verify a stateful signature over the canonical action hash for `context`.
/// Returns `true`/`false` for a cryptographically valid/invalid signature;
/// THROWS only on malformed input, never for an invalid signature.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulAction)]
pub fn shrincs_verify_stateful_action(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateful_action_inner(
        expected_public_key_commitment_hex,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

/// Verify a stateless signature over raw message bytes. Returns `true`/`false`
/// for a cryptographically valid/invalid signature; THROWS only on malformed
/// input (bad hex / wrong-length fields), never for an invalid signature.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
/// * `message_hex` - arbitrary-length hex.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessRaw)]
pub fn shrincs_verify_stateless_raw(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateless_raw_inner(
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

/// Verify a stateless signature over the canonical action hash for `context`.
/// Returns `true`/`false` for a cryptographically valid/invalid signature;
/// THROWS only on malformed input, never for an invalid signature.
///
/// * `expected_public_key_commitment_hex` - 32-byte hex (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessAction)]
pub fn shrincs_verify_stateless_action(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateless_action_inner(
        expected_public_key_commitment_hex,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ShrincsPublicKey {
    /// Encoded stateful key: `pkSeed ‖ root ‖ maxSignatures` (68 bytes hex).
    stateful_public_key: String,
    /// Commitment to the installed hybrid public-key bundle. This is the
    /// 32-byte value verifiers pin (`expectedPublicKeyCommitmentHex`).
    public_key_commitment: String,
    /// Global stateless public seed used for FORS-C, hypertree, and WOTS-C hashing.
    pk_seed: String,
    /// Expected final hypertree root.
    hypertree_root: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ActionContext {
    domain_separator: String,
    nonce: String,
    key_version: String,
    action_type: String,
    payload_hash: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct RotationContext {
    domain_separator: String,
    nonce: String,
    key_version: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct StatefulSignature {
    randomizer: String,
    counter: u32,
    chains: Vec<String>,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
/// Result of auto-advancing stateful signing: the signature plus the counter
/// value to persist (same field name/meaning as the keypair getter and the
/// exported blob).
pub struct StatefulSignResult {
    signature: StatefulSignature,
    next_stateful_leaf_index: u32,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ForsEntry {
    secret_leaf: String,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ForsSignature {
    randomizer: String,
    counter: u32,
    entries: Vec<ForsEntry>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
struct WasmWotsCSignature {
    randomizer: String,
    counter: u32,
    chains: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
struct WasmHypertreeLayerSignature {
    wots_c_pk_hash: String,
    wots_c_signature: WasmWotsCSignature,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct StatelessSignature {
    fors: ForsSignature,
    hypertree: Vec<WasmHypertreeLayerSignature>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
/// Full signing-key material. Anyone with the four 🔒 seed fields can sign —
/// treat the whole object as a private key.
///
/// Versioned serialization format (`formatVersion`), accepted by
/// `shrincsImportSigningKey`. Shape is frozen per version once published.
pub struct ShrincsExportedSigningKey {
    /// Serialization format version. Always `1` today; import rejects others
    /// with `ERR_FORMAT_VERSION_UNSUPPORTED`.
    format_version: u32,
    /// 🔒 Secret seed used to derive stateful WOTS-C chain secrets.
    stateful_sk_seed: String,
    /// 🔒 Secret PRF seed used to derive stateful WOTS-C message randomizers.
    stateful_prf_seed: String,
    /// Public seed used in stateful WOTS-C and stateful tree hashing.
    stateful_pk_seed: String,
    /// Root of the stateful unbalanced tree committed in the public key.
    stateful_root: String,
    /// Highest stateful leaf index this key may sign with.
    max_stateful_signatures: u32,
    /// Next monotonic stateful leaf index. Persist this after each stateful signature.
    next_stateful_leaf_index: u32,
    /// 🔒 Stateless SK.seed-style material used to derive FORS-C and hypertree WOTS-C secrets.
    stateless_sk_seed: String,
    /// 🔒 Stateless SK.prf-style material used to derive stateless message randomizers.
    stateless_prf_seed: String,
    /// Global public seed used in FORS-C, hypertree WOTS-C, and Merkle node hashing.
    pk_seed: String,
    /// Top hypertree root committed in the public key.
    hypertree_root: String,
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
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct StatefulRotationTarget {
    stateful_public_key: String,
    public_key_commitment: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct RotationTarget {
    stateful_public_key: String,
    public_key_commitment: String,
    pk_seed: String,
    hypertree_root: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateful_raw_inner(
    expected_public_key_commitment_hex: &str,
    public_key: &ShrincsPublicKey,
    message_hex: &str,
    signature: &StatefulSignature,
) -> Result<bool, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes_with_max(message_hex, MAX_RAW_INPUT_BYTES)?;
    let signature = parse_stateful_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateful_unsafe_raw(
        expected_public_key_commitment,
        &public_key,
        &message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_action_message_hash_inner(
    expected_public_key_commitment_hex: &str,
    context: &ActionContext,
) -> Result<String, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let context = parse_action_context(context)?;
    Ok(hex_string(
        &ShrincsVerifier::new()
            .stateful_action_message_hash(expected_public_key_commitment, &context),
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateless_action_message_hash_inner(
    expected_public_key_commitment_hex: &str,
    context: &ActionContext,
) -> Result<String, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let context = parse_action_context(context)?;
    Ok(hex_string(
        &ShrincsVerifier::new()
            .stateless_action_message_hash(expected_public_key_commitment, &context),
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_rotation_message_hash_inner(
    expected_public_key_commitment_hex: &str,
    current_public_key: &ShrincsPublicKey,
    context: &RotationContext,
    next_key: &StatefulRotationTarget,
) -> Result<String, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let current_public_key = parse_public_key(current_public_key)?;
    let context = parse_rotation_context(context)?;
    let next_key = parse_stateful_rotation_target(next_key)?;
    Ok(hex_string(
        &ShrincsVerifier::new().stateful_rotation_message_hash(
            expected_public_key_commitment,
            &current_public_key,
            &context,
            &next_key,
        ),
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn full_rotation_message_hash_inner(
    expected_public_key_commitment_hex: &str,
    current_public_key: &ShrincsPublicKey,
    context: &RotationContext,
    next_key: &RotationTarget,
) -> Result<String, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let current_public_key = parse_public_key(current_public_key)?;
    let context = parse_rotation_context(context)?;
    let next_key = parse_rotation_target(next_key)?;
    Ok(hex_string(
        &ShrincsVerifier::new().full_rotation_message_hash(
            expected_public_key_commitment,
            &current_public_key,
            &context,
            &next_key,
        ),
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateful_action_inner(
    expected_public_key_commitment_hex: &str,
    public_key: &ShrincsPublicKey,
    context: &ActionContext,
    signature: &StatefulSignature,
) -> Result<bool, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let context = parse_action_context(context)?;
    let signature = parse_stateful_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateful(
        expected_public_key_commitment,
        &public_key,
        &context,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateless_raw_inner(
    expected_public_key_commitment_hex: &str,
    public_key: &ShrincsPublicKey,
    message_hex: &str,
    signature: &StatelessSignature,
) -> Result<bool, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes_with_max(message_hex, MAX_RAW_INPUT_BYTES)?;
    let signature = parse_stateless_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateless_unsafe_raw(
        expected_public_key_commitment,
        &public_key,
        &message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateless_action_inner(
    expected_public_key_commitment_hex: &str,
    public_key: &ShrincsPublicKey,
    context: &ActionContext,
    signature: &StatelessSignature,
) -> Result<bool, WasmErr> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let context = parse_action_context(context)?;
    let signature = parse_stateless_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateless(
        expected_public_key_commitment,
        &public_key,
        &context,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_public_key(input: &ShrincsPublicKey) -> Result<PublicKey, WasmErr> {
    Ok(PublicKey {
        stateful_public_key: parse_fixed_hex::<STATEFUL_PUBLIC_KEY_BYTES>(
            &input.stateful_public_key,
        )?
        .to_vec(),
        public_key_commitment: parse_word32(&input.public_key_commitment)?.to_vec(),
        pk_seed: parse_word32(&input.pk_seed)?.to_vec(),
        hypertree_root: parse_word32(&input.hypertree_root)?.to_vec(),
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_action_context(input: &ActionContext) -> Result<CoreActionContext, WasmErr> {
    Ok(CoreActionContext {
        domain_separator: parse_word32(&input.domain_separator)?,
        nonce: parse_word32(&input.nonce)?,
        key_version: parse_word32(&input.key_version)?,
        action_type: parse_word32(&input.action_type)?,
        payload_hash: parse_word32(&input.payload_hash)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_rotation_context(
    input: &RotationContext,
) -> Result<crate::shrincs::RotationContext, WasmErr> {
    Ok(crate::shrincs::RotationContext {
        domain_separator: parse_word32(&input.domain_separator)?,
        nonce: parse_word32(&input.nonce)?,
        key_version: parse_word32(&input.key_version)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateful_signature(input: &StatefulSignature) -> Result<CoreStatefulSignature, WasmErr> {
    expect_vec_len("stateful signature chains", input.chains.len(), WOTS_CHAINS_STATEFUL)?;
    expect_vec_len_at_most(
        "stateful signature auth path",
        input.auth_path.len(),
        MAX_STATEFUL_SIGNATURES_LIMIT,
    )?;
    Ok(CoreStatefulSignature {
        randomizer: parse_word32(&input.randomizer)?,
        counter: input.counter,
        chains: input
            .chains
            .iter()
            .map(|item| parse_word32(item))
            .collect::<Result<Vec<_>, _>>()?,
        auth_path: input
            .auth_path
            .iter()
            .map(|item| parse_word32(item))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Parse one FORS entry, length-checking its auth path against the schema
/// before decoding any node. Extracted from `parse_stateless_signature` to keep
/// that function's cyclomatic complexity within bounds.
#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_fors_entry(entry: &ForsEntry) -> Result<CoreForsEntry, WasmErr> {
    expect_vec_len("FORS auth path", entry.auth_path.len(), FORS_TREE_HEIGHT as usize)?;
    Ok(CoreForsEntry {
        secret_leaf: parse_word32(&entry.secret_leaf)?.to_vec(),
        auth_path: entry
            .auth_path
            .iter()
            .map(|node| parse_word32(node).map(|word| word.to_vec()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Parse one hypertree layer, length-checking its WOTS-C chains and auth path
/// against the schema before decoding any node. Extracted from
/// `parse_stateless_signature` to keep its cyclomatic complexity within bounds.
#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_hypertree_layer(
    layer: &WasmHypertreeLayerSignature,
    subtree_height: usize,
) -> Result<CoreHypertreeLayerSignature, WasmErr> {
    expect_vec_len(
        "WOTS-C chains",
        layer.wots_c_signature.chains.len(),
        NUM_WOTS_CHAINS as usize,
    )?;
    expect_vec_len("hypertree auth path", layer.auth_path.len(), subtree_height)?;
    Ok(CoreHypertreeLayerSignature {
        wots_c_pk_hash: parse_word32(&layer.wots_c_pk_hash)?.to_vec(),
        wots_c_signature: CoreWotsCSignature {
            randomizer: parse_word32(&layer.wots_c_signature.randomizer)?.to_vec(),
            counter: layer.wots_c_signature.counter,
            chains: layer
                .wots_c_signature
                .chains
                .iter()
                .map(|chain| parse_word32(chain).map(|word| word.to_vec()))
                .collect::<Result<Vec<_>, _>>()?,
        },
        auth_path: layer
            .auth_path
            .iter()
            .map(|node| parse_word32(node).map(|word| word.to_vec()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateless_signature(
    input: &StatelessSignature,
) -> Result<CoreStatelessSignature, WasmErr> {
    let signed_fors_trees = NUM_FORS_TREES as usize - 1;
    let subtree_height = (HYPERTREE_HEIGHT / NUM_HYPERTREE_LAYERS) as usize;
    expect_vec_len("FORS entries", input.fors.entries.len(), signed_fors_trees)?;
    expect_vec_len("hypertree layers", input.hypertree.len(), NUM_HYPERTREE_LAYERS as usize)?;
    Ok(CoreStatelessSignature {
        fors: CoreForsSignature {
            randomizer: parse_word32(&input.fors.randomizer)?.to_vec(),
            counter: input.fors.counter,
            entries: input
                .fors
                .entries
                .iter()
                .map(parse_fors_entry)
                .collect::<Result<Vec<_>, _>>()?,
        },
        hypertree: input
            .hypertree
            .iter()
            .map(|layer| parse_hypertree_layer(layer, subtree_height))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateful_rotation_target(
    input: &StatefulRotationTarget,
) -> Result<CoreStatefulRotationTarget, WasmErr> {
    Ok(CoreStatefulRotationTarget {
        stateful_public_key: parse_fixed_hex::<STATEFUL_PUBLIC_KEY_BYTES>(
            &input.stateful_public_key,
        )?
        .to_vec(),
        public_key_commitment: parse_word32(&input.public_key_commitment)?.to_vec(),
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_rotation_target(input: &RotationTarget) -> Result<CoreRotationTarget, WasmErr> {
    Ok(CoreRotationTarget {
        stateful_public_key: parse_fixed_hex::<STATEFUL_PUBLIC_KEY_BYTES>(
            &input.stateful_public_key,
        )?
        .to_vec(),
        public_key_commitment: parse_word32(&input.public_key_commitment)?.to_vec(),
        pk_seed: parse_word32(&input.pk_seed)?.to_vec(),
        hypertree_root: parse_word32(&input.hypertree_root)?.to_vec(),
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_word32(input: &str) -> Result<[u8; HASH_LEN], WasmErr> {
    parse_fixed_hex::<HASH_LEN>(input)
}

/// Stateful signatures still available: `max - (next - 1)`, clamped to 0
/// (an exhausted key has `next == max + 1`).
#[cfg(any(test, feature = "wasm-bindings"))]
fn remaining_stateful(max_stateful_signatures: u32, next_stateful_leaf_index: u32) -> u32 {
    max_stateful_signatures.saturating_sub(next_stateful_leaf_index.saturating_sub(1))
}

/// Enforce the `MIN_SEED_BYTES` floor. Reports length only — never the seed
/// value (it is secret key material).
#[cfg(any(test, feature = "wasm-bindings"))]
fn validate_seed_length(seed: &[u8]) -> Result<(), WasmErr> {
    if seed.len() < MIN_SEED_BYTES {
        return Err(WasmErr {
            code: ERR_SEED_TOO_SHORT,
            message: format!(
                "seed must be at least {MIN_SEED_BYTES} bytes, got {}",
                seed.len()
            ),
        });
    }
    Ok(())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn normalized_hex_body(input: &str) -> Result<&str, WasmErr> {
    // Error messages must not echo `input`: hex inputs include secret seeds,
    // and echoed values leak into logs/telemetry via exception messages.
    // Accept either `0x` or `0X` prefix.
    let trimmed = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if !trimmed.is_ascii() {
        return Err(WasmErr {
            code: ERR_HEX_INVALID,
            message: "hex string must be ASCII".into(),
        });
    }
    if trimmed.len() % 2 != 0 {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("hex string must have even length (got {} chars)", trimmed.len()),
        });
    }
    Ok(trimmed)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_hex_bytes_with_max(input: &str, max_bytes: usize) -> Result<Vec<u8>, WasmErr> {
    let trimmed = normalized_hex_body(input)?;
    let byte_len = trimmed.len() / 2;
    if byte_len > max_bytes {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("hex input exceeds maximum of {max_bytes} bytes"),
        });
    }

    let mut out = Vec::with_capacity(byte_len);
    for index in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|_| WasmErr {
            code: ERR_HEX_INVALID,
            message: format!("invalid hex at byte offset {}", index / 2),
        })?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, WasmErr> {
    parse_hex_bytes_with_max(input, MAX_RAW_INPUT_BYTES)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_fixed_hex<const N: usize>(input: &str) -> Result<[u8; N], WasmErr> {
    let trimmed = normalized_hex_body(input)?;
    let len = trimmed.len() / 2;
    if len != N {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("expected {N} bytes for fixed-width field, got {len}"),
        });
    }

    let mut out = [0u8; N];
    for (i, index) in (0..trimmed.len()).step_by(2).enumerate() {
        out[i] = u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|_| WasmErr {
            code: ERR_HEX_INVALID,
            message: format!("invalid hex at byte offset {}", index / 2),
        })?;
    }
    Ok(out)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_address20(input: &str) -> Result<[u8; 20], WasmErr> {
    parse_fixed_hex::<20>(input)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn expect_vec_len(name: &str, actual: usize, expected: usize) -> Result<(), WasmErr> {
    if actual != expected {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("{name} must contain exactly {expected} items, got {actual}"),
        });
    }
    Ok(())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn expect_vec_len_at_most(name: &str, actual: usize, max: usize) -> Result<(), WasmErr> {
    if actual > max {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("{name} exceeds maximum of {max} items (got {actual})"),
        });
    }
    Ok(())
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
fn public_key_dto(public_key: &PublicKey) -> ShrincsPublicKey {
    ShrincsPublicKey {
        stateful_public_key: hex_string(&public_key.stateful_public_key),
        public_key_commitment: hex_string(&public_key.public_key_commitment),
        pk_seed: hex_string(&public_key.pk_seed),
        hypertree_root: hex_string(&public_key.hypertree_root),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn public_key_dto_from_signer(public_key: &SigningPublicKey) -> ShrincsPublicKey {
    ShrincsPublicKey {
        stateful_public_key: hex_string(&public_key.stateful_public_key),
        public_key_commitment: hex_string(&public_key.public_key_commitment),
        pk_seed: hex_string(&public_key.pk_seed),
        hypertree_root: hex_string(&public_key.hypertree_root),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_signature_dto_from_signer(
    signature: &SigningStatefulSignature,
) -> StatefulSignature {
    StatefulSignature {
        randomizer: hex_string(&signature.randomizer),
        counter: signature.counter,
        chains: signature
            .chains
            .iter()
            .map(|item| hex_string(item))
            .collect(),
        auth_path: signature
            .auth_path
            .iter()
            .map(|item| hex_string(item))
            .collect(),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateless_signature_dto_from_signer(
    signature: &SigningStatelessSignature,
) -> StatelessSignature {
    StatelessSignature {
        fors: ForsSignature {
            randomizer: hex_string(&signature.fors.randomizer),
            counter: signature.fors.counter,
            entries: signature
                .fors
                .entries
                .iter()
                .map(|entry| ForsEntry {
                    secret_leaf: hex_string(&entry.secret_leaf),
                    auth_path: entry
                        .auth_path
                        .iter()
                        .map(|node| hex_string(node))
                        .collect(),
                })
                .collect(),
        },
        hypertree: signature
            .hypertree
            .iter()
            .map(|layer| WasmHypertreeLayerSignature {
                wots_c_pk_hash: hex_string(&layer.wots_c_pk_hash),
                wots_c_signature: WasmWotsCSignature {
                    randomizer: hex_string(&layer.wots_c_signature.randomizer),
                    counter: layer.wots_c_signature.counter,
                    chains: layer
                        .wots_c_signature
                        .chains
                        .iter()
                        .map(|chain| hex_string(chain))
                        .collect(),
                },
                auth_path: layer
                    .auth_path
                    .iter()
                    .map(|node| hex_string(node))
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn signing_key_dto(signing_key: &ShrincsSigningKey) -> ShrincsExportedSigningKey {
    ShrincsExportedSigningKey {
        format_version: SIGNING_KEY_FORMAT_VERSION,
        stateful_sk_seed: hex_string(&signing_key.stateful_sk_seed),
        stateful_prf_seed: hex_string(&signing_key.stateful_prf_seed),
        stateful_pk_seed: hex_string(&signing_key.stateful_pk_seed),
        stateful_root: hex_string(&signing_key.stateful_root),
        max_stateful_signatures: signing_key.max_stateful_signatures,
        next_stateful_leaf_index: signing_key.next_stateful_leaf_index,
        stateless_sk_seed: hex_string(&signing_key.stateless_sk_seed),
        stateless_prf_seed: hex_string(&signing_key.stateless_prf_seed),
        pk_seed: hex_string(&signing_key.pk_seed),
        hypertree_root: hex_string(&signing_key.hypertree_root),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn zeroize_exported_signing_key(exported: &mut ShrincsExportedSigningKey) {
    exported.stateful_sk_seed.zeroize();
    exported.stateful_prf_seed.zeroize();
    exported.stateful_pk_seed.zeroize();
    exported.stateful_root.zeroize();
    exported.stateless_sk_seed.zeroize();
    exported.stateless_prf_seed.zeroize();
    exported.pk_seed.zeroize();
    exported.hypertree_root.zeroize();
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
fn destroyed_handle_error() -> JsValue {
    js_error(WasmErr {
        code: ERR_HANDLE_DESTROYED,
        message: "this keypair handle has been destroyed".to_string(),
    })
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
    use crate::account::INITIAL_STATEFUL_LEAF_INDEX;
    use crate::shrincs::components::public_key::encode_stateful_public_key;
    use crate::shrincs::signers::utils::{derive32, public_key_from_components};
    use crate::shrincs::signers::uxmss::stateful_subtree_root;
    use crate::shrincs::test_fixtures::{
        fixture_entry_opt, fixture_pair, load_fixture_file, stateful_signer_fixture_path,
        TestKeyMode,
    };
    use crate::shrincs::{
        PublicKey as SignerPublicKey, ShrincsSigner, ShrincsSigningKey,
        StatefulSignature as SignerStatefulSignature, StatelessSignature as CoreStatelessSignature,
    };
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::from("0x");
        for byte in bytes {
            use core::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn stateful_signature_dto(signature: &SignerStatefulSignature) -> StatefulSignature {
        StatefulSignature {
            randomizer: hex(&signature.randomizer),
            counter: signature.counter,
            chains: signature.chains.iter().map(|item| hex(item)).collect(),
            auth_path: signature.auth_path.iter().map(|item| hex(item)).collect(),
        }
    }

    fn stateless_signature_dto(
        signature: &CoreStatelessSignature,
    ) -> StatelessSignature {
        StatelessSignature {
            fors: ForsSignature {
                randomizer: hex(&signature.fors.randomizer),
                counter: signature.fors.counter,
                entries: signature
                    .fors
                    .entries
                    .iter()
                    .map(|entry| ForsEntry {
                        secret_leaf: hex(&entry.secret_leaf),
                        auth_path: entry.auth_path.iter().map(|node| hex(node)).collect(),
                    })
                    .collect(),
            },
            hypertree: signature
                .hypertree
                .iter()
                .map(|layer| WasmHypertreeLayerSignature {
                    wots_c_pk_hash: hex(&layer.wots_c_pk_hash),
                    wots_c_signature: WasmWotsCSignature {
                        randomizer: hex(&layer.wots_c_signature.randomizer),
                        counter: layer.wots_c_signature.counter,
                        chains: layer
                            .wots_c_signature
                            .chains
                            .iter()
                            .map(|chain| hex(chain))
                            .collect(),
                    },
                    auth_path: layer.auth_path.iter().map(|node| hex(node)).collect(),
                })
                .collect(),
        }
    }

    fn public_key_dto(public_key: &SignerPublicKey) -> ShrincsPublicKey {
        ShrincsPublicKey {
            stateful_public_key: hex(&public_key.stateful_public_key),
            public_key_commitment: hex(&public_key.public_key_commitment),
            pk_seed: hex(&public_key.pk_seed),
            hypertree_root: hex(&public_key.hypertree_root),
        }
    }

    fn expected_key(public_key: &SignerPublicKey) -> String {
        hex(&public_key.public_key_commitment)
    }

    fn action_context_dto(context: &CoreActionContext) -> ActionContext {
        ActionContext {
            domain_separator: hex(&context.domain_separator),
            nonce: hex(&context.nonce),
            key_version: hex(&context.key_version),
            action_type: hex(&context.action_type),
            payload_hash: hex(&context.payload_hash),
        }
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn rotation_context_dto(
        domain_separator: [u8; HASH_LEN],
        nonce: [u8; HASH_LEN],
        key_version: [u8; HASH_LEN],
    ) -> RotationContext {
        RotationContext {
            domain_separator: hex(&domain_separator),
            nonce: hex(&nonce),
            key_version: hex(&key_version),
        }
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn one_u256_hex() -> String {
        let mut out = [0u8; HASH_LEN];
        out[HASH_LEN - 1] = 1;
        hex_string(&out)
    }

    fn signing_key_and_public_key() -> (ShrincsSigningKey, SignerPublicKey) {
        ShrincsSigner::keygen(b"wasm verifier test seed", 4).unwrap()
    }

    fn stateful_only_key(seed: &[u8], max: u32) -> (ShrincsSigningKey, SignerPublicKey) {
        let stateful_sk_seed = derive32(b"shrincs-stateful-sk-seed", seed, &[]);
        let stateful_prf_seed = derive32(b"shrincs-stateful-prf-seed", seed, &[]);
        let stateful_pk_seed = derive32(b"shrincs-stateful-pk-seed", seed, &[]);
        let stateful_root = stateful_subtree_root(
            &stateful_sk_seed,
            &stateful_pk_seed,
            INITIAL_STATEFUL_LEAF_INDEX,
            max,
        );
        let pk_seed = derive32(b"shrincs-pk-seed", seed, &[]);
        let hypertree_root = derive32(b"placeholder-hypertree-root", seed, &[]);
        let signing_key = ShrincsSigningKey {
            stateful_sk_seed,
            stateful_prf_seed,
            stateful_pk_seed,
            stateful_root,
            max_stateful_signatures: max,
            next_stateful_leaf_index: INITIAL_STATEFUL_LEAF_INDEX,
            stateless_sk_seed: derive32(b"shrincs-stateless-sk-seed", seed, &[]),
            stateless_prf_seed: derive32(b"shrincs-stateless-prf-seed", seed, &[]),
            pk_seed,
            hypertree_root,
        };
        let public_key = public_key_from_components(
            encode_stateful_public_key(stateful_pk_seed, stateful_root, max),
            pk_seed,
            hypertree_root,
        );
        (signing_key, public_key)
    }

    fn stateful_signing_key_and_public_key() -> (ShrincsSigningKey, SignerPublicKey) {
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
    fn parses_prefixed_and_unprefixed_hex() {
        assert_eq!(parse_hex_bytes("0x0102").unwrap(), vec![1u8, 2u8]);
        assert_eq!(parse_hex_bytes("0X0102").unwrap(), vec![1u8, 2u8]); // uppercase prefix
        assert_eq!(parse_hex_bytes("0102").unwrap(), vec![1u8, 2u8]);
        assert!(parse_hex_bytes("0x123").is_err());
        // non-ASCII must return Err gracefully, not panic (wasm trap)
        assert!(parse_hex_bytes("a€").is_err());
        assert!(parse_hex_bytes("€a").is_err());
        assert!(parse_hex_bytes("1€").is_err());
    }

    #[test]
    fn parse_errors_carry_codes_and_do_not_echo_input() {
        // Hex inputs include secret seeds — the input value must never appear
        // in the error message.
        let err = parse_hex_bytes("0xZZ").unwrap_err();
        assert_eq!(err.code, ERR_HEX_INVALID);
        assert!(!err.message.contains("ZZ"));

        let err = parse_hex_bytes("0x123").unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
        assert!(!err.message.contains("123"));

        let err = parse_hex_bytes("a€").unwrap_err();
        assert_eq!(err.code, ERR_HEX_INVALID);
        assert!(!err.message.contains('€'));

        let err = parse_word32("0x0102").unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
        assert!(!err.message.contains("0102"));

        let err = parse_address20("0x0102").unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
        assert!(!err.message.contains("0102"));
    }

    #[test]
    fn seed_floor_rejects_short_seeds_without_echoing_them() {
        // 0 bytes and 31 bytes rejected; 32 bytes accepted.
        let err = validate_seed_length(&[]).unwrap_err();
        assert_eq!(err.code, ERR_SEED_TOO_SHORT);

        let short = [0x42u8; 31];
        let err = validate_seed_length(&short).unwrap_err();
        assert_eq!(err.code, ERR_SEED_TOO_SHORT);
        assert!(!err.message.contains("42"));
        assert!(err.message.contains("31"));

        assert!(validate_seed_length(&[0x42u8; 32]).is_ok());
    }

    #[test]
    fn stateful_raw_at_leaf_helper_verifies_for_requested_leaf() {
        // Mirrors the binding path of `signStatefulRawAt`: sign at a
        // caller-supplied leaf without advancing the counter.
        let (signing_key, public_key) = signing_key_and_public_key();
        let message = b"wasm-stateful-at-leaf-message".to_vec();
        let signature =
            ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 2, &message).unwrap();

        assert_eq!(signature.auth_path.len(), 2);
        let ok = verify_stateful_raw_inner(
            &expected_key(&public_key),
            &public_key_dto(&public_key),
            &hex(&message),
            &stateful_signature_dto(&signature),
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn stateful_raw_helper_verifies_signer_output() {
        let (mut signing_key, public_key) = stateful_signing_key_and_public_key();
        let message = b"wasm-stateful-message".to_vec();
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        let ok = verify_stateful_raw_inner(
            &expected_key(&public_key),
            &public_key_dto(&public_key),
            &hex(&message),
            &stateful_signature_dto(&signature),
        )
        .unwrap();

        assert!(ok);
    }

    #[test]
    fn stateful_action_helper_verifies_signer_output() {
        let verifier = ShrincsVerifier::new();
        let (mut signing_key, public_key) = stateful_signing_key_and_public_key();
        let public_key_dto = public_key_dto(&public_key);
        let expected = expected_key(&public_key);
        let context = CoreActionContext {
            domain_separator: [7u8; HASH_LEN],
            nonce: [1u8; HASH_LEN],
            key_version: [2u8; HASH_LEN],
            action_type: [3u8; HASH_LEN],
            payload_hash: [4u8; HASH_LEN],
        };
        let message =
            verifier.stateful_action_message_hash(parse_word32(&expected).unwrap(), &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        let ok = verify_stateful_action_inner(
            &expected,
            &public_key_dto,
            &action_context_dto(&context),
            &stateful_signature_dto(&signature),
        )
        .unwrap();

        assert!(ok);
    }

    #[cfg_attr(
        any(feature = "profile-128s-q18", feature = "profile-128s-q20"),
        ignore = "128s stateless keygen/signing is compute-infeasible in-process"
    )]
    #[test]
    fn stateless_raw_and_action_helpers_verify_signer_output() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = signing_key_and_public_key();
        let public_key_dto = public_key_dto(&public_key);
        let expected = expected_key(&public_key);

        let raw_message = b"wasm-stateless-message".to_vec();
        let raw_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &raw_message).unwrap();
        assert!(verify_stateless_raw_inner(
            &expected,
            &public_key_dto,
            &hex(&raw_message),
            &stateless_signature_dto(&raw_signature),
        )
        .unwrap());

        let context = CoreActionContext {
            domain_separator: [8u8; HASH_LEN],
            nonce: [9u8; HASH_LEN],
            key_version: [10u8; HASH_LEN],
            action_type: [11u8; HASH_LEN],
            payload_hash: [12u8; HASH_LEN],
        };
        let action_message =
            verifier.stateless_action_message_hash(parse_word32(&expected).unwrap(), &context);
        let action_signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &action_message).unwrap();
        assert!(verify_stateless_action_inner(
            &expected,
            &public_key_dto,
            &action_context_dto(&context),
            &stateless_signature_dto(&action_signature),
        )
        .unwrap());
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_keypair_binding_signs_and_exports_public_key() {
        let mut keypair = shrincs_keygen(
            "0x7761736d2d6b6579706169722d73656564000000000000000000000000000000",
            4,
        )
        .unwrap();
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(keypair.public_key().unwrap()).unwrap();
        let result: StatefulSignResult = serde_wasm_bindgen::from_value(
            keypair
                .sign_stateful_raw("0x7761736d2d6d657373616765")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result.next_stateful_leaf_index, 2); // leaf 1 consumed
        let signature = result.signature;

        let ok = verify_stateful_raw_inner(
            &public_key.public_key_commitment,
            &public_key,
            "0x7761736d2d6d657373616765",
            &signature,
        )
        .unwrap();

        assert!(ok);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_tracks_policy_changes() {
        let keypair = shrincs_keygen(
            "0x7761736d2d6163636f756e742d73656564000000000000000000000000000000",
            4,
        )
        .unwrap();
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(keypair.public_key().unwrap()).unwrap();
        let mut account = WasmShrincsAccount::new(
            &hex_string(&[1u8; HASH_LEN]),
            &hex_string(&[2u8; HASH_LEN]),
            &hex_string(&[7u8; 20]),
            &public_key.public_key_commitment,
        )
        .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.stateful_policy, "monotonic-index");
        assert!(!snapshot.recovery_mode);

        account
            .set_stateful_policy_recovery_rotation(&hex_string(&[1u8; HASH_LEN]))
            .unwrap();
        account
            .enter_recovery_mode(&hex_string(&[1u8; HASH_LEN]))
            .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.stateful_policy, "recovery-rotation");
        assert!(snapshot.recovery_mode);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_verifies_canonical_stateful_action_end_to_end() {
        let mut keypair =
            shrincs_keygen(
                "0x7761736d2d63616e6f6e6963616c2d737461746566756c000000000000000000",
                8,
            )
            .unwrap();
        let public_key_value = keypair.public_key().unwrap();
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key_value.clone()).unwrap();
        let mut account = WasmShrincsAccount::new(
            &hex_string(&[1u8; HASH_LEN]),
            &hex_string(&[2u8; HASH_LEN]),
            &hex_string(&[3u8; 20]),
            &public_key.public_key_commitment,
        )
        .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        let context = ActionContext {
            domain_separator: snapshot.domain_separator,
            nonce: snapshot.nonce,
            key_version: snapshot.key_version,
            action_type: hex_string(&[4u8; HASH_LEN]),
            payload_hash: hex_string(&[5u8; HASH_LEN]),
        };
        let message_hex = shrincs_stateful_action_message_hash(
            &public_key.public_key_commitment,
            serde_wasm_bindgen::to_value(&context).unwrap(),
        )
        .unwrap();
        let result: StatefulSignResult =
            serde_wasm_bindgen::from_value(keypair.sign_stateful_raw(&message_hex).unwrap())
                .unwrap();
        let signature = serde_wasm_bindgen::to_value(&result.signature).unwrap();

        account
            .verify_stateful_action(
                public_key_value,
                &context.action_type,
                &context.payload_hash,
                signature,
            )
            .expect("valid stateful action verifies");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.next_stateful_leaf_index, 2);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_rotates_full_key_via_canonical_recovery_message() {
        let current_keypair =
            shrincs_keygen(
                "0x7761736d2d726f746174696f6e2d63757272656e740000000000000000000000",
                8,
            )
            .unwrap();
        let next_keypair = shrincs_keygen(
            "0x7761736d2d726f746174696f6e2d6e6578740000000000000000000000000000",
            16,
        )
        .unwrap();
        let current_public_key_value = current_keypair.public_key().unwrap();
        let current_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(current_public_key_value.clone()).unwrap();
        let next_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(next_keypair.public_key().unwrap()).unwrap();
        let mut account = WasmShrincsAccount::new(
            &hex_string(&[1u8; HASH_LEN]),
            &hex_string(&[2u8; HASH_LEN]),
            &hex_string(&[3u8; 20]),
            &current_public_key.public_key_commitment,
        )
        .unwrap();

        account
            .set_stateful_policy_recovery_rotation(&hex_string(&[1u8; HASH_LEN]))
            .unwrap();
        account
            .enter_recovery_mode(&hex_string(&[1u8; HASH_LEN]))
            .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        let rotation_context = rotation_context_dto(
            parse_word32(&snapshot.domain_separator).unwrap(),
            parse_word32(&snapshot.nonce).unwrap(),
            parse_word32(&snapshot.key_version).unwrap(),
        );
        let next_target = RotationTarget {
            stateful_public_key: next_public_key.stateful_public_key.clone(),
            public_key_commitment: next_public_key.public_key_commitment.clone(),
            pk_seed: next_public_key.pk_seed.clone(),
            hypertree_root: next_public_key.hypertree_root.clone(),
        };
        let recovery_message_hex = shrincs_full_rotation_message_hash(
            &current_public_key.public_key_commitment,
            current_public_key_value.clone(),
            serde_wasm_bindgen::to_value(&rotation_context).unwrap(),
            serde_wasm_bindgen::to_value(&next_target).unwrap(),
        )
        .unwrap();
        let recovery_signature = current_keypair
            .sign_stateless_raw(&recovery_message_hex)
            .unwrap();

        account
            .rotate_full_key(
                current_public_key_value,
                recovery_signature,
                serde_wasm_bindgen::to_value(&next_target).unwrap(),
            )
            .expect("valid full rotation succeeds");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(
            snapshot.current_shrincs_public_key,
            next_public_key.public_key_commitment
        );
        assert_eq!(snapshot.key_version, one_u256_hex());
        assert_eq!(snapshot.stateful_policy, "monotonic-index");
        assert!(!snapshot.recovery_mode);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_verifies_canonical_stateless_action_end_to_end() {
        let keypair =
            shrincs_keygen(
                "0x7761736d2d63616e6f6e6963616c2d73746174656c6573730000000000000000",
                8,
            )
            .unwrap();
        let public_key_value = keypair.public_key().unwrap();
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key_value.clone()).unwrap();
        let mut account = WasmShrincsAccount::new(
            &hex_string(&[1u8; HASH_LEN]),
            &hex_string(&[2u8; HASH_LEN]),
            &hex_string(&[3u8; 20]),
            &public_key.public_key_commitment,
        )
        .unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        let context = ActionContext {
            domain_separator: snapshot.domain_separator,
            nonce: snapshot.nonce,
            key_version: snapshot.key_version,
            action_type: hex_string(&[6u8; HASH_LEN]),
            payload_hash: hex_string(&[7u8; HASH_LEN]),
        };
        let message_hex = shrincs_stateless_action_message_hash(
            &public_key.public_key_commitment,
            serde_wasm_bindgen::to_value(&context).unwrap(),
        )
        .unwrap();
        let signature = keypair.sign_stateless_raw(&message_hex).unwrap();

        account
            .verify_stateless_action(
                public_key_value,
                &context.action_type,
                &context.payload_hash,
                signature,
            )
            .expect("valid stateless action verifies");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.stateless_signatures_used, 1);
    }

    #[test]
    fn exported_signing_key_parses_back_to_core_key() {
        let (key, _) = signing_key_and_public_key();
        let dto = signing_key_dto(&key);
        assert_eq!(dto.format_version, SIGNING_KEY_FORMAT_VERSION);
        let parsed = parse_exported_signing_key(&dto).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn exported_signing_key_parse_errors_do_not_echo_secrets() {
        let (key, _) = signing_key_and_public_key();
        let mut dto = signing_key_dto(&key);
        let secret = dto.stateful_sk_seed.clone();
        dto.stateful_sk_seed = format!("{}00", secret); // 33 bytes → bad length
        let err = parse_exported_signing_key(&dto).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
        assert!(!err.message.contains(secret.trim_start_matches("0x")));
    }

    #[test]
    fn remaining_stateful_clamps_correctly() {
        assert_eq!(remaining_stateful(4, 1), 4); // fresh
        assert_eq!(remaining_stateful(4, 3), 2); // two spent
        assert_eq!(remaining_stateful(4, 4), 1); // last leaf pending
        assert_eq!(remaining_stateful(4, 5), 0); // exhausted (max + 1)
        assert_eq!(remaining_stateful(4, 0), 4); // degenerate, never reachable via API
    }
}
