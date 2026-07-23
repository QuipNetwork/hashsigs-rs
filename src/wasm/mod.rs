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
use crate::verifier::VerifierInterface as _;
use crate::shrincs::{
    ActionContext as CoreActionContext, ForsEntry as CoreForsEntry,
    ForsSignature as CoreForsSignature,
    HypertreeLayerSignature as CoreHypertreeLayerSignature, PublicKey,
    RotationTarget as CoreRotationTarget, ShrincsSigner,
    ShrincsSigningKey, ShrincsVerifier, StatefulRotationTarget as CoreStatefulRotationTarget,
    StatefulSignature as CoreStatefulSignature,
    StatelessSignature as CoreStatelessSignature,
    STATEFUL_PUBLIC_KEY_BYTES,
    WotsCSignature as CoreWotsCSignature, FORS_TREE_HEIGHT, HASH_LEN,
    HYPERTREE_HEIGHT, NUM_FORS_TREES, NUM_HYPERTREE_LAYERS, NUM_WOTS_CHAINS,
    WOTS_CHAINS_STATEFUL,
};
// The Uint8Array-native noble-style free functions (sphincsPlusC*/shrincs
// keygen/sign/verify) work directly with the independent SPHINCS+C layer and
// the shared scheme-hash, rather than going through the hex DTO plumbing
// above.
#[cfg(any(test, feature = "wasm-bindings"))]
#[cfg(any(test, feature = "wasm-bindings"))]
use crate::sphincs_plus_c::SphincsPlusCSigningKey;
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
  | "ERR_HEX_INVALID" | "ERR_BAD_LENGTH" | "ERR_ONLY_OWNER"
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

    /// Verify a stateful action signature against the account's canonical
    /// action hash and enforce the stateful policy. Resolves on success and
    /// advances account state; THROWS a typed `ShrincsErrorCode` on malformed
    /// input OR on rejection — e.g. `ERR_INVALID_SIGNATURE` for a bad
    /// signature, `ERR_STATEFUL_LEAF_REJECTED` / `ERR_STATEFUL_PATH_DISABLED`
    /// for a policy-blocked leaf.
    ///
    /// * `action_type` - 32 bytes (bytes32).
    /// * `payload_hash` - 32 bytes (bytes32).
    #[wasm_bindgen(js_name = verifyStatefulAction)]
    pub fn verify_stateful_action(
        &mut self,
        action_type: &[u8],
        payload_hash: &[u8],
        envelope: &[u8],
    ) -> Result<(), JsValue> {
        // `envelope` is the stateful signature envelope `shrincs.sign` produces
        // (ABI-encoded PublicKey + StatefulSignature); decode it directly into
        // the core types the account verifier consumes.
        let (public_key, signature) =
            crate::envelope::decode_stateful_envelope(envelope).ok_or_else(malformed_envelope)?;
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
    #[wasm_bindgen(js_name = verifyStatelessAction)]
    pub fn verify_stateless_action(
        &mut self,
        action_type: &[u8],
        payload_hash: &[u8],
        envelope: &[u8],
    ) -> Result<(), JsValue> {
        // `envelope` is the stateless signature envelope `shrincs.signStateless`
        // produces (ABI-encoded PublicKey + StatelessSignature).
        let (public_key, signature) =
            crate::envelope::decode_stateless_envelope(envelope).ok_or_else(malformed_envelope)?;
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
    #[wasm_bindgen(js_name = rotateToFreshKey)]
    pub fn rotate_to_fresh_key(
        &mut self,
        recovery_envelope: &[u8],
        next_public_key: &[u8],
    ) -> Result<(), JsValue> {
        // The recovery envelope (from `shrincs.signStateless`) carries the
        // current public key that authorizes the rotation plus the stateless
        // signature. `next_public_key` is the replacement keypair's 164-byte
        // flat publicKey; the stateful rotation target is its leading
        // statefulPublicKey(68) and commitment(32).
        let (current_public_key, recovery_signature) =
            crate::envelope::decode_stateless_envelope(recovery_envelope)
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
    #[wasm_bindgen(js_name = rotateFullKey)]
    pub fn rotate_full_key(
        &mut self,
        recovery_envelope: &[u8],
        next_public_key: &[u8],
    ) -> Result<(), JsValue> {
        // Full rotation replaces the whole bundle: `next_public_key` is the
        // replacement keypair's 164-byte flat publicKey, which is exactly a
        // RotationTarget (statefulPublicKey(68)‖commitment(32)‖pkSeed(32)‖
        // hypertreeRoot(32)).
        let (current_public_key, recovery_signature) =
            crate::envelope::decode_stateless_envelope(recovery_envelope)
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

    /// ERC-1271 compatibility view: verify a mode-prefixed action envelope
    /// against the account's current state WITHOUT mutating it (no leaf
    /// commit, no nonce advance, no stateless-budget consumption). Resolves
    /// on success; THROWS a typed `ShrincsErrorCode` on rejection —
    /// `ERR_MALFORMED_SIGNATURE` for an empty/unrecognized/malformed
    /// envelope, `ERR_INVALID_SIGNATURE` for a well-formed but invalid or
    /// mismatched-hash signature, plus the same policy codes as
    /// `verifyStatefulAction` / `verifyStatelessAction`.
    ///
    /// * `hash` - 32 bytes (bytes32); the hash the signature must authorize.
    /// * `signature` - the mode-prefixed ERC-1271 envelope, arbitrary length.
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
    let (signing_key, _public_key) =
        crate::sphincs_plus_c::keygen(stateless_sk_seed, stateless_prf_seed, pk_seed);
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
    let hash = message_hash(message).map_err(js_error)?;
    let signature = crate::sphincs_plus_c::sign(&signing_key, &hash).ok_or_else(|| {
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
/// ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 264 bytes total — the exact field
/// order of `ShrincsSigningKey`.
#[cfg(any(test, feature = "wasm-bindings"))]
fn serialize_shrincs_signing_key(key: &ShrincsSigningKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(264);
    out.extend_from_slice(&key.stateful_sk_seed);
    out.extend_from_slice(&key.stateful_prf_seed);
    out.extend_from_slice(&key.stateful_pk_seed);
    out.extend_from_slice(&key.stateful_root);
    out.extend_from_slice(&key.max_stateful_signatures.to_be_bytes());
    out.extend_from_slice(&key.next_stateful_leaf_index.to_be_bytes());
    out.extend_from_slice(&key.stateless_sk_seed);
    out.extend_from_slice(&key.stateless_prf_seed);
    out.extend_from_slice(&key.pk_seed);
    out.extend_from_slice(&key.hypertree_root);
    out
}

/// Deserialize the flat layout above WITHOUT validating the roots — callers
/// MUST run the result through `ShrincsSigner::import_signing_key` before
/// trusting it (this only checks the length and slices the fields).
#[cfg(any(test, feature = "wasm-bindings"))]
fn deserialize_shrincs_signing_key(bytes: &[u8]) -> Result<ShrincsSigningKey, WasmErr> {
    if bytes.len() != 264 {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("shrincs secretKey must be 264 bytes, got {}", bytes.len()),
        });
    }
    let max_stateful_signatures = u32::from_be_bytes(bytes_fixed::<4>(&bytes[128..132])?);
    let next_stateful_leaf_index = u32::from_be_bytes(bytes_fixed::<4>(&bytes[132..136])?);
    Ok(ShrincsSigningKey {
        stateful_sk_seed: bytes_word32(&bytes[0..32])?,
        stateful_prf_seed: bytes_word32(&bytes[32..64])?,
        stateful_pk_seed: bytes_word32(&bytes[64..96])?,
        stateful_root: bytes_word32(&bytes[96..128])?,
        max_stateful_signatures,
        next_stateful_leaf_index,
        stateless_sk_seed: bytes_word32(&bytes[136..168])?,
        stateless_prf_seed: bytes_word32(&bytes[168..200])?,
        pk_seed: bytes_word32(&bytes[200..232])?,
        hypertree_root: bytes_word32(&bytes[232..264])?,
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
    signing_key: ShrincsSigningKey,
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
    let (mut signing_key, public_key) =
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
    if signing_key.next_stateful_leaf_index > signing_key.max_stateful_signatures {
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
    let envelope = crate::envelope::encode_stateful_envelope(&public_key, &signature);
    secret_key.copy_from_slice(&serialize_shrincs_signing_key(&signing_key));
    Ok(envelope)
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
    let (signing_key, public_key) =
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
    // `ShrincsVerifier::verify_stateless_envelope` decodes a full `(PublicKey,
    // SPHINCSPlusC.Signature)` envelope — it re-derives and checks the
    // commitment before delegating to `SphincsPlusCVerifier` — NOT the
    // signature-only envelope `sphincsPlusCSign` produces. Using the wrong
    // encoder here made `shrincsVerifyStateless` reject every signature.
    Ok(crate::envelope::encode_stateless_envelope(&public_key, &signature))
}

/// Verify a SHRINCS stateful signature envelope (`shrincsSign`'s output)
/// over the 32-byte `message` against a 32-byte
/// `publicKeyCommitment`. Never throws — a malformed envelope or
/// wrong-length key is simply `false`.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerify)]
pub fn shrincs_verify(signature: &[u8], message: &[u8], public_key_commitment: &[u8]) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    ShrincsVerifier::new().verify_envelope(public_key_commitment, &hash, signature)
        == crate::verifier::VerifyOutcome::Valid
}

/// Verify a SHRINCS stateless signature envelope (`shrincsSignStateless`'s
/// output) over the 32-byte `message` against a 32-byte
/// `publicKeyCommitment`. Never throws.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStateless)]
pub fn shrincs_verify_stateless(
    signature: &[u8],
    message: &[u8],
    public_key_commitment: &[u8],
) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    ShrincsVerifier::new().verify_stateless_envelope(public_key_commitment, &hash, signature)
        == crate::verifier::VerifyOutcome::Valid
}

// ── Verifier-interface / account surface (hex DTOs, params bytes-ified) ──

/// Canonical message hash a stateful action signature must sign for the given
/// commitment and context.
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulActionMessageHash)]
pub fn shrincs_stateful_action_message_hash(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let expected_public_key_commitment = bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    stateful_action_message_hash_inner(expected_public_key_commitment, &context).map_err(js_error)
}

/// Canonical message hash a stateless action signature must sign for the given
/// commitment and context.
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatelessActionMessageHash)]
pub fn shrincs_stateless_action_message_hash(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let expected_public_key_commitment = bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    stateless_action_message_hash_inner(expected_public_key_commitment, &context).map_err(js_error)
}

/// Canonical message hash authorizing a fresh-stateful-key rotation
/// (`rotateToFreshKey`).
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulRotationMessageHash)]
pub fn shrincs_stateful_rotation_message_hash(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulRotationTarget")] next_key: JsValue,
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let expected_public_key_commitment = bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key)
            .map_err(js_error_from_serde("currentPublicKey"))?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let next_key: StatefulRotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
    stateful_rotation_message_hash_inner(
        expected_public_key_commitment,
        &current_public_key,
        &context,
        &next_key,
    )
    .map_err(js_error)
}

/// Canonical message hash authorizing a full key-bundle rotation
/// (`rotateFullKey`).
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsFullRotationMessageHash)]
pub fn shrincs_full_rotation_message_hash(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationTarget")] next_key: JsValue,
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let expected_public_key_commitment = bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key)
            .map_err(js_error_from_serde("currentPublicKey"))?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let next_key: RotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde("nextKey"))?;
    full_rotation_message_hash_inner(
        expected_public_key_commitment,
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
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
/// * `message` - arbitrary length.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulRaw)]
pub fn shrincs_verify_stateful_raw(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message: &[u8],
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let expected_public_key_commitment =
        bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateful_raw_inner(expected_public_key_commitment, &public_key, message, &signature)
        .map_err(js_error)
}

/// Verify a stateful signature over the canonical action hash for `context`.
/// Returns `true`/`false` for a cryptographically valid/invalid signature;
/// THROWS only on malformed input, never for an invalid signature.
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulAction)]
pub fn shrincs_verify_stateful_action(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let expected_public_key_commitment =
        bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateful_action_inner(expected_public_key_commitment, &public_key, &context, &signature)
        .map_err(js_error)
}

/// Verify a stateless signature over raw message bytes. Returns `true`/`false`
/// for a cryptographically valid/invalid signature; THROWS only on malformed
/// input (bad hex / wrong-length fields), never for an invalid signature.
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
/// * `message` - arbitrary length.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessRaw)]
pub fn shrincs_verify_stateless_raw(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message: &[u8],
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let expected_public_key_commitment =
        bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateless_raw_inner(expected_public_key_commitment, &public_key, message, &signature)
        .map_err(js_error)
}

/// Verify a stateless signature over the canonical action hash for `context`.
/// Returns `true`/`false` for a cryptographically valid/invalid signature;
/// THROWS only on malformed input, never for an invalid signature.
///
/// * `expected_public_key_commitment` - 32 bytes (bytes32).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessAction)]
pub fn shrincs_verify_stateless_action(
    expected_public_key_commitment: &[u8],
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let expected_public_key_commitment =
        bytes_word32(expected_public_key_commitment).map_err(js_error)?;
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde("publicKey"))?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde("context"))?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde("signature"))?;
    verify_stateless_action_inner(
        expected_public_key_commitment,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

/// the verifier interface SHRINCS stateful verify (`ShrincsVerifier::verify`):
/// `key` is the 32-byte SHRINCS `publicKeyCommitment`, `signature` is
/// `abi.encode(PublicKey, SHRINCS.Signature)` (no mode prefix — this is NOT
/// the account wrapper's ERC-1271 envelope; see
/// `WasmShrincsAccount::isValidSignature` for that shape). `hash` is the
/// already-32-byte digest (NOT hashed again — unlike the noble-style
/// `shrincsVerify`, which takes an arbitrary message). Returns `true`/`false`
/// for a well-formed valid/invalid signature (or a wrong-length key); THROWS
/// `ERR_ENVELOPE_MALFORMED` only when the envelope framing itself cannot be
/// decoded.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyEnvelope)]
pub fn shrincs_verify_envelope(key: &[u8], hash: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    shrincs_verify_envelope_inner(key, hash, signature).map_err(js_error)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn shrincs_verify_envelope_inner(key: &[u8], hash: &[u8], signature: &[u8]) -> Result<bool, WasmErr> {
    require_max_len(key, MAX_RAW_INPUT_BYTES)?;
    require_max_len(signature, MAX_RAW_INPUT_BYTES)?;
    let hash = bytes_word32(hash)?;
    match crate::shrincs::ShrincsVerifier::new().verify_envelope(key, &hash, signature) {
        crate::shrincs::VerifyOutcome::Valid => Ok(true),
        crate::shrincs::VerifyOutcome::Invalid => Ok(false),
        crate::shrincs::VerifyOutcome::Malformed => Err(WasmErr {
            code: ERR_ENVELOPE_MALFORMED,
            message: "the verifier interface stateful envelope could not be decoded".into(),
        }),
    }
}

/// the verifier interface SHRINCS stateless verify (`ShrincsVerifier::verify_stateless`):
/// `key` is the 32-byte SHRINCS `publicKeyCommitment`, `signature` is
/// `abi.encode(PublicKey, SPHINCSPlusC.Signature)`. Delegates to the pinned
/// `SphincsPlusCVerifier` internally, mirroring
/// `SHRINCSVerifier.verifyStateless`. `hash` is the already-32-byte digest
/// (NOT hashed again). Returns `true`/`false` for a well-formed
/// valid/invalid signature (or a wrong-length key); THROWS
/// `ERR_ENVELOPE_MALFORMED` only when the envelope framing itself cannot be
/// decoded.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessEnvelope)]
pub fn shrincs_verify_stateless_envelope(
    key: &[u8],
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    shrincs_verify_stateless_envelope_inner(key, hash, signature).map_err(js_error)
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn shrincs_verify_stateless_envelope_inner(
    key: &[u8],
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, WasmErr> {
    require_max_len(key, MAX_RAW_INPUT_BYTES)?;
    require_max_len(signature, MAX_RAW_INPUT_BYTES)?;
    let hash = bytes_word32(hash)?;
    match crate::shrincs::ShrincsVerifier::new().verify_stateless_envelope(key, &hash, signature) {
        crate::shrincs::VerifyOutcome::Valid => Ok(true),
        crate::shrincs::VerifyOutcome::Invalid => Ok(false),
        crate::shrincs::VerifyOutcome::Malformed => Err(WasmErr {
            code: ERR_ENVELOPE_MALFORMED,
            message: "the verifier interface stateless envelope could not be decoded".into(),
        }),
    }
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
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &ShrincsPublicKey,
    message: &[u8],
    signature: &StatefulSignature,
) -> Result<bool, WasmErr> {
    require_max_len(message, MAX_RAW_INPUT_BYTES)?;
    let public_key = parse_public_key(public_key)?;
    let signature = parse_stateful_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateful_unsafe_raw(
        expected_public_key_commitment,
        &public_key,
        message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_action_message_hash_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let context = parse_action_context(context)?;
    Ok(ShrincsVerifier::new()
        .stateful_action_message_hash(expected_public_key_commitment, &context)
        .to_vec())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateless_action_message_hash_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    context: &ActionContext,
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let context = parse_action_context(context)?;
    Ok(ShrincsVerifier::new()
        .stateless_action_message_hash(expected_public_key_commitment, &context)
        .to_vec())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn stateful_rotation_message_hash_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &ShrincsPublicKey,
    context: &RotationContext,
    next_key: &StatefulRotationTarget,
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let current_public_key = parse_public_key(current_public_key)?;
    let context = parse_rotation_context(context)?;
    let next_key = parse_stateful_rotation_target(next_key)?;
    Ok(ShrincsVerifier::new()
        .stateful_rotation_message_hash(
            expected_public_key_commitment,
            &current_public_key,
            &context,
            &next_key,
        )
        .to_vec())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn full_rotation_message_hash_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    current_public_key: &ShrincsPublicKey,
    context: &RotationContext,
    next_key: &RotationTarget,
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let current_public_key = parse_public_key(current_public_key)?;
    let context = parse_rotation_context(context)?;
    let next_key = parse_rotation_target(next_key)?;
    Ok(ShrincsVerifier::new()
        .full_rotation_message_hash(
            expected_public_key_commitment,
            &current_public_key,
            &context,
            &next_key,
        )
        .to_vec())
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateful_action_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &ShrincsPublicKey,
    context: &ActionContext,
    signature: &StatefulSignature,
) -> Result<bool, WasmErr> {
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
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &ShrincsPublicKey,
    message: &[u8],
    signature: &StatelessSignature,
) -> Result<bool, WasmErr> {
    require_max_len(message, MAX_RAW_INPUT_BYTES)?;
    let public_key = parse_public_key(public_key)?;
    let signature = parse_stateless_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateless_unsafe_raw(
        expected_public_key_commitment,
        &public_key,
        message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateless_action_inner(
    expected_public_key_commitment: [u8; HASH_LEN],
    public_key: &ShrincsPublicKey,
    context: &ActionContext,
    signature: &StatelessSignature,
) -> Result<bool, WasmErr> {
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
        secret_leaf: parse_word32(&entry.secret_leaf)?,
        auth_path: entry
            .auth_path
            .iter()
            .map(|node| parse_word32(node))
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
        wots_c_pk_hash: parse_word32(&layer.wots_c_pk_hash)?,
        wots_c_signature: CoreWotsCSignature {
            randomizer: parse_word32(&layer.wots_c_signature.randomizer)?,
            counter: layer.wots_c_signature.counter,
            chains: layer
                .wots_c_signature
                .chains
                .iter()
                .map(|chain| parse_word32(chain))
                .collect::<Result<Vec<_>, _>>()?,
        },
        auth_path: layer
            .auth_path
            .iter()
            .map(|node| parse_word32(node))
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
            randomizer: parse_word32(&input.fors.randomizer)?,
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
    if !trimmed.len().is_multiple_of(2) {
        return Err(WasmErr {
            code: ERR_BAD_LENGTH,
            message: format!("hex string must have even length (got {} chars)", trimmed.len()),
        });
    }
    Ok(trimmed)
}

#[cfg(test)]
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

#[cfg(test)]
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

    /// The 32-byte `publicKeyCommitment`, in the `[u8; HASH_LEN]` shape the
    /// (now byte-native) verify/message-hash `_inner` helpers take directly.
    fn expected_key(public_key: &SignerPublicKey) -> [u8; HASH_LEN] {
        public_key.public_key_commitment.as_slice().try_into().unwrap()
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

    use crate::test_support::stateful_only_key;


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

    #[test]
    fn stateful_raw_at_leaf_helper_verifies_for_requested_leaf() {
        // Mirrors the noble-style `shrincsSign` path: sign at a caller-supplied
        // leaf without advancing the counter.
        let (signing_key, public_key) = signing_key_and_public_key();
        let message = b"wasm-stateful-at-leaf-message".to_vec();
        let signature =
            ShrincsSigner::sign_stateful_raw_at_leaf(&signing_key, 2, &message).unwrap();

        assert_eq!(signature.auth_path.len(), 2);
        let ok = verify_stateful_raw_inner(
            expected_key(&public_key),
            &public_key_dto(&public_key),
            &message,
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
            expected_key(&public_key),
            &public_key_dto(&public_key),
            &message,
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
        let message = verifier.stateful_action_message_hash(expected, &context);
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        let ok = verify_stateful_action_inner(
            expected,
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
            expected,
            &public_key_dto,
            &raw_message,
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
        let action_message = verifier.stateless_action_message_hash(expected, &context);
        let action_signature =
            ShrincsSigner::sign_stateless_raw(&signing_key, &action_message).unwrap();
        assert!(verify_stateless_action_inner(
            expected,
            &public_key_dto,
            &action_context_dto(&context),
            &stateless_signature_dto(&action_signature),
        )
        .unwrap());
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
    // above; ts/test/'s node conformance suite covers these same error
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
        let public_key_commitment = keys.public_key_commitment();
        assert_eq!(secret_key.len(), 264);
        assert_eq!(public_key_commitment.len(), 32);

        let message = [0x03u8; 32].to_vec();
        let signature = shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(shrincs_verify(&signature, &message, &public_key_commitment));
        assert!(!shrincs_verify(&signature, &[0xEEu8; 32], &public_key_commitment));

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!shrincs_verify(&tampered, &message, &public_key_commitment));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_sign_advances_secret_key_in_place_across_two_signatures() {
        let seed = [0x44u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let public_key_commitment = keys.public_key_commitment();
        let before = secret_key.clone();

        let message = [0x04u8; 32].to_vec();
        let first = shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(secret_key, before, "secretKey must mutate in place after sign");
        assert!(shrincs_verify(&first, &message, &public_key_commitment));

        let after_first = secret_key.clone();
        let second = shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(secret_key, after_first, "secretKey must advance again on the next sign");
        assert_ne!(first, second, "two leaves must yield distinct signatures");
        assert!(shrincs_verify(&second, &message, &public_key_commitment));
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
        let public_key_commitment = keys.public_key_commitment();
        let before = secret_key.clone();

        let message = [0x05u8; 32].to_vec();
        let signature = shrincs_sign_stateless(&message, &secret_key).unwrap();
        assert_eq!(secret_key, before, "stateless sign must not mutate secretKey");
        assert!(shrincs_verify_stateless(&signature, &message, &public_key_commitment));
        assert!(!shrincs_verify_stateless(
            &signature,
            &[0xEEu8; 32],
            &public_key_commitment,
        ));
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
            stateless_sk_seed: key.stateless_sk_seed,
            stateless_prf_seed: key.stateless_prf_seed,
            pk_seed: key.pk_seed,
            hypertree_root: key.hypertree_root,
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
    // the noble-style `shrincsKeygen`/`shrincsSign` free functions: they
    // exist to exercise `WasmShrincsAccount`, which still speaks the hex-DTO
    // `ShrincsPublicKey`/`StatefulSignature`/`StatelessSignature` shapes (see
    // the wasm-noble delivery report on scope). The noble free functions
    // themselves are covered by the `shrincs_noble_*` / `sphincs_plus_c_noble_*`
    // tests above and by ts/test/'s node conformance suite.

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
        let public_key_dto = public_key_dto(&public_key);
        let public_key_value = serde_wasm_bindgen::to_value(&public_key_dto).unwrap();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
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
        let message = shrincs_stateful_action_message_hash(
            &public_key.public_key_commitment,
            serde_wasm_bindgen::to_value(&context).unwrap(),
        )
        .unwrap();
        let core_signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();
        let signature = serde_wasm_bindgen::to_value(&stateful_signature_dto(&core_signature)).unwrap();
        let action_type = parse_word32(&context.action_type).unwrap();
        let payload_hash = parse_word32(&context.payload_hash).unwrap();

        account
            .verify_stateful_action(public_key_value, &action_type, &payload_hash, signature)
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
        let current_public_key_dto = public_key_dto(&current_public_key);
        let current_public_key_value = serde_wasm_bindgen::to_value(&current_public_key_dto).unwrap();
        let next_public_key_dto = public_key_dto(&next_public_key);
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
            &current_public_key.public_key_commitment,
        )
        .unwrap();

        account.set_stateful_policy_recovery_rotation(&[1u8; HASH_LEN]).unwrap();
        account.enter_recovery_mode(&[1u8; HASH_LEN]).unwrap();

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        let rotation_context = rotation_context_dto(
            parse_word32(&snapshot.domain_separator).unwrap(),
            parse_word32(&snapshot.nonce).unwrap(),
            parse_word32(&snapshot.key_version).unwrap(),
        );
        let next_target = RotationTarget {
            stateful_public_key: next_public_key_dto.stateful_public_key.clone(),
            public_key_commitment: next_public_key_dto.public_key_commitment.clone(),
            pk_seed: next_public_key_dto.pk_seed.clone(),
            hypertree_root: next_public_key_dto.hypertree_root.clone(),
        };
        let recovery_message = shrincs_full_rotation_message_hash(
            &current_public_key.public_key_commitment,
            current_public_key_value.clone(),
            serde_wasm_bindgen::to_value(&rotation_context).unwrap(),
            serde_wasm_bindgen::to_value(&next_target).unwrap(),
        )
        .unwrap();
        let core_recovery_signature =
            ShrincsSigner::sign_stateless_raw(&current_signing_key, &recovery_message).unwrap();
        let recovery_signature =
            serde_wasm_bindgen::to_value(&stateless_signature_dto(&core_recovery_signature)).unwrap();

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
            next_public_key_dto.public_key_commitment
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
        let public_key_dto = public_key_dto(&public_key);
        let public_key_value = serde_wasm_bindgen::to_value(&public_key_dto).unwrap();
        let mut account = WasmShrincsAccount::new(
            &[1u8; HASH_LEN],
            &[2u8; HASH_LEN],
            &[3u8; 20],
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
        let message = shrincs_stateless_action_message_hash(
            &public_key.public_key_commitment,
            serde_wasm_bindgen::to_value(&context).unwrap(),
        )
        .unwrap();
        let core_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &message).unwrap();
        let signature = serde_wasm_bindgen::to_value(&stateless_signature_dto(&core_signature)).unwrap();
        let action_type = parse_word32(&context.action_type).unwrap();
        let payload_hash = parse_word32(&context.payload_hash).unwrap();

        account
            .verify_stateless_action(public_key_value, &action_type, &payload_hash, signature)
            .expect("valid stateless action verifies");

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.stateless_signatures_used, 1);
    }
}
