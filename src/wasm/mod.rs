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
//! ImportSigningKey,Reset,ComputePublicKeyCommitment,
//! RecoverPublicKeyCommitment}`).

#[cfg(any(test, feature = "wasm-bindings"))]
use crate::verifier::VerifierInterface as _;
use crate::shrincs::{
    Keys, PublicKey, ShrincsSigner, ShrincsVerifier, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES,
};
// The Uint8Array-native noble-style free functions (sphincsPlusC*/shrincs
// keygen/sign/verify) work directly with the independent SPHINCS+C layer and
// the shared scheme-hash, rather than going through the hex DTO plumbing
// above.
#[cfg(any(test, feature = "wasm-bindings"))]
use zeroize::Zeroize;

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

// Machine-readable error codes surfaced to JS as `error.code`. Frozen API once
// published: additions are safe, renames/removals are breaking.
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_BAD_LENGTH: &str = "ERR_BAD_LENGTH";
#[cfg(any(test, feature = "wasm-bindings"))]
const ERR_STATEFUL_LEAVES_EXHAUSTED: &str = "ERR_STATEFUL_LEAVES_EXHAUSTED";
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
  | "ERR_BAD_LENGTH" | "ERR_STATEFUL_LEAVES_EXHAUSTED"
  | "ERR_SIGNING_FAILED" | "ERR_KEYGEN_FAILED" | "ERR_INVALID_INPUT"
  | "ERR_IMPORT_INVALID"
  | "ERR_ENVELOPE_MALFORMED";
"#;

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

/// Parse a SPHINCS+C secret key: `statelessSkSeed(32) ‖ statelessPrfSeed(32)
/// ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 128 bytes total (the field order of
/// `sphincs_plus_c::Key::to_bytes`).
#[cfg(any(test, feature = "wasm-bindings"))]
fn deserialize_sphincs_plus_c_signing_key(
    bytes: &[u8],
) -> Result<crate::sphincs_plus_c::Key, WasmErr> {
    crate::sphincs_plus_c::Key::from_bytes(bytes).ok_or_else(|| WasmErr {
        code: ERR_BAD_LENGTH,
        message: format!("SPHINCS+C secretKey must be 128 bytes, got {}", bytes.len()),
    })
}

/// A generated SPHINCS+C keypair: `secretKey` is the 128-byte flat
/// serialization above; `publicKey` is `pkSeed ‖ hypertreeRoot` (64 bytes,
/// the verifier-interface key shape `sphincsPlusCVerify` expects).
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub struct WasmSphincsPlusCKeys {
    signing_key: crate::sphincs_plus_c::Key,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmSphincsPlusCKeys {
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> alloc::vec::Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(64);
        out.extend_from_slice(self.signing_key.public_key.pk_seed.as_bytes());
        out.extend_from_slice(self.signing_key.public_key.root.as_bytes());
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
    let signing_key =
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
    let full_key = deserialize_sphincs_plus_c_signing_key(secret_key).map_err(js_error)?;
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
/// flat layout (`stateful(136) ‖ stateless(128)`).
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
/// spent. Returns the commitment-path envelope (`PublicKey ‖ StatefulSignature`)
/// `shrincsVerify` expects — the signature carries the full public key so a
/// verifier holding only the 32-byte `publicKeyCommitment` can check it.
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
    // Return the PublicKey-carrying envelope, not the bare signature:
    // `shrincsVerify` pins only the 32-byte commitment, so the signature
    // itself must carry the public key for the verifier to check against it.
    Ok(crate::envelope::encode_stateful_envelope(&public_key, &signature))
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

/// Verify a SHRINCS stateful signature (`shrincsSign`'s output, which carries
/// the full public key) over the 32-byte `message` against a 32-byte
/// `publicKeyCommitment` — the commitment-path shape: the verifier pins only
/// the commitment, decodes the public key the envelope carries, checks it
/// hashes to that commitment, then verifies. Never throws — a malformed
/// signature, wrong-length commitment, or commitment mismatch is simply
/// `false`.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerify)]
pub fn shrincs_verify(signature: &[u8], message: &[u8], public_key_commitment: &[u8]) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    ShrincsVerifier::new().verify_envelope(public_key_commitment, &hash, signature)
        == crate::verifier::VerifyOutcome::Valid
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

/// Regenerate a fresh stateful chain for a 264-byte `secretKey`, discarding
/// any relationship to prior stateful signatures (e.g. after suspected leaf
/// reuse). `secretKey` is re-validated via `ShrincsSigner::import_signing_key`
/// and then MUTATED IN PLACE with the new stateful seeds and a reset leaf
/// counter — the caller's `keys.secretKey` Uint8Array changes after this
/// call, and its `publicKeyCommitment` changes with it (the stateless half
/// and `maxSignatures` are untouched). `newSeed` is arbitrary-length seed
/// material; this wasm build has no RNG, so the caller must supply fresh
/// entropy.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsReset)]
pub fn shrincs_reset(secret_key: &mut [u8], new_seed: &[u8]) -> Result<(), JsValue> {
    let candidate = deserialize_shrincs_signing_key(secret_key).map_err(js_error)?;
    let (mut keys, _public_key) = ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_IMPORT_INVALID,
            message: "secretKey failed validation: counter out of range or roots do not \
                      match the seeds"
                .into(),
        })
    })?;
    keys.reset(new_seed);
    secret_key.copy_from_slice(&serialize_shrincs_signing_key(&keys));
    Ok(())
}

/// Recompute the 32-byte `publicKeyCommitment` a 264-byte `secretKey`
/// currently implies. `secretKey` is re-validated via
/// `ShrincsSigner::import_signing_key`; never mutates it. Equivalent to
/// `shrincsImportSigningKey(secretKey).publicKeyCommitment` without
/// constructing the intermediate `WasmShrincsKeys`.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsComputePublicKeyCommitment)]
pub fn shrincs_compute_public_key_commitment(
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    let candidate = deserialize_shrincs_signing_key(secret_key).map_err(js_error)?;
    let (keys, _public_key) = ShrincsSigner::import_signing_key(candidate).ok_or_else(|| {
        js_error(WasmErr {
            code: ERR_IMPORT_INVALID,
            message: "secretKey failed validation: counter out of range or roots do not \
                      match the seeds"
                .into(),
        })
    })?;
    Ok(keys.recompute_commitment().as_bytes().to_vec())
}

/// Recover the 32-byte `publicKeyCommitment` a `shrincsSign` envelope
/// implies, ecrecover-style: decode the envelope's carried public key and
/// recompute the commitment from it. The envelope's own commitment field is
/// never trusted — only the recomputed value is returned. Throws
/// `ERR_ENVELOPE_MALFORMED` if `signature` is not a well-formed
/// `shrincsSign` envelope.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsRecoverPublicKeyCommitment)]
pub fn shrincs_recover_public_key_commitment(
    signature: &[u8],
) -> Result<alloc::vec::Vec<u8>, JsValue> {
    Keys::recover_commitment(signature)
        .map(|commitment| commitment.as_bytes().to_vec())
        .ok_or_else(malformed_envelope)
}

/// Build the `malformed envelope` error `shrincsRecoverPublicKeyCommitment`
/// raises when ABI framing cannot be decoded.
#[cfg(feature = "wasm-bindings")]
fn malformed_envelope() -> JsValue {
    js_error(WasmErr {
        code: ERR_ENVELOPE_MALFORMED,
        message: "signature envelope could not be decoded".into(),
    })
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
    // wasm-bindgen-test harness; ts/test/'s node conformance suite covers
    // these same error codes against the real compiled wasm.
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
        let public_key_commitment = keys.public_key_commitment();
        assert_eq!(secret_key.len(), 264);
        assert_eq!(public_key.len(), 164);

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
    fn shrincs_noble_verify_rejects_wrong_public_key_commitment() {
        let seed = [0x55u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let real_commitment = keys.public_key_commitment();

        let message = [0x05u8; 32].to_vec();
        let signature = shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(shrincs_verify(&signature, &message, &real_commitment));

        // The envelope carries the full PublicKey; `shrincsVerify` must check
        // that it actually hashes to the supplied commitment, not just that
        // the signature verifies under whatever PublicKey it happens to
        // carry. A wrong-but-well-formed 32-byte commitment must fail even
        // though the signature and message are untouched.
        let mut wrong_commitment = real_commitment.clone();
        wrong_commitment[0] ^= 1;
        assert!(!shrincs_verify(&signature, &message, &wrong_commitment));

        assert!(!shrincs_verify(&signature, &message, &[0xFFu8; 32]));
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

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_reset_changes_commitment_keeps_stateless_and_still_signs() {
        let seed = [0x88u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let stateless_public_key = keys.stateless_public_key();
        let original_commitment = keys.public_key_commitment();

        shrincs_reset(&mut secret_key, b"a fresh reset seed").unwrap();

        let reset_commitment =
            shrincs_compute_public_key_commitment(&secret_key).unwrap();
        assert_ne!(reset_commitment, original_commitment);

        let reimported = shrincs_import_signing_key(&secret_key).unwrap();
        assert_eq!(reimported.public_key_commitment(), reset_commitment);
        assert_eq!(
            reimported.stateless_public_key(),
            stateless_public_key,
            "reset must not touch the stateless half"
        );

        let message = [0x09u8; 32].to_vec();
        let signature = shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(shrincs_verify(&signature, &message, &reset_commitment));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_compute_public_key_commitment_matches_keygen() {
        let seed = [0x99u8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let commitment = shrincs_compute_public_key_commitment(&secret_key).unwrap();
        assert_eq!(commitment, keys.public_key_commitment());
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_recover_public_key_commitment_matches_signer() {
        let seed = [0xaau8; 32];
        let keys = shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let expected_commitment = keys.public_key_commitment();

        let message = [0x0au8; 32].to_vec();
        let signature = shrincs_sign(&message, &mut secret_key).unwrap();

        let recovered = shrincs_recover_public_key_commitment(&signature).unwrap();
        assert_eq!(recovered, expected_commitment);
    }

    // `.unwrap_err()`/`error.code` on the rejection path needs a real JS
    // engine (see the comment on `sphincs_plus_c_noble_keygen_rejects_wrong_length_seed`
    // above) — wasm32-gated.
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn shrincs_noble_recover_public_key_commitment_rejects_garbage_envelope() {
        let err = expect_err(shrincs_recover_public_key_commitment(&[0u8; 4]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ERR_ENVELOPE_MALFORMED,
        );
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
        let spk = key.stateless.clone();
        let bytes = spk.to_bytes();
        assert_eq!(bytes.len(), 128);
        let parsed = deserialize_sphincs_plus_c_signing_key(&bytes).unwrap();
        assert_eq!(parsed, spk);

        let err = deserialize_sphincs_plus_c_signing_key(&bytes[..127]).unwrap_err();
        assert_eq!(err.code, ERR_BAD_LENGTH);
    }
}
