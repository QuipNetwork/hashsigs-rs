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

//! Profile-generic body of the wasm surface.
//!
//! Every function here is generic over `P: Profile` plus that profile's two
//! array widths, and none of them mention `wasm_bindgen` or `JsValue`. The
//! concrete `#[wasm_bindgen]` exports are stamped out over one profile by
//! [`crate::wasm::export`]; this module is where the logic lives exactly once.
//!
//! The split exists because `#[wasm_bindgen]` cannot be applied to a generic
//! function: the export boundary needs concrete monomorphic types. Keeping the
//! logic generic and the export layer declarative is what lets the same code
//! serve six profiles.
//!
//! These functions deliberately bypass the `ShrincsVerifier` and
//! `SphincsPlusCVerifier` facades and call the generic free functions those
//! facades wrap. The facades name the build-selected profile, so routing
//! through them would silently pin every verify to that one profile no matter
//! which `P` the caller asked for.

// Under a plain `cargo test` without `wasm-bindings`, the export layer that
// consumes most of these is absent, so all but the directly-tested functions
// read as dead. They are still compiled, which is the point: the cross-profile
// tests in the parent module type-check them at several profiles.
#![cfg_attr(not(feature = "wasm-bindings"), allow(dead_code))]

use crate::profile::Profile;
use crate::shrincs::{
    encode_stateful_envelope, Keys, PublicKey, ShrincsSigner, HASH_LEN, STATEFUL_PUBLIC_KEY_BYTES,
};
use crate::ErrorCode;
use zeroize::Zeroize;

/// Single source of truth for the budget cap: a wasm-local copy could drift
/// silently if core ever retunes the limit.
pub(crate) const MAX_STATEFUL_SIGNATURES_LIMIT: usize =
    crate::shrincs::signer::MAX_STATEFUL_SIGNATURES_LIMIT as usize;

/// Error carrier for the wasm boundary: a stable machine-readable `code` plus
/// a human-readable `message`. Messages must never echo raw caller input
/// (seeds and other secrets would leak into logs/telemetry).
#[derive(Debug)]
pub(crate) struct WasmErr {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

// ── Length-checked field parsers ────────────────────────────────────────
// Profile-independent: every profile shares the 32-byte hash width and the
// flat key layouts below.

/// 32-byte fixed-width field, byte version of `parse_word32`.
pub(crate) fn bytes_word32(input: &[u8]) -> Result<[u8; HASH_LEN], WasmErr> {
    bytes_fixed::<HASH_LEN>(input)
}

/// Byte version of `parse_fixed_hex`: exact-length check, no hex decoding.
pub(crate) fn bytes_fixed<const N: usize>(input: &[u8]) -> Result<[u8; N], WasmErr> {
    if input.len() != N {
        return Err(WasmErr {
            code: ErrorCode::BadLength.as_str(),
            message: format!(
                "expected {N} bytes for fixed-width field, got {}",
                input.len()
            ),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(input);
    Ok(out)
}

/// The 32-byte message every noble-style sign/verify free function operates
/// on. The message IS the hash: callers pre-hash arbitrary-length data and
/// pass the 32-byte digest. SHRINCS stateful adapter operations subsequently
/// bind that digest to the operation, suite, and public-key commitment;
/// standalone SPHINCS+C operations use it directly. A wrong length is an
/// error (for signing) or a rejected verify.
pub(crate) fn message_hash(message: &[u8]) -> Result<[u8; HASH_LEN], WasmErr> {
    bytes_word32(message).map_err(|_| WasmErr {
        code: ErrorCode::BadLength.as_str(),
        message: format!("message must be exactly 32 bytes, got {}", message.len()),
    })
}

/// Parse a SPHINCS+C secret key: `statelessSkSeed(32) ‖ statelessPrfSeed(32)
/// ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 128 bytes total (the field order of
/// `sphincs_plus_c::Key::to_bytes`). The layout carries no profile-dependent
/// width, so this needs no `P`.
pub(crate) fn deserialize_sphincs_plus_c_signing_key(
    bytes: &[u8],
) -> Result<crate::sphincs_plus_c::Key, WasmErr> {
    crate::sphincs_plus_c::Key::from_bytes(bytes).ok_or_else(|| WasmErr {
        code: ErrorCode::BadLength.as_str(),
        message: format!("SPHINCS+C secretKey must be 128 bytes, got {}", bytes.len()),
    })
}

/// `pkSeed ‖ hypertreeRoot` (64 bytes), the verifier-interface public key
/// shape the SPHINCS+C verify entry points expect.
pub(crate) fn encode_sphincs_plus_c_public_key(
    key: &crate::sphincs_plus_c::Key,
) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(64);
    out.extend_from_slice(key.public_key.pk_seed.as_bytes());
    out.extend_from_slice(key.public_key.root.as_bytes());
    out
}

/// SHRINCS secret key: `statefulSkSeed(32) ‖ statefulPrfSeed(32) ‖
/// statefulPkSeed(32) ‖ statefulRoot(32) ‖ maxStatefulSignatures(u32 BE) ‖
/// nextStatefulLeafIndex(u32 BE) ‖ statelessSkSeed(32) ‖ statelessPrfSeed(32)
/// ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 264 bytes total — `Keys::to_bytes`'s
/// flat layout (`stateful(136) ‖ stateless(128)`).
pub(crate) fn serialize_shrincs_signing_key(key: &Keys) -> alloc::vec::Vec<u8> {
    key.to_bytes().to_vec()
}

/// Deserialize the flat layout above WITHOUT validating the roots — callers
/// MUST run the result through `ShrincsSigner::import_signing_key` before
/// trusting it (this only checks the length and slices the fields).
pub(crate) fn deserialize_shrincs_signing_key<P: Profile>(bytes: &[u8]) -> Result<Keys, WasmErr> {
    Keys::from_bytes::<P>(bytes).ok_or_else(|| WasmErr {
        code: ErrorCode::BadLength.as_str(),
        message: format!("shrincs secretKey must be 264 bytes, got {}", bytes.len()),
    })
}

/// Flat concatenation of every `PublicKey` field: `statefulPublicKey(68) ‖
/// publicKeyCommitment(32) ‖ pkSeed(32) ‖ hypertreeRoot(32)`, 164 bytes.
/// Not ABI-encoded (unlike `envelope::encode_*`) — a plain fixed-layout byte
/// bundle for the noble-style keygen/import return value.
pub(crate) fn encode_public_key_flat(public_key: &PublicKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(STATEFUL_PUBLIC_KEY_BYTES + HASH_LEN * 3);
    out.extend_from_slice(&public_key.stateful_public_key);
    out.extend_from_slice(&public_key.public_key_commitment);
    out.extend_from_slice(&public_key.pk_seed);
    out.extend_from_slice(&public_key.hypertree_root);
    out
}

/// The 64-byte stateless public key (`pkSeed ‖ hypertreeRoot`) — the
/// SPHINCS+C key the stateless verify entry points take.
pub(crate) fn encode_stateless_public_key(public_key: &PublicKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(64);
    out.extend_from_slice(&public_key.pk_seed);
    out.extend_from_slice(&public_key.hypertree_root);
    out
}

// ── SPHINCS+C ───────────────────────────────────────────────────────────

/// Derive a SPHINCS+C keypair from a 32-byte seed under profile `P`.
pub(crate) fn sphincs_plus_c_keygen<P: Profile, const NUM_LAYERS: usize>(
    seed: &[u8],
) -> Result<crate::sphincs_plus_c::Key, WasmErr> {
    let mut seed = bytes_fixed::<32>(seed)?;
    let signing_key = crate::sphincs_plus_c::keygen_from_master_seed::<P, NUM_LAYERS>(&seed);
    seed.zeroize();
    Ok(signing_key)
}

/// Sign a 32-byte message with a 128-byte SPHINCS+C secret key under `P`.
pub(crate) fn sphincs_plus_c_sign<P: Profile, const NUM_LAYERS: usize>(
    message: &[u8],
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let full_key = deserialize_sphincs_plus_c_signing_key(secret_key)?;
    let hash = message_hash(message)?;
    let signature =
        crate::sphincs_plus_c::sign::<P, NUM_LAYERS>(&full_key, &hash).ok_or_else(|| WasmErr {
            code: ErrorCode::SigningFailed.as_str(),
            message: "stateless signing failed for the supplied key/message".into(),
        })?;
    Ok(signature.to_bytes())
}

/// Verify a SPHINCS+C stateless signature envelope under `P`. Never fails
/// loudly: a malformed envelope or wrong-length key is simply `false`.
pub(crate) fn sphincs_plus_c_verify<P: Profile, const NUM_CHAINS: usize>(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    if public_key.len() != 64 {
        return false;
    }
    let Some(pk) =
        crate::sphincs_plus_c::PublicKey::from_slices(&public_key[..32], &public_key[32..64])
    else {
        return false;
    };
    let Some(decoded) = crate::sphincs_plus_c::Signature::from_bytes::<P>(signature) else {
        return false;
    };
    crate::sphincs_plus_c::verify_hash::<P, NUM_CHAINS>(&pk, &hash, &decoded)
}

// ── SHRINCS ─────────────────────────────────────────────────────────────

/// Derive a SHRINCS keypair from a 32-byte seed and a stateful leaf budget.
pub(crate) fn shrincs_keygen<P: Profile, const NUM_CHAINS: usize, const NUM_LAYERS: usize>(
    seed: &[u8],
    max_signatures: u32,
) -> Result<(Keys, PublicKey), WasmErr> {
    let mut seed = bytes_fixed::<32>(seed)?;
    if max_signatures == 0 || max_signatures > MAX_STATEFUL_SIGNATURES_LIMIT as u32 {
        return Err(WasmErr {
            code: ErrorCode::InvalidInput.as_str(),
            message: format!("maxSignatures must be in 1..={MAX_STATEFUL_SIGNATURES_LIMIT}"),
        });
    }
    let result = ShrincsSigner::keygen::<P, NUM_CHAINS, NUM_LAYERS>(&seed, max_signatures);
    seed.zeroize();
    result.ok_or_else(|| WasmErr {
        code: ErrorCode::KeygenFailed.as_str(),
        message: "key generation failed for the supplied inputs".into(),
    })
}

/// The `ERR_IMPORT_INVALID` error every import path below raises. One
/// definition so the six call sites cannot drift in wording.
fn import_invalid() -> WasmErr {
    WasmErr {
        code: ErrorCode::ImportInvalid.as_str(),
        message: "secretKey failed validation: counter out of range or roots do not \
                  match the seeds"
            .into(),
    }
}

/// Length-check a 264-byte secret key and revalidate it against its seeds.
/// Every entry point that accepts a persisted secret key goes through here.
pub(crate) fn import_secret_key<P: Profile, const NUM_CHAINS: usize, const NUM_LAYERS: usize>(
    secret_key: &[u8],
) -> Result<(Keys, PublicKey), WasmErr> {
    let candidate = deserialize_shrincs_signing_key::<P>(secret_key)?;
    ShrincsSigner::import_signing_key::<P, NUM_CHAINS, NUM_LAYERS>(candidate)
        .ok_or_else(import_invalid)
}

/// Sign a 32-byte message with the next unused stateful leaf, advancing
/// `secret_key` in place. Returns the commitment-path envelope.
pub(crate) fn shrincs_sign<P: Profile, const NUM_CHAINS: usize, const NUM_LAYERS: usize>(
    message: &[u8],
    secret_key: &mut [u8],
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let (mut signing_key, public_key) = import_secret_key::<P, NUM_CHAINS, NUM_LAYERS>(secret_key)?;
    // Pre-check exhaustion explicitly. Core signals BOTH exhaustion and
    // (astronomically rare) WOTS-C grinding failure as `None`; without this
    // check the two are conflated under one misleading error code.
    if signing_key.stateful().next_leaf_index() > signing_key.stateful().public_key().max_signatures
    {
        return Err(WasmErr {
            code: ErrorCode::StatefulLeavesExhausted.as_str(),
            message: "no unused stateful leaf available for this key".into(),
        });
    }
    let hash = message_hash(message)?;
    let signature =
        ShrincsSigner::sign_stateful_adapter::<P, NUM_CHAINS>(&mut signing_key, &public_key, hash)
            .ok_or_else(|| WasmErr {
                code: ErrorCode::SigningFailed.as_str(),
                message: "stateful signing failed for the supplied key/message".into(),
            })?;
    secret_key.copy_from_slice(&serialize_shrincs_signing_key(&signing_key));
    // Return the PublicKey-carrying envelope, not the bare signature: the
    // verifier pins only the 32-byte commitment, so the signature itself must
    // carry the public key for the verifier to check against it.
    Ok(encode_stateful_envelope(&public_key, &signature))
}

/// Sign a 32-byte message via the stateless recovery path: consumes no leaf
/// and never mutates `secret_key`.
pub(crate) fn shrincs_sign_stateless<
    P: Profile,
    const NUM_CHAINS: usize,
    const NUM_LAYERS: usize,
>(
    message: &[u8],
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let (signing_key, _public_key) = import_secret_key::<P, NUM_CHAINS, NUM_LAYERS>(secret_key)?;
    let hash = message_hash(message)?;
    let signature = ShrincsSigner::sign_stateless_raw::<P, NUM_LAYERS>(&signing_key, &hash)
        .ok_or_else(|| WasmErr {
            code: ErrorCode::SigningFailed.as_str(),
            message: "stateless signing failed for the supplied key/message".into(),
        })?;
    // A SHRINCS stateless signature IS a SPHINCS+C signature over the message,
    // signed under the keypair's embedded stateless key. Return exactly what
    // `sphincs_plus_c_sign` returns (the signature-only encoding) so the
    // stateless verify is a direct SPHINCS+C verify.
    Ok(signature.to_bytes())
}

/// Verify a stateful SHRINCS envelope against a 32-byte commitment under `P`.
/// Never fails loudly — a malformed envelope or commitment mismatch is `false`.
pub(crate) fn shrincs_verify<P: Profile, const NUM_CHAINS: usize>(
    signature: &[u8],
    message: &[u8],
    public_key_commitment: &[u8],
) -> bool {
    let Ok(hash) = message_hash(message) else {
        return false;
    };
    let Some(commitment) =
        crate::shrincs::Commitment::from_bytes(public_key_commitment).map(|c| *c.as_bytes())
    else {
        return false;
    };
    let Some((public_key, decoded)) =
        crate::shrincs::signature::decode_stateful_envelope::<P>(signature)
    else {
        return false;
    };
    let bound_hash = crate::shrincs::stateful_raw_message_hash::<P>(commitment, hash);
    crate::shrincs::verify_stateful_unsafe_raw::<P, NUM_CHAINS>(
        commitment,
        &public_key,
        &bound_hash,
        &decoded,
    )
}

/// Regenerate a fresh stateful chain for a 264-byte secret key, mutating it
/// in place. The stateless half and `maxSignatures` are untouched.
pub(crate) fn shrincs_reset<P: Profile, const NUM_CHAINS: usize, const NUM_LAYERS: usize>(
    secret_key: &mut [u8],
    new_seed: &[u8],
) -> Result<(), WasmErr> {
    // Fail fast on a wrong-length seed, symmetric with keygen.
    let new_seed = bytes_word32(new_seed).map_err(|_| WasmErr {
        code: ErrorCode::BadLength.as_str(),
        message: format!("newSeed must be exactly 32 bytes, got {}", new_seed.len()),
    })?;
    let (mut keys, _public_key) = import_secret_key::<P, NUM_CHAINS, NUM_LAYERS>(secret_key)?;
    keys.reset::<P, NUM_CHAINS>(&new_seed);
    secret_key.copy_from_slice(&serialize_shrincs_signing_key(&keys));
    Ok(())
}

/// Recompute the 32-byte commitment a 264-byte secret key currently implies.
pub(crate) fn shrincs_compute_public_key_commitment<
    P: Profile,
    const NUM_CHAINS: usize,
    const NUM_LAYERS: usize,
>(
    secret_key: &[u8],
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    let (keys, _public_key) = import_secret_key::<P, NUM_CHAINS, NUM_LAYERS>(secret_key)?;
    Ok(keys.recompute_commitment::<P>().as_bytes().to_vec())
}

/// Recover the 32-byte commitment a stateful envelope implies, ecrecover
/// style. The envelope's own commitment field is never trusted — only the
/// value recomputed from the carried public key is returned.
pub(crate) fn shrincs_recover_public_key_commitment<P: Profile>(
    signature: &[u8],
) -> Result<alloc::vec::Vec<u8>, WasmErr> {
    Keys::recover_commitment::<P>(signature)
        .map(|commitment| commitment.as_bytes().to_vec())
        .ok_or_else(|| WasmErr {
            code: ErrorCode::EnvelopeMalformed.as_str(),
            message: "signature envelope could not be decoded".into(),
        })
}
