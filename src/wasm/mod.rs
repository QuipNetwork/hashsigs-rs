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

//! WASM-oriented surface for `hashsigs-rs`.
//!
//! The first exported bindings are verifier-only and TS-friendly:
//! callers pass hex strings plus plain JS objects that mirror the SHRINCS
//! public-key / signature shapes.

pub use crate::shrincs;
pub use crate::wotsplus;

#[cfg(any(test, feature = "wasm-bindings"))]
use crate::shrincs::{
    ActionContext, ForsEntry, ForsSignature, HypertreeLayerSignature, ParameterSetId, PublicKey,
    ShrincsVerifier, StatefulSignature, StatelessSignature, WotsCSignature, HASH_LEN,
};

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm-bindings", wasm_bindgen)]
pub fn supported_parameter_sets() -> Vec<String> {
    vec!["sphincs-256s-keccak-q20".to_string()]
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn shrincs_verify_stateful_raw(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: JsValue,
    message_hex: &str,
    signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: WasmPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let signature: WasmStatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateful_raw_inner(
        parameter_set_id,
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn shrincs_verify_stateful_action(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: JsValue,
    context: JsValue,
    signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: WasmPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let context: WasmActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let signature: WasmStatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateful_action_inner(
        parameter_set_id,
        expected_public_key_commitment_hex,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn shrincs_verify_stateless_raw(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: JsValue,
    message_hex: &str,
    signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: WasmPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let signature: WasmStatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateless_raw_inner(
        parameter_set_id,
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn shrincs_verify_stateless_action(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: JsValue,
    context: JsValue,
    signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: WasmPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let context: WasmActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let signature: WasmStatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateless_action_inner(
        parameter_set_id,
        expected_public_key_commitment_hex,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmPublicKey {
    parameter_set_id: String,
    stateful_public_key: String,
    public_key_commitment: String,
    pk_seed: String,
    hypertree_root: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmActionContext {
    domain_separator: String,
    nonce: String,
    key_version: String,
    action_type: String,
    payload_hash: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmStatefulSignature {
    randomizer: String,
    counter: u32,
    chains: Vec<String>,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmForsEntry {
    secret_leaf: String,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmForsSignature {
    randomizer: String,
    counter: u32,
    entries: Vec<WasmForsEntry>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmWotsCSignature {
    randomizer: String,
    counter: u32,
    chains: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmHypertreeLayerSignature {
    tree_index: u64,
    leaf_index: u32,
    wots_c_pk_hash: String,
    wots_c_signature: WasmWotsCSignature,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WasmStatelessSignature {
    fors: WasmForsSignature,
    hypertree: Vec<WasmHypertreeLayerSignature>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateful_raw_inner(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: &WasmPublicKey,
    message_hex: &str,
    signature: &WasmStatefulSignature,
) -> Result<bool, String> {
    let parameter_set_id = parse_parameter_set_id(parameter_set_id)?;
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes(message_hex)?;
    let signature = parse_stateful_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateful_unsafe_raw(
        parameter_set_id,
        expected_public_key_commitment,
        &public_key,
        &message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateful_action_inner(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: &WasmPublicKey,
    context: &WasmActionContext,
    signature: &WasmStatefulSignature,
) -> Result<bool, String> {
    let parameter_set_id = parse_parameter_set_id(parameter_set_id)?;
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let context = parse_action_context(context)?;
    let signature = parse_stateful_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateful(
        parameter_set_id,
        expected_public_key_commitment,
        &public_key,
        &context,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateless_raw_inner(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: &WasmPublicKey,
    message_hex: &str,
    signature: &WasmStatelessSignature,
) -> Result<bool, String> {
    let parameter_set_id = parse_parameter_set_id(parameter_set_id)?;
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes(message_hex)?;
    let signature = parse_stateless_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateless_unsafe_raw(
        parameter_set_id,
        expected_public_key_commitment,
        &public_key,
        &message,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn verify_stateless_action_inner(
    parameter_set_id: &str,
    expected_public_key_commitment_hex: &str,
    public_key: &WasmPublicKey,
    context: &WasmActionContext,
    signature: &WasmStatelessSignature,
) -> Result<bool, String> {
    let parameter_set_id = parse_parameter_set_id(parameter_set_id)?;
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let context = parse_action_context(context)?;
    let signature = parse_stateless_signature(signature)?;

    Ok(ShrincsVerifier::new().verify_stateless(
        parameter_set_id,
        expected_public_key_commitment,
        &public_key,
        &context,
        &signature,
    ))
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_public_key(input: &WasmPublicKey) -> Result<PublicKey, String> {
    Ok(PublicKey {
        parameter_set_id: parse_parameter_set_id(&input.parameter_set_id)?,
        stateful_public_key: parse_hex_bytes(&input.stateful_public_key)?,
        public_key_commitment: parse_hex_bytes(&input.public_key_commitment)?,
        pk_seed: parse_hex_bytes(&input.pk_seed)?,
        hypertree_root: parse_hex_bytes(&input.hypertree_root)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_action_context(input: &WasmActionContext) -> Result<ActionContext, String> {
    Ok(ActionContext {
        domain_separator: parse_word32(&input.domain_separator)?,
        nonce: parse_word32(&input.nonce)?,
        key_version: parse_word32(&input.key_version)?,
        action_type: parse_word32(&input.action_type)?,
        payload_hash: parse_word32(&input.payload_hash)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateful_signature(input: &WasmStatefulSignature) -> Result<StatefulSignature, String> {
    Ok(StatefulSignature {
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

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateless_signature(input: &WasmStatelessSignature) -> Result<StatelessSignature, String> {
    Ok(StatelessSignature {
        fors: ForsSignature {
            randomizer: parse_hex_bytes(&input.fors.randomizer)?,
            counter: input.fors.counter,
            entries: input
                .fors
                .entries
                .iter()
                .map(|entry| {
                    Ok(ForsEntry {
                        secret_leaf: parse_hex_bytes(&entry.secret_leaf)?,
                        auth_path: entry
                            .auth_path
                            .iter()
                            .map(|node| parse_hex_bytes(node))
                            .collect::<Result<Vec<_>, _>>()?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        },
        hypertree: input
            .hypertree
            .iter()
            .map(|layer| {
                Ok(HypertreeLayerSignature {
                    tree_index: layer.tree_index,
                    leaf_index: layer.leaf_index,
                    wots_c_pk_hash: parse_hex_bytes(&layer.wots_c_pk_hash)?,
                    wots_c_signature: WotsCSignature {
                        randomizer: parse_hex_bytes(&layer.wots_c_signature.randomizer)?,
                        counter: layer.wots_c_signature.counter,
                        chains: layer
                            .wots_c_signature
                            .chains
                            .iter()
                            .map(|chain| parse_hex_bytes(chain))
                            .collect::<Result<Vec<_>, _>>()?,
                    },
                    auth_path: layer
                        .auth_path
                        .iter()
                        .map(|node| parse_hex_bytes(node))
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_parameter_set_id(input: &str) -> Result<ParameterSetId, String> {
    match input {
        "sphincs-256s-keccak-q20" | "Sphincs256sKeccakQ20" => {
            Ok(ParameterSetId::Sphincs256sKeccakQ20)
        }
        "unsupported" | "Unsupported" => Ok(ParameterSetId::Unsupported),
        _ => Err(format!("unsupported parameter set id: {input}")),
    }
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_word32(input: &str) -> Result<[u8; HASH_LEN], String> {
    let bytes = parse_hex_bytes(input)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        format!(
            "expected {} bytes for fixed-width field, got {}",
            HASH_LEN,
            len
        )
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() % 2 != 0 {
        return Err(format!("hex string must have even length: {input}"));
    }

    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for index in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[index..index + 2], 16)
            .map_err(|_| format!("invalid hex at byte offset {}", index / 2))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(feature = "wasm-bindings")]
fn js_error(message: String) -> JsValue {
    JsValue::from_str(&message)
}

#[cfg(feature = "wasm-bindings")]
fn js_error_from_serde(error: serde_wasm_bindgen::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::signer::verifier::{
        ParameterSetId as SignerParameterSetId, PublicKey as SignerPublicKey,
        StatefulSignature as SignerStatefulSignature,
    };
    use crate::shrincs::{ShrincsSigner, ShrincsSigningKey};

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::from("0x");
        for byte in bytes {
            use core::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    fn stateful_signature_dto(signature: &SignerStatefulSignature) -> WasmStatefulSignature {
        WasmStatefulSignature {
            randomizer: hex(&signature.randomizer),
            counter: signature.counter,
            chains: signature.chains.iter().map(|item| hex(item)).collect(),
            auth_path: signature.auth_path.iter().map(|item| hex(item)).collect(),
        }
    }

    fn stateless_signature_dto(signature: &crate::shrincs::signer::verifier::StatelessSignature) -> WasmStatelessSignature {
        WasmStatelessSignature {
            fors: WasmForsSignature {
                randomizer: hex(&signature.fors.randomizer),
                counter: signature.fors.counter,
                entries: signature
                    .fors
                    .entries
                    .iter()
                    .map(|entry| WasmForsEntry {
                        secret_leaf: hex(&entry.secret_leaf),
                        auth_path: entry.auth_path.iter().map(|node| hex(node)).collect(),
                    })
                    .collect(),
            },
            hypertree: signature
                .hypertree
                .iter()
                .map(|layer| WasmHypertreeLayerSignature {
                    tree_index: layer.tree_index,
                    leaf_index: layer.leaf_index,
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

    fn public_key_dto(public_key: &SignerPublicKey) -> WasmPublicKey {
        WasmPublicKey {
            parameter_set_id: "sphincs-256s-keccak-q20".to_string(),
            stateful_public_key: hex(&public_key.stateful_public_key),
            public_key_commitment: hex(&public_key.public_key_commitment),
            pk_seed: hex(&public_key.pk_seed),
            hypertree_root: hex(&public_key.hypertree_root),
        }
    }

    fn expected_key(public_key: &SignerPublicKey) -> String {
        hex(&public_key.public_key_commitment)
    }

    fn action_context_dto(context: &ActionContext) -> WasmActionContext {
        WasmActionContext {
            domain_separator: hex(&context.domain_separator),
            nonce: hex(&context.nonce),
            key_version: hex(&context.key_version),
            action_type: hex(&context.action_type),
            payload_hash: hex(&context.payload_hash),
        }
    }

    fn signing_key_and_public_key() -> (ShrincsSigningKey, SignerPublicKey) {
        ShrincsSigner::keygen(
            SignerParameterSetId::Sphincs256sKeccakQ20,
            b"wasm verifier test seed",
            4,
        )
        .unwrap()
    }

    #[test]
    fn parses_prefixed_and_unprefixed_hex() {
        assert_eq!(parse_hex_bytes("0x0102").unwrap(), vec![1u8, 2u8]);
        assert_eq!(parse_hex_bytes("0102").unwrap(), vec![1u8, 2u8]);
        assert!(parse_hex_bytes("0x123").is_err());
    }

    #[test]
    fn stateful_raw_helper_verifies_signer_output() {
        let (mut signing_key, public_key) = signing_key_and_public_key();
        let message = b"wasm-stateful-message".to_vec();
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        let ok = verify_stateful_raw_inner(
            "sphincs-256s-keccak-q20",
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
        let (mut signing_key, public_key) = signing_key_and_public_key();
        let public_key_dto = public_key_dto(&public_key);
        let expected = expected_key(&public_key);
        let context = ActionContext {
            domain_separator: [7u8; HASH_LEN],
            nonce: [1u8; HASH_LEN],
            key_version: [2u8; HASH_LEN],
            action_type: [3u8; HASH_LEN],
            payload_hash: [4u8; HASH_LEN],
        };
        let message = verifier.stateful_action_message_hash(
            ParameterSetId::Sphincs256sKeccakQ20,
            parse_word32(&expected).unwrap(),
            &context,
        );
        let signature = ShrincsSigner::sign_stateful_raw(&mut signing_key, &message).unwrap();

        let ok = verify_stateful_action_inner(
            "sphincs-256s-keccak-q20",
            &expected,
            &public_key_dto,
            &action_context_dto(&context),
            &stateful_signature_dto(&signature),
        )
        .unwrap();

        assert!(ok);
    }

    #[test]
    fn stateless_raw_and_action_helpers_verify_signer_output() {
        let verifier = ShrincsVerifier::new();
        let (signing_key, public_key) = signing_key_and_public_key();
        let public_key_dto = public_key_dto(&public_key);
        let expected = expected_key(&public_key);

        let raw_message = b"wasm-stateless-message".to_vec();
        let raw_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &raw_message).unwrap();
        assert!(verify_stateless_raw_inner(
            "sphincs-256s-keccak-q20",
            &expected,
            &public_key_dto,
            &hex(&raw_message),
            &stateless_signature_dto(&raw_signature),
        )
        .unwrap());

        let context = ActionContext {
            domain_separator: [8u8; HASH_LEN],
            nonce: [9u8; HASH_LEN],
            key_version: [10u8; HASH_LEN],
            action_type: [11u8; HASH_LEN],
            payload_hash: [12u8; HASH_LEN],
        };
        let action_message = verifier.stateless_action_message_hash(
            ParameterSetId::Sphincs256sKeccakQ20,
            parse_word32(&expected).unwrap(),
            &context,
        );
        let action_signature = ShrincsSigner::sign_stateless_raw(&signing_key, &action_message).unwrap();
        assert!(verify_stateless_action_inner(
            "sphincs-256s-keccak-q20",
            &expected,
            &public_key_dto,
            &action_context_dto(&context),
            &stateless_signature_dto(&action_signature),
        )
        .unwrap());
    }
}
