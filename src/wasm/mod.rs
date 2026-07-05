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

pub use crate::shrincs;
pub use crate::wotsplus;

#[cfg(test)]
use crate::shrincs::signer::verifier::{
    PublicKey as SigningPublicKey, StatefulSignature as SigningStatefulSignature,
    StatelessSignature as SigningStatelessSignature,
};
#[cfg(any(test, feature = "wasm-bindings"))]
use crate::shrincs::{
    ActionContext as CoreActionContext, ForsEntry as CoreForsEntry,
    ForsSignature as CoreForsSignature,
    HypertreeLayerSignature as CoreHypertreeLayerSignature, PublicKey,
    RotationTarget as CoreRotationTarget, ShrincsSigner, ShrincsSigningKey,
    ShrincsVerifier, StatefulRotationTarget as CoreStatefulRotationTarget,
    StatefulSignature as CoreStatefulSignature,
    StatelessSignature as CoreStatelessSignature,
    WotsCSignature as CoreWotsCSignature, HASH_LEN,
};
#[cfg(all(not(test), feature = "wasm-bindings"))]
use crate::shrincs::{
    PublicKey as SigningPublicKey, StatefulSignature as SigningStatefulSignature,
    StatelessSignature as SigningStatelessSignature,
};

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub struct WasmShrincsKeypair {
    signing_key: ShrincsSigningKey,
    public_key: PublicKey,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmShrincsKeypair {
    #[wasm_bindgen(js_name = publicKey, unchecked_return_type = "ShrincsPublicKey")]
    pub fn public_key(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&public_key_dto(&self.public_key))
    }

    #[wasm_bindgen(js_name = signStatefulRaw, unchecked_return_type = "StatefulSignature")]
    pub fn sign_stateful_raw(&mut self, message_hex: &str) -> Result<JsValue, JsValue> {
        let message = parse_hex_bytes(message_hex).map_err(js_error)?;
        let signature = ShrincsSigner::sign_stateful_raw(&mut self.signing_key, &message)
            .ok_or_else(|| {
                js_error("stateful signing failed for the supplied key/message".to_string())
            })?;
        js_value_from_serde(&stateful_signature_dto_from_signer(&signature))
    }

    #[wasm_bindgen(js_name = signStatelessRaw, unchecked_return_type = "StatelessSignature")]
    pub fn sign_stateless_raw(&self, message_hex: &str) -> Result<JsValue, JsValue> {
        let message = parse_hex_bytes(message_hex).map_err(js_error)?;
        let signature =
            ShrincsSigner::sign_stateless_raw(&self.signing_key, &message).ok_or_else(|| {
                js_error("stateless signing failed for the supplied key/message".to_string())
            })?;
        js_value_from_serde(&stateless_signature_dto_from_signer(&signature))
    }

    #[wasm_bindgen(js_name = exportSigningKey, unchecked_return_type = "ShrincsExportedSigningKey")]
    pub fn export_signing_key(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&signing_key_dto(&self.signing_key))
    }
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub struct WasmShrincsAccount {
    inner: crate::account::ShrincsAccountVerifierExample,
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
impl WasmShrincsAccount {
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

    #[wasm_bindgen(js_name = snapshot, unchecked_return_type = "ShrincsAccountSnapshot")]
    pub fn snapshot(&self) -> Result<JsValue, JsValue> {
        js_value_from_serde(&account_snapshot_dto(&self.inner))
    }

    #[wasm_bindgen(js_name = verifyStatefulAction)]
    pub fn verify_stateful_action(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
        action_type_hex: &str,
        payload_hash_hex: &str,
        #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
    ) -> Result<bool, JsValue> {
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
        let signature: StatefulSignature =
            serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
        let public_key = parse_public_key(&public_key).map_err(js_error)?;
        let action_type = parse_word32(action_type_hex).map_err(js_error)?;
        let payload_hash = parse_word32(payload_hash_hex).map_err(js_error)?;
        let signature = parse_stateful_signature(&signature).map_err(js_error)?;
        Ok(self
            .inner
            .verifyStatefulAction(&public_key, action_type, payload_hash, &signature))
    }

    #[wasm_bindgen(js_name = verifyStatelessAction)]
    pub fn verify_stateless_action(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
        action_type_hex: &str,
        payload_hash_hex: &str,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
    ) -> Result<bool, JsValue> {
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
        let signature: StatelessSignature =
            serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
        let public_key = parse_public_key(&public_key).map_err(js_error)?;
        let action_type = parse_word32(action_type_hex).map_err(js_error)?;
        let payload_hash = parse_word32(payload_hash_hex).map_err(js_error)?;
        let signature = parse_stateless_signature(&signature).map_err(js_error)?;
        Ok(self
            .inner
            .verifyStatelessAction(&public_key, action_type, payload_hash, &signature))
    }

    #[wasm_bindgen(js_name = rotateToFreshKey)]
    pub fn rotate_to_fresh_key(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] recovery_signature: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatefulRotationTarget")] next_key: JsValue,
    ) -> Result<bool, JsValue> {
        let current_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(current_public_key).map_err(js_error_from_serde)?;
        let recovery_signature: StatelessSignature =
            serde_wasm_bindgen::from_value(recovery_signature).map_err(js_error_from_serde)?;
        let next_key: StatefulRotationTarget =
            serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde)?;
        let current_public_key = parse_public_key(&current_public_key).map_err(js_error)?;
        let recovery_signature =
            parse_stateless_signature(&recovery_signature).map_err(js_error)?;
        let next_key = parse_stateful_rotation_target(&next_key).map_err(js_error)?;
        Ok(self
            .inner
            .rotateToFreshKey(&current_public_key, &recovery_signature, &next_key))
    }

    #[wasm_bindgen(js_name = rotateFullKey)]
    pub fn rotate_full_key(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] recovery_signature: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RotationTarget")] next_key: JsValue,
    ) -> Result<bool, JsValue> {
        let current_public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(current_public_key).map_err(js_error_from_serde)?;
        let recovery_signature: StatelessSignature =
            serde_wasm_bindgen::from_value(recovery_signature).map_err(js_error_from_serde)?;
        let next_key: RotationTarget =
            serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde)?;
        let current_public_key = parse_public_key(&current_public_key).map_err(js_error)?;
        let recovery_signature =
            parse_stateless_signature(&recovery_signature).map_err(js_error)?;
        let next_key = parse_rotation_target(&next_key).map_err(js_error)?;
        Ok(self
            .inner
            .rotateFullKey(&current_public_key, &recovery_signature, &next_key))
    }

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

    #[wasm_bindgen(js_name = setStatefulPolicyLeafBitmap)]
    pub fn set_stateful_policy_leaf_bitmap(&mut self, caller_hex: &str) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .setStatefulPolicyLeafBitmap(caller)
            .map_err(account_error_to_js)
    }

    #[wasm_bindgen(js_name = enterRecoveryMode)]
    pub fn enter_recovery_mode(&mut self, caller_hex: &str) -> Result<(), JsValue> {
        let caller = parse_word32(caller_hex).map_err(js_error)?;
        self.inner
            .enterRecoveryMode(caller)
            .map_err(account_error_to_js)
    }
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsKeygen)]
pub fn shrincs_keygen(
    seed_hex: &str,
    max_stateful_signatures: u32,
) -> Result<WasmShrincsKeypair, JsValue> {
    let seed_material = parse_hex_bytes(seed_hex).map_err(js_error)?;
    let (signing_key, public_key) = ShrincsSigner::keygen(&seed_material, max_stateful_signatures)
        .ok_or_else(|| js_error("key generation failed for the supplied inputs".to_string()))?;
    Ok(WasmShrincsKeypair {
        signing_key,
        public_key: parse_public_key(&public_key_dto_from_signer(&public_key)).map_err(js_error)?,
    })
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulActionMessageHash)]
pub fn shrincs_stateful_action_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<String, JsValue> {
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    stateful_action_message_hash_inner(expected_public_key_commitment_hex, &context)
        .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatelessActionMessageHash)]
pub fn shrincs_stateless_action_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
) -> Result<String, JsValue> {
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    stateless_action_message_hash_inner(expected_public_key_commitment_hex, &context)
        .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsStatefulRotationMessageHash)]
pub fn shrincs_stateful_rotation_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulRotationTarget")] next_key: JsValue,
) -> Result<String, JsValue> {
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key).map_err(js_error_from_serde)?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let next_key: StatefulRotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde)?;
    stateful_rotation_message_hash_inner(
        expected_public_key_commitment_hex,
        &current_public_key,
        &context,
        &next_key,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsFullRotationMessageHash)]
pub fn shrincs_full_rotation_message_hash(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] current_public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RotationTarget")] next_key: JsValue,
) -> Result<String, JsValue> {
    let current_public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(current_public_key).map_err(js_error_from_serde)?;
    let context: RotationContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let next_key: RotationTarget =
        serde_wasm_bindgen::from_value(next_key).map_err(js_error_from_serde)?;
    full_rotation_message_hash_inner(
        expected_public_key_commitment_hex,
        &current_public_key,
        &context,
        &next_key,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulRaw)]
pub fn shrincs_verify_stateful_raw(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateful_raw_inner(
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatefulAction)]
pub fn shrincs_verify_stateful_action(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatefulSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let signature: StatefulSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateful_action_inner(
        expected_public_key_commitment_hex,
        &public_key,
        &context,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessRaw)]
pub fn shrincs_verify_stateless_raw(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    message_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
    verify_stateless_raw_inner(
        expected_public_key_commitment_hex,
        &public_key,
        message_hex,
        &signature,
    )
    .map_err(js_error)
}

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(js_name = shrincsVerifyStatelessAction)]
pub fn shrincs_verify_stateless_action(
    expected_public_key_commitment_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "ShrincsPublicKey")] public_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ActionContext")] context: JsValue,
    #[wasm_bindgen(unchecked_param_type = "StatelessSignature")] signature: JsValue,
) -> Result<bool, JsValue> {
    let public_key: ShrincsPublicKey =
        serde_wasm_bindgen::from_value(public_key).map_err(js_error_from_serde)?;
    let context: ActionContext =
        serde_wasm_bindgen::from_value(context).map_err(js_error_from_serde)?;
    let signature: StatelessSignature =
        serde_wasm_bindgen::from_value(signature).map_err(js_error_from_serde)?;
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
    stateful_public_key: String,
    public_key_commitment: String,
    pk_seed: String,
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
pub struct WotsCSignature {
    randomizer: String,
    counter: u32,
    chains: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct HypertreeLayerSignature {
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "bigint"))]
    tree_index: u64,
    leaf_index: u32,
    wots_c_pk_hash: String,
    wots_c_signature: WotsCSignature,
    auth_path: Vec<String>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct StatelessSignature {
    fors: ForsSignature,
    hypertree: Vec<HypertreeLayerSignature>,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ShrincsExportedSigningKey {
    stateful_sk_seed: String,
    stateful_prf_seed: String,
    stateful_pk_seed: String,
    stateful_root: String,
    max_stateful_signatures: u32,
    next_stateful_leaf_index: u32,
    stateless_sk_seed: String,
    stateless_prf_seed: String,
    pk_seed: String,
    hypertree_root: String,
}

#[cfg(any(test, feature = "wasm-bindings"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[serde(rename_all = "camelCase")]
pub struct ShrincsAccountSnapshot {
    current_shrincs_public_key: String,
    owner: String,
    chain_id: String,
    contract_address: String,
    domain_separator: String,
    nonce: String,
    key_version: String,
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "bigint"))]
    stateless_signatures_used: u64,
    stateful_policy: String,
    next_stateful_leaf_index: u32,
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
) -> Result<bool, String> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes(message_hex)?;
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
) -> Result<String, String> {
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
) -> Result<String, String> {
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
) -> Result<String, String> {
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
) -> Result<String, String> {
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
) -> Result<bool, String> {
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
) -> Result<bool, String> {
    let expected_public_key_commitment = parse_word32(expected_public_key_commitment_hex)?;
    let public_key = parse_public_key(public_key)?;
    let message = parse_hex_bytes(message_hex)?;
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
) -> Result<bool, String> {
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
fn parse_public_key(input: &ShrincsPublicKey) -> Result<PublicKey, String> {
    Ok(PublicKey {
        stateful_public_key: parse_hex_bytes(&input.stateful_public_key)?,
        public_key_commitment: parse_hex_bytes(&input.public_key_commitment)?,
        pk_seed: parse_hex_bytes(&input.pk_seed)?,
        hypertree_root: parse_hex_bytes(&input.hypertree_root)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_action_context(input: &ActionContext) -> Result<CoreActionContext, String> {
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
) -> Result<crate::shrincs::RotationContext, String> {
    Ok(crate::shrincs::RotationContext {
        domain_separator: parse_word32(&input.domain_separator)?,
        nonce: parse_word32(&input.nonce)?,
        key_version: parse_word32(&input.key_version)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateful_signature(input: &StatefulSignature) -> Result<CoreStatefulSignature, String> {
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

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_stateless_signature(input: &StatelessSignature) -> Result<CoreStatelessSignature, String> {
    Ok(CoreStatelessSignature {
        fors: CoreForsSignature {
            randomizer: parse_hex_bytes(&input.fors.randomizer)?,
            counter: input.fors.counter,
            entries: input
                .fors
                .entries
                .iter()
                .map(|entry| {
                    Ok(CoreForsEntry {
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
                Ok(CoreHypertreeLayerSignature {
                    tree_index: layer.tree_index,
                    leaf_index: layer.leaf_index,
                    wots_c_pk_hash: parse_hex_bytes(&layer.wots_c_pk_hash)?,
                    wots_c_signature: CoreWotsCSignature {
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
fn parse_stateful_rotation_target(
    input: &StatefulRotationTarget,
) -> Result<CoreStatefulRotationTarget, String> {
    Ok(CoreStatefulRotationTarget {
        stateful_public_key: parse_hex_bytes(&input.stateful_public_key)?,
        public_key_commitment: parse_hex_bytes(&input.public_key_commitment)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_rotation_target(input: &RotationTarget) -> Result<CoreRotationTarget, String> {
    Ok(CoreRotationTarget {
        stateful_public_key: parse_hex_bytes(&input.stateful_public_key)?,
        public_key_commitment: parse_hex_bytes(&input.public_key_commitment)?,
        pk_seed: parse_hex_bytes(&input.pk_seed)?,
        hypertree_root: parse_hex_bytes(&input.hypertree_root)?,
    })
}

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_word32(input: &str) -> Result<[u8; HASH_LEN], String> {
    let bytes = parse_hex_bytes(input)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        format!(
            "expected {} bytes for fixed-width field, got {}",
            HASH_LEN, len
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

#[cfg(any(test, feature = "wasm-bindings"))]
fn parse_address20(input: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex_bytes(input)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("expected 20 bytes for address field, got {len}"))
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
            .map(|layer| HypertreeLayerSignature {
                tree_index: layer.tree_index,
                leaf_index: layer.leaf_index,
                wots_c_pk_hash: hex_string(&layer.wots_c_pk_hash),
                wots_c_signature: WotsCSignature {
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
fn js_error(message: String) -> JsValue {
    JsValue::from_str(&message)
}

#[cfg(feature = "wasm-bindings")]
fn js_error_from_serde(error: serde_wasm_bindgen::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(feature = "wasm-bindings")]
fn account_error_to_js(error: crate::account::AccountError) -> JsValue {
    let message = match error {
        crate::account::AccountError::OnlyOwner => "only owner may perform this action",
        crate::account::AccountError::RecoveryPolicyRequired => {
            "recovery policy must be active before entering recovery mode"
        }
        crate::account::AccountError::StatefulIndexRollback => {
            "stateful monotonic leaf index rollback is not allowed"
        }
        crate::account::AccountError::StatefulPolicyFrozen => {
            "stateful policy changes are frozen after the first successful stateful use in a key epoch"
        }
    };
    JsValue::from_str(message)
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
    value.serialize(&serializer).map_err(js_error_from_serde)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::signer::verifier::{
        PublicKey as SignerPublicKey, StatefulSignature as SignerStatefulSignature,
    };
    use crate::shrincs::{ShrincsSigner, ShrincsSigningKey};
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    wasm_bindgen_test_configure!(run_in_browser);

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
        signature: &crate::shrincs::signer::verifier::StatelessSignature,
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
                .map(|layer| HypertreeLayerSignature {
                    tree_index: layer.tree_index,
                    leaf_index: layer.leaf_index,
                    wots_c_pk_hash: hex(&layer.wots_c_pk_hash),
                    wots_c_signature: WotsCSignature {
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
        let mut keypair = shrincs_keygen("0x7761736d2d6b6579706169722d73656564", 4).unwrap();
        let public_key: ShrincsPublicKey =
            serde_wasm_bindgen::from_value(keypair.public_key().unwrap()).unwrap();
        let signature: StatefulSignature = serde_wasm_bindgen::from_value(
            keypair
                .sign_stateful_raw("0x7761736d2d6d657373616765")
                .unwrap(),
        )
        .unwrap();

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
        let keypair = shrincs_keygen("0x7761736d2d6163636f756e742d73656564", 4).unwrap();
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
            shrincs_keygen("0x7761736d2d63616e6f6e6963616c2d737461746566756c", 8).unwrap();
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
        let signature = keypair.sign_stateful_raw(&message_hex).unwrap();

        assert!(account
            .verify_stateful_action(
                public_key_value,
                &context.action_type,
                &context.payload_hash,
                signature,
            )
            .unwrap());

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.next_stateful_leaf_index, 2);
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn wasm_account_binding_rotates_full_key_via_canonical_recovery_message() {
        let current_keypair =
            shrincs_keygen("0x7761736d2d726f746174696f6e2d63757272656e74", 8).unwrap();
        let next_keypair = shrincs_keygen("0x7761736d2d726f746174696f6e2d6e657874", 16).unwrap();
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

        assert!(account
            .rotate_full_key(
                current_public_key_value,
                recovery_signature,
                serde_wasm_bindgen::to_value(&next_target).unwrap(),
            )
            .unwrap());

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
            shrincs_keygen("0x7761736d2d63616e6f6e6963616c2d73746174656c657373", 8).unwrap();
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

        assert!(account
            .verify_stateless_action(
                public_key_value,
                &context.action_type,
                &context.payload_hash,
                signature,
            )
            .unwrap());

        let snapshot: ShrincsAccountSnapshot =
            serde_wasm_bindgen::from_value(account.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.nonce, one_u256_hex());
        assert_eq!(snapshot.stateless_signatures_used, 1);
    }
}
