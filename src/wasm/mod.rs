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
//! RecoverPublicKeyCommitment}`), plus `version()` and `profileName()`.
//!
//! It is split in two. [`crate::bindings`] holds every operation generic over
//! `P: Profile` and that profile's two array widths, with no `wasm_bindgen` in
//! sight, shared with the Python bindings. [`export`] holds the macro that
//! stamps those operations out as concrete `#[wasm_bindgen]` items for one
//! profile. This module invokes that macro exactly once, over the
//! build-selected profile.
//!
//! One binary therefore carries one profile, and the npm package ships six
//! binaries — one per subpath export — so a browser consumer downloads only
//! the profile it imports. `profileName()` reports which one a loaded binary
//! is, because all six export identical names.

#[cfg(feature = "wasm-bindings")]
mod export;

#[cfg(any(test, feature = "wasm-bindings"))]
use crate::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};

#[cfg(feature = "wasm-bindings")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm-bindings")]
use crate::bindings::BindingError;

// Plain constant so `typescript_union_lists_every_error_code` (below) can read
// it under a native test build. `#[wasm_bindgen(typescript_custom_section)]`
// does not just annotate a const, it consumes the item entirely (the const
// exists only to hand its value to the wasm-bindgen CLI's `.d.ts` generator),
// so a single item cannot be both wasm_bindgen-registered and visible to
// ordinary Rust code. The `feature = "wasm-bindings"`-only const just below
// re-exports this same value to keep that registration; on a non-test build
// of that feature, this constant's only reader is that const's initializer,
// and the macro consumes the reference along with the rest of that item, so
// the compiler cannot see it and misreports this as dead code.
#[cfg(any(test, feature = "wasm-bindings"))]
#[cfg_attr(not(test), allow(dead_code))]
const TS_ERROR_CODES: &str = r#"
export type ShrincsErrorCode =
  | "ERR_BAD_LENGTH" | "ERR_STATEFUL_LEAVES_EXHAUSTED"
  | "ERR_SIGNING_FAILED" | "ERR_KEYGEN_FAILED" | "ERR_INVALID_INPUT"
  | "ERR_IMPORT_INVALID"
  | "ERR_ENVELOPE_MALFORMED";
"#;

#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen(typescript_custom_section)]
const _TS_ERROR_CODES_TYPESCRIPT_SECTION: &str = TS_ERROR_CODES;

/// The version of this wasm build, frozen in at compile time from the crate
/// version (`Cargo.toml`). The npm `package.json` version is synced to the
/// same value at build/publish, so for consumers this is simply "the package
/// version, queryable from the running module". Useful for asserting that a
/// vendored or separately-served `.wasm` matches the JS that loaded it.
///
/// Profile-independent: all six published binaries are built from one crate
/// version. Use `profileName()` to tell them apart.
#[cfg(feature = "wasm-bindings")]
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Convert a boundary error into the `Error` object with a machine-readable
/// `code` property that every throwing export raises. Profile-independent.
#[cfg(feature = "wasm-bindings")]
pub(crate) fn js_error(err: BindingError) -> JsValue {
    let e = js_sys::Error::new(&err.message);
    if js_sys::Reflect::set(&e, &JsValue::from_str("code"), &JsValue::from_str(err.code)).is_err() {
        // Reflect::set failed, so the machine-readable code would be lost off the
        // Error object. Fold it into the message so callers never lose it.
        return js_sys::Error::new(&format!("[{}] {}", err.code, err.message)).into();
    }
    e.into()
}

// The one monomorphization. `SelectedProfile` comes from the single
// `shrincs_default_profile_*` cfg that build.rs derives from the enabled
// `profile-*` features, so `bin/build-wasm.sh` picks the profile per binary by
// passing a different `--features` on each of its six passes.
#[cfg(feature = "wasm-bindings")]
export::wasm_profile_surface!(SelectedProfile, NUM_CHAINS, NUM_LAYERS);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{
        bytes_fixed, bytes_word32, deserialize_shrincs_signing_key,
        deserialize_sphincs_plus_c_signing_key, serialize_shrincs_signing_key,
    };
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use crate::shrincs::test_fixtures::{
        fixture_entry_opt, fixture_pair, load_fixture_file, stateful_signer_fixture_path,
        TestKeyMode,
    };
    use crate::shrincs::{Keys, PublicKey as SignerPublicKey, ShrincsSigner};
    use crate::ErrorCode;
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
        ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
            b"wasm verifier test seed",
            4,
        )
        .unwrap()
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    use crate::test_support::stateful_only_key;

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    fn stateful_signing_key_and_public_key() -> (Keys, SignerPublicKey) {
        match TestKeyMode::from_env() {
            TestKeyMode::Fresh => {
                stateful_only_key::<SelectedProfile, NUM_CHAINS>(b"wasm verifier test seed", 4)
            }
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

                stateful_only_key::<SelectedProfile, NUM_CHAINS>(b"wasm verifier test seed", 4)
            }
        }
    }

    #[test]
    fn bytes_fixed_rejects_wrong_length_without_echoing_the_value() {
        let err = bytes_fixed::<32>(&[0x42u8; 31]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadLength.as_str());
        assert!(!err.message.contains("42"));
        assert!(err.message.contains("31"));

        assert!(bytes_fixed::<32>(&[0x42u8; 32]).is_ok());
        assert!(bytes_word32(&[0u8; 32]).is_ok());
        assert!(bytes_word32(&[0u8; 33]).is_err());
    }

    // ── The generic core, exercised at more than one profile ────────────────
    //
    // These are the tests that make the `P` parameterization mean something.
    // The `#[wasm_bindgen]` exports below can only ever run at whichever
    // profile the build selected, so on their own they would leave the core
    // proven at exactly one profile — which is indistinguishable from a core
    // that is not generic at all. These drive it at two.

    /// A full keygen/sign/verify round trip through the generic core at one
    /// profile, plus the rejections that prove the verify is not a constant
    /// `true`. Instantiated per profile by the tests below.
    fn core_round_trips_and_rejects_tamper<
        P: crate::profile::Profile,
        const N: usize,
        const L: usize,
    >() {
        let seed = [0x33u8; 32];
        let (signing_key, public_key) =
            crate::bindings::shrincs_keygen::<P, N, L>(&seed, 4).unwrap();
        let mut secret_key = serialize_shrincs_signing_key(&signing_key);
        let commitment = public_key.public_key_commitment.clone();

        let message = [0x03u8; 32];
        let signature =
            crate::bindings::shrincs_sign::<P, N, L>(&message, &mut secret_key).unwrap();
        assert!(crate::bindings::shrincs_verify::<P, N>(
            &signature,
            &message,
            &commitment
        ));

        // Wrong message, tampered signature, and wrong commitment must all
        // fail — otherwise "verify" is not verifying.
        assert!(!crate::bindings::shrincs_verify::<P, N>(
            &signature,
            &[0xEEu8; 32],
            &commitment
        ));
        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!crate::bindings::shrincs_verify::<P, N>(
            &tampered,
            &message,
            &commitment
        ));
        let mut wrong_commitment = commitment.clone();
        wrong_commitment[0] ^= 1;
        assert!(!crate::bindings::shrincs_verify::<P, N>(
            &signature,
            &message,
            &wrong_commitment
        ));

        // Recovery must recompute the same commitment from the envelope's
        // carried public key, under this profile's hashing.
        let recovered =
            crate::bindings::shrincs_recover_public_key_commitment::<P>(&signature).unwrap();
        assert_eq!(recovered, commitment);
    }

    #[cfg(feature = "profile-256s")]
    #[test]
    fn core_round_trips_at_256s_keccak() {
        core_round_trips_and_rejects_tamper::<crate::profiles::p256s::Profile256s, 64, 8>();
    }

    #[cfg(feature = "profile-256s-sha2")]
    #[test]
    fn core_round_trips_at_256s_sha2() {
        core_round_trips_and_rejects_tamper::<crate::profiles::p256s_sha2::Profile256sSha2, 64, 8>(
        );
    }

    /// A signature made under one profile must not verify under another. Two
    /// profiles sharing every array width and differing only in the scheme
    /// hash suite is the case a width-only check cannot catch: if the core
    /// ever routed hashing through the build-selected profile instead of `P`,
    /// these two would accept each other's signatures.
    #[cfg(all(feature = "profile-256s", feature = "profile-256s-sha2"))]
    #[test]
    fn a_signature_does_not_verify_under_the_twin_profile() {
        use crate::profiles::p256s::Profile256s;
        use crate::profiles::p256s_sha2::Profile256sSha2;

        let seed = [0x5au8; 32];
        let (signing_key, public_key) =
            crate::bindings::shrincs_keygen::<Profile256s, 64, 8>(&seed, 4).unwrap();
        let mut secret_key = serialize_shrincs_signing_key(&signing_key);
        let commitment = public_key.public_key_commitment.clone();

        let message = [0x5bu8; 32];
        let signature =
            crate::bindings::shrincs_sign::<Profile256s, 64, 8>(&message, &mut secret_key).unwrap();

        assert!(crate::bindings::shrincs_verify::<Profile256s, 64>(
            &signature,
            &message,
            &commitment
        ));
        assert!(
            !crate::bindings::shrincs_verify::<Profile256sSha2, 64>(
                &signature,
                &message,
                &commitment
            ),
            "a keccak-suite signature verified under the sha2 twin: the core is \
             hashing under something other than its own P"
        );
    }

    /// The 128s profiles carry different array widths (32 chains, 1 layer)
    /// than the 256s profiles (64 chains, 8 layers). Keygen at 128s costs tens
    /// of seconds, far too slow for a unit test, so this drives only the
    /// verify path on a garbage envelope. It still forces the core to
    /// monomorphize at those widths, which is what a wrong width would break.
    #[cfg(feature = "profile-128s-q18")]
    #[test]
    fn core_monomorphizes_at_the_128s_widths() {
        use crate::profiles::p128s_q18::Profile128sQ18;
        assert!(!crate::bindings::shrincs_verify::<Profile128sQ18, 32>(
            &[0u8; 8], &[0u8; 32], &[0u8; 32]
        ));
        assert!(
            crate::bindings::shrincs_recover_public_key_commitment::<Profile128sQ18>(&[0u8; 8])
                .is_err()
        );
    }

    // ── Noble-style Uint8Array API: round trips at the Rust level ──────────
    // The primary conformance coverage lives in ts/test/ (node, against the
    // real compiled wasm); these pin the pure-Rust logic these free functions
    // wrap. Feature-gated (not `any(test, wasm-bindings)`) because they call
    // the `#[wasm_bindgen]`-annotated free functions directly, which are only
    // defined under `feature = "wasm-bindings"`.

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn profile_name_reports_the_build_selected_profile() {
        assert_eq!(super::profile_name(), crate::shrincs::PROFILE_NAME);
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn sphincs_plus_c_noble_keygen_sign_verify_round_trips_and_rejects_tamper() {
        let seed = [0x11u8; 32];
        let keys = super::sphincs_plus_c_keygen(&seed).unwrap();
        let secret_key = keys.secret_key();
        let public_key = keys.public_key();
        assert_eq!(secret_key.len(), 128);
        assert_eq!(public_key.len(), 64);

        let message = [0x01u8; 32].to_vec();
        let signature = super::sphincs_plus_c_sign(&message, &secret_key).unwrap();
        assert!(super::sphincs_plus_c_verify(
            &signature,
            &message,
            &public_key
        ));
        assert!(!super::sphincs_plus_c_verify(
            &signature,
            &[0xEEu8; 32],
            &public_key
        ));

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!super::sphincs_plus_c_verify(
            &tampered,
            &message,
            &public_key
        ));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn sphincs_plus_c_noble_keygen_is_deterministic_for_the_same_seed() {
        let seed = [0x22u8; 32];
        let a = super::sphincs_plus_c_keygen(&seed).unwrap();
        let b = super::sphincs_plus_c_keygen(&seed).unwrap();
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
        let err = expect_err(super::sphincs_plus_c_keygen(&[0u8; 31]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ErrorCode::BadLength.as_str(),
        );
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_keygen_sign_verify_round_trips_and_rejects_tamper() {
        let seed = [0x33u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let public_key = keys.public_key();
        let public_key_commitment = keys.public_key_commitment();
        assert_eq!(secret_key.len(), 264);
        assert_eq!(public_key.len(), 164);

        let message = [0x03u8; 32].to_vec();
        let signature = super::shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(super::shrincs_verify(
            &signature,
            &message,
            &public_key_commitment
        ));
        assert!(!super::shrincs_verify(
            &signature,
            &[0xEEu8; 32],
            &public_key_commitment
        ));

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(!super::shrincs_verify(
            &tampered,
            &message,
            &public_key_commitment
        ));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_verify_rejects_wrong_public_key_commitment() {
        let seed = [0x55u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let real_commitment = keys.public_key_commitment();

        let message = [0x05u8; 32].to_vec();
        let signature = super::shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(super::shrincs_verify(
            &signature,
            &message,
            &real_commitment
        ));

        // The envelope carries the full PublicKey; `shrincsVerify` must check
        // that it actually hashes to the supplied commitment, not just that
        // the signature verifies under whatever PublicKey it happens to
        // carry. A wrong-but-well-formed 32-byte commitment must fail even
        // though the signature and message are untouched.
        let mut wrong_commitment = real_commitment.clone();
        wrong_commitment[0] ^= 1;
        assert!(!super::shrincs_verify(
            &signature,
            &message,
            &wrong_commitment
        ));

        assert!(!super::shrincs_verify(&signature, &message, &[0xFFu8; 32]));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_sign_advances_secret_key_in_place_across_two_signatures() {
        let seed = [0x44u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let public_key_commitment = keys.public_key_commitment();
        let before = secret_key.clone();

        let message = [0x04u8; 32].to_vec();
        let first = super::shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(
            secret_key, before,
            "secretKey must mutate in place after sign"
        );
        assert!(super::shrincs_verify(
            &first,
            &message,
            &public_key_commitment
        ));

        let after_first = secret_key.clone();
        let second = super::shrincs_sign(&message, &mut secret_key).unwrap();
        assert_ne!(
            secret_key, after_first,
            "secretKey must advance again on the next sign"
        );
        assert_ne!(first, second, "two leaves must yield distinct signatures");
        assert!(super::shrincs_verify(
            &second,
            &message,
            &public_key_commitment
        ));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_reset_changes_commitment_keeps_stateless_and_still_signs() {
        let seed = [0x88u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let stateless_public_key = keys.stateless_public_key();
        let original_commitment = keys.public_key_commitment();

        super::shrincs_reset(&mut secret_key, &[0x99u8; 32]).unwrap();

        let reset_commitment = super::shrincs_compute_public_key_commitment(&secret_key).unwrap();
        assert_ne!(reset_commitment, original_commitment);

        let reimported = super::shrincs_import_signing_key(&secret_key).unwrap();
        assert_eq!(reimported.public_key_commitment(), reset_commitment);
        assert_eq!(
            reimported.stateless_public_key(),
            stateless_public_key,
            "reset must not touch the stateless half"
        );

        let message = [0x09u8; 32].to_vec();
        let signature = super::shrincs_sign(&message, &mut secret_key).unwrap();
        assert!(super::shrincs_verify(
            &signature,
            &message,
            &reset_commitment
        ));
    }

    // The `shrincs_reset` wrong-length rejection (ERR_BAD_LENGTH) is covered in
    // ts/test/conformance.test.mjs — the public JsValue error path cannot be
    // exercised on a non-wasm target (constructing the JsValue panics), so the
    // native tests only drive the success path.

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_compute_public_key_commitment_matches_keygen() {
        let seed = [0x99u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let commitment = super::shrincs_compute_public_key_commitment(&secret_key).unwrap();
        assert_eq!(commitment, keys.public_key_commitment());
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_recover_public_key_commitment_matches_signer() {
        let seed = [0xaau8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let mut secret_key = keys.secret_key();
        let expected_commitment = keys.public_key_commitment();

        let message = [0x0au8; 32].to_vec();
        let signature = super::shrincs_sign(&message, &mut secret_key).unwrap();

        let recovered = super::shrincs_recover_public_key_commitment(&signature).unwrap();
        assert_eq!(recovered, expected_commitment);
    }

    // `.unwrap_err()`/`error.code` on the rejection path needs a real JS
    // engine (see the comment on `sphincs_plus_c_noble_keygen_rejects_wrong_length_seed`
    // above) — wasm32-gated.
    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn shrincs_noble_recover_public_key_commitment_rejects_garbage_envelope() {
        let err = expect_err(super::shrincs_recover_public_key_commitment(&[0u8; 4]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ErrorCode::EnvelopeMalformed.as_str(),
        );
    }

    #[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
    #[wasm_bindgen_test]
    fn shrincs_noble_sign_throws_when_stateful_leaves_are_exhausted() {
        let seed = [0x55u8; 32];
        let keys = super::shrincs_keygen(&seed, 1).unwrap();
        let mut secret_key = keys.secret_key();
        let message = [0x06u8; 32].to_vec();

        super::shrincs_sign(&message, &mut secret_key).unwrap(); // consumes the only leaf
        let err = expect_err(super::shrincs_sign(&message, &mut secret_key));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ErrorCode::StatefulLeavesExhausted.as_str(),
        );
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_sign_stateless_never_mutates_and_verifies() {
        let seed = [0x66u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();
        // Stateless verify takes the 64-byte SPHINCS+C key (pkSeed‖hypertreeRoot),
        // not the commitment — a stateless signature is a SPHINCS+C signature.
        let stateless_public_key = keys.stateless_public_key();
        let before = secret_key.clone();

        let message = [0x05u8; 32].to_vec();
        let signature = super::shrincs_sign_stateless(&message, &secret_key).unwrap();
        assert_eq!(
            secret_key, before,
            "stateless sign must not mutate secretKey"
        );
        assert!(super::shrincs_verify_stateless(
            &signature,
            &message,
            &stateless_public_key
        ));
        assert!(!super::shrincs_verify_stateless(
            &signature,
            &[0xEEu8; 32],
            &stateless_public_key,
        ));
        // And it is literally the SPHINCS+C verify with that key.
        assert!(super::sphincs_plus_c_verify(
            &signature,
            &message,
            &stateless_public_key
        ));
    }

    #[cfg(feature = "wasm-bindings")]
    #[test]
    fn shrincs_noble_import_signing_key_round_trips() {
        let seed = [0x77u8; 32];
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let imported = super::shrincs_import_signing_key(&secret_key).unwrap();
        assert_eq!(imported.secret_key(), secret_key);
        assert_eq!(
            imported.public_key_commitment(),
            keys.public_key_commitment()
        );
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
        let keys = super::shrincs_keygen(&seed, 4).unwrap();
        let secret_key = keys.secret_key();

        let mut tampered = secret_key.clone();
        tampered[0] ^= 1; // corrupts statefulSkSeed, invalidating statefulRoot
        let err = expect_err(super::shrincs_import_signing_key(&tampered));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ErrorCode::ImportInvalid.as_str(),
        );

        let err = expect_err(super::shrincs_import_signing_key(&secret_key[..263]));
        assert_eq!(
            js_sys::Reflect::get(&err, &JsValue::from_str("code"))
                .unwrap()
                .as_string()
                .unwrap(),
            ErrorCode::BadLength.as_str(),
        );
    }

    #[test]
    fn shrincs_signing_key_flat_serialization_round_trips() {
        let (key, _) = signing_key_and_public_key();
        let bytes = serialize_shrincs_signing_key(&key);
        assert_eq!(bytes.len(), 264);
        let parsed = deserialize_shrincs_signing_key::<SelectedProfile>(&bytes).unwrap();
        assert_eq!(parsed, key);

        let err = deserialize_shrincs_signing_key::<SelectedProfile>(&bytes[..263]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadLength.as_str());
    }

    #[test]
    fn sphincs_plus_c_signing_key_flat_serialization_round_trips() {
        let (key, _) = signing_key_and_public_key();
        let spk = key.stateless().clone();
        let bytes = spk.to_bytes();
        assert_eq!(bytes.len(), 128);
        let parsed = deserialize_sphincs_plus_c_signing_key(&bytes).unwrap();
        assert_eq!(parsed, spk);

        let err = deserialize_sphincs_plus_c_signing_key(&bytes[..127]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadLength.as_str());
    }

    #[test]
    fn typescript_union_lists_every_error_code() {
        for code in crate::ErrorCode::ALL {
            let quoted = alloc::format!("\"{}\"", code.as_str());
            assert!(
                TS_ERROR_CODES.contains(&quoted),
                "the ShrincsErrorCode TypeScript union is missing {quoted}"
            );
        }
    }

    /// The direction above cannot catch a union member that no Rust variant
    /// produces. That one ships in the published `.d.ts` and tells callers to
    /// handle a code they will never receive, so the type definition is a lie
    /// and no test fails. Containment in one direction is not agreement.
    #[test]
    fn every_typescript_union_member_maps_to_an_error_code() {
        let known: alloc::vec::Vec<_> = crate::ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect();

        // Every quoted literal in the union block, without pulling in a
        // TypeScript parser. This works only because nothing else in
        // TS_ERROR_CODES is double-quoted. Add a comment containing a quoted
        // string to that literal and this parse cannot tell the fragment apart
        // from a union member, so the guard below names that cause instead of
        // reporting a phantom code.
        let members: alloc::vec::Vec<&str> = TS_ERROR_CODES.split('"').skip(1).step_by(2).collect();

        assert!(
            !members.is_empty(),
            "parsed no members out of the union; the literal's shape changed"
        );

        for member in &members {
            assert!(
                member.starts_with("ERR_"),
                "parsed {member:?} out of the union, which is not an error code. \
                 TS_ERROR_CODES most likely gained a quoted string outside the \
                 union members, which this parse cannot distinguish from one."
            );
        }

        for member in &members {
            assert!(
                known.contains(member),
                "the TypeScript union declares {member}, which no ErrorCode variant produces"
            );
        }

        assert_eq!(
            members.len(),
            known.len(),
            "union has {} members, ErrorCode has {} variants",
            members.len(),
            known.len()
        );
    }
}
