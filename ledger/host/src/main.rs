// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public test fixtures. This seed must never secure assets.
use hashsigs_rs::profiles::selected::{SelectedProfile, NUM_CHAINS, NUM_LAYERS};
use hashsigs_rs::shrincs::{
    decode_stateful_envelope, encode_stateful_envelope, sign, ShrincsSigner, ShrincsVerifier,
};
use hashsigs_rs::{VerifierInterface, VerifyOutcome};
use serde_json::json;

fn main() {
    // Public emulator oracle. Input is a PUBLIC test keygen seed, never a
    // hardware-wallet secret; output contains only the canonical public key.
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--keygen-public" {
        let seed = hex::decode(&args[2]).expect("public emulator seed hex");
        assert_eq!(seed.len(), 32);
        let (_, public) =
            ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(&seed, 4)
                .expect("public oracle keygen");
        println!("{}", hex::encode(public.to_bytes()));
        return;
    }
    assert_eq!(
        args.len(),
        1,
        "usage: hashsigs-ledger-vectors [--keygen-public SEED_HEX]"
    );
    let (mut keys, public) = ShrincsSigner::keygen::<SelectedProfile, NUM_CHAINS, NUM_LAYERS>(
        b"hashsigs-ledger PUBLIC TEST FIXTURE v1",
        4,
    )
    .expect("fixture key generation");
    let mut cases = Vec::new();
    for leaf in 1u8..=4 {
        let hash = [leaf; 32];
        let signature = sign::<SelectedProfile, NUM_CHAINS>(&mut keys, &hash)
            .expect("fixture signing within the four-leaf budget");
        assert_eq!(
            ShrincsVerifier::new().verify(&public.public_key_commitment, &hash, &signature),
            VerifyOutcome::Valid
        );
        cases.push(json!({"leaf": leaf, "hash": hex::encode(hash),
            "commitment": hex::encode(&public.public_key_commitment), "envelope": hex::encode(signature)}));
    }
    assert!(sign::<SelectedProfile, NUM_CHAINS>(&mut keys, &[5; 32]).is_none());
    // A canonical but invalid envelope at the exact transport limit exercises
    // the decoder's peak allocation path, unlike a zero-filled malformed blob.
    let first = hex::decode(cases[0]["envelope"].as_str().unwrap()).unwrap();
    let (boundary_public, mut boundary_sig) =
        decode_stateful_envelope::<SelectedProfile>(&first).expect("decode fixture");
    let mut boundary = encode_stateful_envelope(&boundary_public, &boundary_sig);
    while boundary.len() < 4096 {
        boundary_sig.auth_path.push([0; 32]);
        boundary = encode_stateful_envelope(&boundary_public, &boundary_sig);
    }
    assert_eq!(boundary.len(), 4096);
    assert_eq!(
        ShrincsVerifier::new().verify(&public.public_key_commitment, &[1; 32], &boundary),
        VerifyOutcome::Invalid,
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"schema": 1,
        "profile": hashsigs_rs::shrincs::PROFILE_NAME,
        "profile_id": hex::encode(hashsigs_rs::shrincs::PROFILE_ID), "cases": cases, "boundary_envelope": hex::encode(boundary)}))
        .expect("fixture JSON")
    );
}
