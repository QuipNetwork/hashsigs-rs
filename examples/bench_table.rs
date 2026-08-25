//! Timing table generator for the README performance table.
//!
//! Measures, for the compiled profile, the mean wall-clock time of:
//! keygen (maxSignatures = 1024), stateful sign (leaf 1) + verify,
//! stateless sign + verify. Also prints the measured wire sizes.
//!
//! Run one profile per invocation (single-threaded; the `parallel`
//! feature is intentionally off so numbers reflect the default build):
//!
//! ```bash
//! BENCH_LABEL=256s-keccak   cargo run --release --example bench_table
//! BENCH_LABEL=256s-sha2     cargo run --release --example bench_table --features profile-256s-sha2
//! BENCH_LABEL=128s-q18      cargo run --release --example bench_table --features profile-128s-q18
//! BENCH_LABEL=128s-q20      cargo run --release --example bench_table --features profile-128s-q20
//! ```
//!
//! Stateless sign times vary run to run: FORS-C signing grinds a counter
//! (expected 2^14 tries at 256s, 2^24 at 128s), so each message is a fresh
//! geometric draw. The harness signs distinct messages and reports the mean.

use hashsigs_rs::profile_active::{ActiveProfile, NUM_CHAINS, NUM_LAYERS};
use std::time::Instant;

use hashsigs_rs::shrincs::{sign, Keys, ShrincsSigner, ShrincsVerifier, VerifierInterface};
use hashsigs_rs::sphincs_plus_c;
use hashsigs_rs::VerifyOutcome;

const MAX_SIGNATURES: u32 = 1024;
const KEYGEN_ITERS: u32 = 2;
const STATEFUL_SIGN_ITERS: u32 = 5;
const STATELESS_SIGN_ITERS: u32 = 3;
const VERIFY_ITERS: u32 = 20;

fn msg(i: u8) -> [u8; 32] {
    let mut m = [0u8; 32];
    m[0] = i;
    m[31] = 0xb7;
    m
}

fn mean_ms(total_ms: f64, iters: u32) -> f64 {
    total_ms / f64::from(iters)
}

fn main() {
    let label = std::env::var("BENCH_LABEL").unwrap_or_else(|_| "unlabeled".to_owned());
    let seed = b"readme-bench-table-seed";

    // Warm-up round: allocator pages plus one draw of every code path.
    let (warm_keys, warm_pk) =
        ShrincsSigner::keygen::<ActiveProfile, NUM_CHAINS, NUM_LAYERS>(seed, MAX_SIGNATURES)
            .expect("keygen");
    let mut warm_signer =
        Keys::from_bytes::<ActiveProfile>(&warm_keys.to_bytes()).expect("snapshot");
    let warm_envelope =
        sign::<ActiveProfile, NUM_CHAINS>(&mut warm_signer, &msg(0)).expect("stateful sign");
    let warm_stateless =
        ShrincsSigner::sign_stateless_raw::<ActiveProfile, NUM_LAYERS>(&warm_keys, &msg(0))
            .expect("sign");

    // Keygen.
    let mut keygen_total = 0.0;
    for _ in 0..KEYGEN_ITERS {
        let t = Instant::now();
        let (_keys, _pk) =
            ShrincsSigner::keygen::<ActiveProfile, NUM_CHAINS, NUM_LAYERS>(seed, MAX_SIGNATURES)
                .expect("keygen");
        keygen_total += t.elapsed().as_secs_f64() * 1000.0;
    }

    // Stateful sign, always at leaf 1: snapshot the fresh key before each
    // sign so the leaf counter never advances across iterations.
    let mut stateful_sign_total = 0.0;
    let mut envelope = warm_envelope.clone();
    for i in 0..STATEFUL_SIGN_ITERS {
        let mut k = Keys::from_bytes::<ActiveProfile>(&warm_keys.to_bytes()).expect("snapshot");
        let m = msg(i as u8 + 1);
        let t = Instant::now();
        envelope = sign::<ActiveProfile, NUM_CHAINS>(&mut k, &m).expect("stateful sign");
        stateful_sign_total += t.elapsed().as_secs_f64() * 1000.0;
    }
    let stateful_msg = msg(STATEFUL_SIGN_ITERS as u8);

    // Stateful verify (commitment-keyed envelope path, as on-chain).
    let verifier = ShrincsVerifier::new();
    let mut stateful_verify_total = 0.0;
    for _ in 0..VERIFY_ITERS {
        let t = Instant::now();
        let outcome = verifier.verify(&warm_pk.public_key_commitment, &stateful_msg, &envelope);
        stateful_verify_total += t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    // Stateless sign over distinct messages (fresh grind draw each).
    let mut stateless_sign_total = 0.0;
    let mut stateless_sig = warm_stateless.clone();
    for i in 0..STATELESS_SIGN_ITERS {
        let m = msg(100 + i as u8);
        let t = Instant::now();
        stateless_sig =
            ShrincsSigner::sign_stateless_raw::<ActiveProfile, NUM_LAYERS>(&warm_keys, &m)
                .expect("stateless sign");
        stateless_sign_total += t.elapsed().as_secs_f64() * 1000.0;
    }
    let stateless_msg = msg(100 + STATELESS_SIGN_ITERS as u8 - 1);

    // Stateless verify at the SPHINCS+C layer (same core the Solana
    // stateless-verify instruction runs).
    let stateless_pk = &warm_keys.stateless().public_key;
    let mut stateless_verify_total = 0.0;
    for _ in 0..VERIFY_ITERS {
        let t = Instant::now();
        let ok = sphincs_plus_c::verify_hash::<ActiveProfile, NUM_CHAINS>(
            stateless_pk,
            &stateless_msg,
            &stateless_sig,
        );
        stateless_verify_total += t.elapsed().as_secs_f64() * 1000.0;
        assert!(ok);
    }

    println!("label={label}");
    println!("max_signatures={MAX_SIGNATURES}");
    println!("secret_key_bytes={}", warm_keys.to_bytes().len());
    println!("public_bundle_bytes={}", warm_pk.to_bytes().len());
    println!("stateful_envelope_leaf1_bytes={}", warm_envelope.len());
    println!("stateless_sig_bytes={}", warm_stateless.to_bytes().len());
    println!("keygen_ms={:.1}", mean_ms(keygen_total, KEYGEN_ITERS));
    println!(
        "stateful_sign_ms={:.1}",
        mean_ms(stateful_sign_total, STATEFUL_SIGN_ITERS)
    );
    println!(
        "stateful_verify_ms={:.3}",
        mean_ms(stateful_verify_total, VERIFY_ITERS)
    );
    println!(
        "stateless_sign_ms={:.1}",
        mean_ms(stateless_sign_total, STATELESS_SIGN_ITERS)
    );
    println!(
        "stateless_verify_ms={:.3}",
        mean_ms(stateless_verify_total, VERIFY_ITERS)
    );
}
