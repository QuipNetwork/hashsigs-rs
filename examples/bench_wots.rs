//! Timing probe for the standalone WOTS+ (v1, legacy) scheme, for the README
//! performance table. Profile-independent: WOTS+ owns its constants.
//!
//! ```bash
//! cargo run --release --example bench_wots
//! ```

use std::time::Instant;

use hashsigs_rs::{constants, WOTSPlus};
use sha3::{Digest, Keccak256};

const ITERS: u32 = 100;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn main() {
    let wots = WOTSPlus::new(keccak256);
    let seed = [7u8; 32];
    let message = [42u8; constants::MESSAGE_LEN];

    // Warm-up.
    let (pk, sk) = wots.generate_key_pair(&seed);
    let sig = wots.sign(&sk, &message).expect("sign");
    assert!(wots.verify(&pk, &message, &sig));

    let mut keygen_total = 0.0;
    let mut sign_total = 0.0;
    let mut verify_total = 0.0;
    for _ in 0..ITERS {
        let t = Instant::now();
        let (pk, sk) = wots.generate_key_pair(&seed);
        keygen_total += t.elapsed().as_secs_f64() * 1000.0;

        let t = Instant::now();
        let sig = wots.sign(&sk, &message).expect("sign");
        sign_total += t.elapsed().as_secs_f64() * 1000.0;

        let t = Instant::now();
        let ok = wots.verify(&pk, &message, &sig);
        verify_total += t.elapsed().as_secs_f64() * 1000.0;
        assert!(ok);
    }

    println!("signature_bytes={}", constants::SIGNATURE_SIZE);
    println!("public_key_bytes={}", constants::PUBLIC_KEY_SIZE);
    println!("keygen_ms={:.3}", keygen_total / f64::from(ITERS));
    println!("sign_ms={:.3}", sign_total / f64::from(ITERS));
    println!("verify_ms={:.3}", verify_total / f64::from(ITERS));
}
