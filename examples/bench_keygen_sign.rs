//! Timing probe for 256s keygen + one stateless sign.
//! Run sequential: cargo run --example bench_keygen_sign --release --locked
//! Run parallel:   cargo run --example bench_keygen_sign --release --locked --features parallel
//!
//! Runs one untimed warm-up round first (so rayon's global thread-pool spin-up,
//! a one-time cost under `--features parallel`, does not skew the measured
//! iterations), then times `ITERATIONS` keygen+sign rounds and reports the mean.

use std::time::Instant;

use hashsigs_rs::shrincs::ShrincsSigner;

const ITERATIONS: u32 = 5;

fn main() {
    let seed = b"perf-lane-timing-benchmark-seed";
    let msg = b"timing benchmark message";

    // Warm-up: absorbs one-time costs (rayon thread-pool init under `parallel`,
    // allocator warm pages) so the measured loop reflects steady-state cost.
    let (warm_sk, _warm_pk) = ShrincsSigner::keygen(seed, 4).expect("keygen");
    let _warm_sig = ShrincsSigner::sign_stateless_raw(&warm_sk, msg).expect("sign");

    let mut keygen_total_ms = 0.0;
    let mut sign_total_ms = 0.0;
    for _ in 0..ITERATIONS {
        let keygen_start = Instant::now();
        let (sk, _pk) = ShrincsSigner::keygen(seed, 4).expect("keygen");
        keygen_total_ms += keygen_start.elapsed().as_secs_f64() * 1000.0;

        let sign_start = Instant::now();
        let _sig = ShrincsSigner::sign_stateless_raw(&sk, msg).expect("sign");
        sign_total_ms += sign_start.elapsed().as_secs_f64() * 1000.0;
    }

    println!(
        "keygen_mean_ms={:.3}",
        keygen_total_ms / f64::from(ITERATIONS)
    );
    println!(
        "stateless_sign_mean_ms={:.3}",
        sign_total_ms / f64::from(ITERATIONS)
    );
}
