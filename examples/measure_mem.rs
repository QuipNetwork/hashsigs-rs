//! Peak-memory probe for 256s keygen + one stateless sign.
//! Run: cargo run --example measure_mem --release --locked

use hashsigs_rs::shrincs::ShrincsSigner;

fn main() {
    let seed = b"perf-lane-memory-measure-seed";
    let (sk, _pk) = ShrincsSigner::keygen(seed, 4).expect("keygen");
    let msg = b"memory measure message";
    let _sig = ShrincsSigner::sign_stateless_raw(&sk, msg).expect("sign");
    // Touch so nothing is optimized away.
    println!("ok seed_len={} msg_len={}", seed.len(), msg.len());
}
