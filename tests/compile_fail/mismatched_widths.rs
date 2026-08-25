use hashsigs_rs::profiles::p256s::Profile256s;

fn main() {
    // Profile256s::NUM_WOTS_CHAINS is 64, not 32.
    let _bad = hashsigs_rs::shrincs::ShrincsCore::<Profile256s, 32, 8>::new();
}
