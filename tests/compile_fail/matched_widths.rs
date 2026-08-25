use hashsigs_rs::profiles::p256s::Profile256s;

// Companion pass case for mismatched_widths.rs: same construction with the
// widths Profile256s actually declares (64 chains, 8 layers). Its only job
// is forcing trybuild to invoke `cargo build` instead of `cargo check` for
// this suite -- `cargo check` alone does not run the codegen pass that
// forces evaluation of an unused associated const, so a bare `compile_fail`
// suite would pass even when assert_widths is not wired at all. See
// tests/compile_fail.rs.
fn main() {
    let _ok = hashsigs_rs::shrincs::ShrincsCore::<Profile256s, 64, 8>::new();
}
