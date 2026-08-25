#[test]
#[cfg(feature = "profile-256s")]
fn mismatched_const_generic_widths_fail_to_compile() {
    let t = trybuild::TestCases::new();
    // A `pass` case forces trybuild to drive `cargo build` instead of
    // `cargo check` for this whole suite. `cargo check` alone does not run
    // the codegen pass that forces evaluation of `ShrincsCore::WIDTHS_AGREE`,
    // so a bare `compile_fail` case would report success even if
    // `assert_widths` were never wired up -- see matched_widths.rs.
    t.pass("tests/compile_fail/matched_widths.rs");
    t.compile_fail("tests/compile_fail/mismatched_widths.rs");
}
