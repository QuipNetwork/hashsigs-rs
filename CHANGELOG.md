# Changelog

This file records changes to this project, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Unreleased

### Added

- Two SHRINCS profiles, `shrincs-128s-q18-sha2` and `shrincs-128s-q20-sha2`,
  behind the `profile-128s-q18-sha2` and `profile-128s-q20-sha2` features.
  Each is the exact numeric twin of the keccak profile of the same name and
  differs only in the scheme hash suite (SHA-256 instead of keccak-256) and in
  the profile identity string. Golden vectors for the two are not generated
  yet, so CI compiles them rather than running the vector-conformance suite.

### Changed

- The six `profile-*` Cargo features (`profile-256s`, `profile-256s-sha2`,
  `profile-128s-q18`, `profile-128s-q20`, `profile-128s-q18-sha2`,
  `profile-128s-q20-sha2`) are additive. Enabling more than
  one now compiles more than one profile into the same build, instead of
  build.rs panicking on two. `cargo test --all-features` compiles and tests
  every profile in one build.
- A `Profile` trait and per-profile types are now public, under
  `hashsigs_rs::profiles`, such as `hashsigs_rs::profiles::p256s::Shrincs`.
  `hashsigs_rs::Shrincs` now follows the profile the build binds to, rather
  than always naming the `256s` profile. When more than one profile feature is
  enabled, a fixed priority order decides which one that is. Name a profile
  module's own alias to pin one explicitly.

### Removed

- `TryFrom<&[u8]>` no longer exists on seven public wire types:
  `wots_c::Signature`, `shrincs::Keys`, `shrincs::Signature`,
  `sphincs_plus_c::LayerSignature`, `fors_c::Entry`, `fors_c::Signature`, and
  `sphincs_plus_c::Signature`. Callers must use the explicit
  `from_bytes::<P>` constructor for the profile they target.
