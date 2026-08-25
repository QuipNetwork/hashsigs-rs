# Changelog

This file records changes to this project, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Unreleased

### Added

- Two SHRINCS profiles, `shrincs-128s-q18-sha2` and `shrincs-128s-q20-sha2`,
  behind the `profile-128s-q18-sha2` and `profile-128s-q20-sha2` features.
  Each is the exact numeric twin of the keccak profile of the same name and
  differs only in the scheme hash suite (SHA-256 instead of keccak-256) and in
  the profile identity string. Both carry committed SPHINCS golden vectors and
  run the library suite in CI. Their ERC-7913 adapter tests are held back until
  the matching account-wrapper vectors, which are generated in
  hashsigs-solidity, are copied across.

### Changed

- Packaging ships one artifact per ecosystem instead of a base package plus
  one sibling package per profile. `hashsigs-rs`, the `hashsigs` PyPI
  distribution, and `@quip.network/hashsigs-wasm` each carry every profile,
  and each profile is imported on its own path. `bin/packages.sh` no longer
  declares `SIBLING_PROFILES`, `PYPI_SIBLINGS`, or `NPM_SIBLINGS`; it declares
  `PROFILES` instead. The Rust import paths work today. The Python and npm
  per-profile subpaths still need the `profiles::selected` module removed,
  because the wasm bindings bind to one profile per build.
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
