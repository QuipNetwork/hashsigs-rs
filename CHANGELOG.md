# Changelog

This file records changes to this project, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Unreleased

### Added

- Explicit-leaf stateful signing on the wasm surface: `shrincsSignAtLeaf`
  (commitment-bound, like `shrincsSign`) and `shrincsSignStatefulRawAt`
  (signs the message as-is, for callers whose canonical hashes already bind
  the commitment). Both are non-mutating -- no leaf counter advances, and the
  caller owns leaf-reuse discipline, for signers whose used-leaf state is
  authoritative elsewhere (an on-chain bitmap). `shrincsVerifyStatefulRaw` is
  the raw verify counterpart. `decodeStatefulEnvelope` and
  `decodeStatelessSignature` decode the ABI signature envelopes into typed
  fields in pure TS, from the node and browser entries alike.

- `profileName()` on the wasm surface, returning the SHRINCS profile the loaded
  binary carries. Every profile binary exports the same function names, so this
  is how a caller confirms it loaded the profile it imported.
- `@quip.network/hashsigs-wasm` ships every profile, each on its own subpath
  export: `@quip.network/hashsigs-wasm/128s-q18` and the five siblings. The
  package root stays the default profile, so a bare import is unchanged. Each
  subpath carries its own wasm binary, built by a `bin/build-wasm.sh` loop, so
  a browser consumer downloads one profile rather than six -- the browser build
  inlines the wasm as base64, where no bundler can drop the profiles nobody
  imported. A shipped binary is 133-147 KB, or 178-196 KB base64.
  `ts/src/api.ts` holds the profile-independent surface, and the per-profile
  loaders and entry points are generated from the profile list by
  `ts/scripts/gen-profile-entries.mjs`.
- The `hashsigs` PyPI distribution has a signing API. It previously exposed
  only `__version__`. `hashsigs.shrincs` and `hashsigs.sphincs_plus_c` cover
  keygen, stateful and stateless signing, verification, key import and export,
  and stateful-chain reset, over decomposed key objects rather than opaque
  blobs. Every failure raises `HashSigsError` with a stable `code`.
- Every SHRINCS profile ships in that one distribution, each as its own module:
  `from hashsigs.profiles import p128s_q18`, and five siblings. The package
  root stays the default profile. Each module carries its own compiled
  extension under `hashsigs._ext`, built from a crate in `py/profiles/`,
  because one Cargo package builds at most one cdylib. Importing a profile
  maps only that profile's code, at the cost of a wheel roughly six times the
  size of a single-profile build.
- Two SHRINCS profiles, `shrincs-128s-q18-sha2` and `shrincs-128s-q20-sha2`,
  behind the `profile-128s-q18-sha2` and `profile-128s-q20-sha2` features.
  Each is the exact numeric twin of the keccak profile of the same name and
  differs only in the scheme hash suite (SHA-256 instead of keccak-256) and in
  the profile identity string. Both carry committed SPHINCS golden vectors and
  run the library suite in CI. Their ERC-7913 adapter tests are held back until
  the matching account-wrapper vectors, which are generated in
  hashsigs-solidity, are copied across.

### Changed

- The FORS message digest binds to the profile. Both digest regimes hash
  `P::PROFILE_ID` into the preimage, which is now
  `H("fors-digest" || PROFILE_ID || pkSeed || hypertreeRoot || randomizer ||
  counter || message [|| i])`. Without it, two profiles that share a hash suite
  derive the same leaf indices for a message. This changes the wire format:
  signatures from earlier versions do not verify, and this release regenerates
  every committed golden vector. `ShrincsVerifier::version_tag()` and
  `SphincsPlusCVerifier::version_tag()` move from `v1` to `v2`, so a Solidity
  verifier pinned to the old tag rejects a new signature outright instead of
  failing inside the FORS check. Answers external audit issue oak-sol-02.
- Packaging ships one artifact per ecosystem instead of a base package plus
  one sibling package per profile. `hashsigs-rs`, the `hashsigs` PyPI
  distribution, and `@quip.network/hashsigs-wasm` each carry every profile,
  and each profile is imported on its own path. `bin/packages.sh` no longer
  declares `SIBLING_PROFILES`, `PYPI_SIBLINGS`, or `NPM_SIBLINGS`; it declares
  `PROFILES` instead. All three ecosystems now work this way.
- The six `profile-*` Cargo features (`profile-256s`, `profile-256s-sha2`,
  `profile-128s-q18`, `profile-128s-q20`, `profile-128s-q18-sha2`,
  `profile-128s-q20-sha2`) are additive. Enabling more than
  one now compiles more than one profile into the same build, instead of
  build.rs panicking on two. `cargo test --all-features` compiles and tests
  every profile in one build.
- The wasm surface is generic over the profile. `src/wasm/core.rs` holds every
  operation as a function over `P: Profile` plus that profile's two array
  widths, and `src/wasm/export.rs` carries the macro that stamps those out as
  concrete `#[wasm_bindgen]` items. `#[wasm_bindgen]` cannot annotate a generic
  function, so the export boundary is monomorphized by macro instead. The
  exported names and behavior do not change. The core verifies through the
  generic free functions rather than the `ShrincsVerifier` and
  `SphincsPlusCVerifier` facades, which name the build-selected profile and
  would otherwise pin every verify to it.
- A `Profile` trait and per-profile types are now public, under
  `hashsigs_rs::profiles`, such as `hashsigs_rs::profiles::p256s::Shrincs`.
  `hashsigs_rs::Shrincs` now follows the profile the build binds to, rather
  than always naming the `256s` profile. When more than one profile feature is
  enabled, a fixed priority order decides which one that is. Name a profile
  module's own alias to pin one explicitly.

- The PyPI distribution builds through `py/hashsigs_build.py`, a PEP 517
  backend that compiles one extension per profile and stages them into the
  package before delegating to maturin. `python -m build` and `pip install .`
  go through it; a bare `maturin build` does not, and produces a wheel whose
  `hashsigs._ext` is empty. The source distribution works: `pip install
  hashsigs --no-binary hashsigs` runs the same backend from the unpacked sdist
  and rebuilds every extension.
- `pyproject.toml` moved from `py/` to the repository root. maturin resolves
  `include` paths against the directory holding it, and that directory becomes
  the sdist root, while path dependencies are vendored at their
  workspace-relative locations. Rooting the file here makes those agree: the
  profile crates sit at `py/profiles/` in the sdist, the same place they
  occupy in the repository, so their path dependencies back to the core
  resolve.
- `hashsigs.ERROR_CODES` comes from the Rust `ErrorCode` enum through the root
  extension, rather than a tuple restated in Python.
- The profile-generic binding core moved from `src/wasm/core.rs` to
  `src/bindings.rs` and is now `#[doc(hidden)] pub`. Both the WebAssembly
  surface and the Python extension crates build on it, and the Python crates
  are separate packages, so they cannot reach a `pub(crate)` module. It is not
  a stable API.

### Removed

- `TryFrom<&[u8]>` no longer exists on seven public wire types:
  `wots_c::Signature`, `shrincs::Keys`, `shrincs::Signature`,
  `sphincs_plus_c::LayerSignature`, `fors_c::Entry`, `fors_c::Signature`, and
  `sphincs_plus_c::Signature`. Callers must use the explicit
  `from_bytes::<P>` constructor for the profile they target.

### Fixed

- The `hashsigs` wheel carries a `manylinux` platform tag again. The build
  moved from the maturin command line to `python -m build`, which builds the
  wheel from the sdist and so proves the sdist is complete. The two entry
  points disagree on one default. The command line tags the wheel for the
  lowest compatible `manylinux`. The PEP 517 hook it exposes defaults to
  `--compatibility off`, which produces a bare `linux_x86_64` tag. PyPI
  rejects that tag with a 400, because it makes no promise about the glibc the
  extensions need. `py/hashsigs_build.py` now passes `--compatibility pypi`,
  and every build path inherits it. `bin/check-wheel.py` checks the platform
  tag and the extension count. The release job, the merge request gate, and
  `make check-python-dists` all call it, so a wheel PyPI would reject now
  fails on a merge request instead of at upload.

- `valid_public_key` rejects a SHRINCS public bundle whose stateful root
  carries nonzero bytes past `P::HASH_TRUNC_LEN`. The 128-bit profiles hold a
  16-byte root in a 32-byte word and zero the unused suffix. A bundle with a
  dirty suffix is not a key any signer produces, and no stateful signature
  verifies against it. The validator used to check only the encoded length, so
  it accepted such a bundle whenever the commitment matched. Answers external
  audit issue oak-sol-09.

- The Rust SHRINCS signing and verification facades bind the full public-key
  commitment into the signed digest, and they use a separate domain tag for the
  stateful adapter and the stateless adapter. The facades used to sign the
  caller hash on its own. A signature over that hash therefore stayed valid
  after a change to the half of the bundle the primitive does not read, so an
  attacker could pair a stateful signature with a substituted stateless half,
  or the reverse. The verifier identity moves to V4, and the compressed
  Solidity interoperability vectors record the caller hash and the bound
  message separately. The old vectors remain as negative tests, which prove the
  V4 boundary rejects the earlier construction. Rust and Solidity now derive
  the same two digests. Answers external audit issues oak-sol-03 and
  oak-sol-06.
