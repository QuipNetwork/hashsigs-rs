## `hashsigs-rs`

`hashsigs-rs` is the Rust codebase in the HashSigs workspace. The crate now
contains four main surfaces:

- `wotsplus`
  - standalone WOTS+ primitives and tests (legacy v1: do not use for new
    integrations)
- `shrincs`
  - SHRINCS signer / verifier primitives
  - stateful signing path
  - stateless signing, verification, and recovery/rotation helpers
- `account`
  - off-chain account-policy wrapper that tracks nonce, key version,
    stateful-leaf use, stateless usage, and recovery-mode transitions
- `wasm`
  - `wasm-bindgen` surface for JS/TS consumers
  - verifier bindings
  - signer/keygen bindings
  - account-wrapper bindings
  - canonical action / rotation message-hash helpers

## Current repo structure

```text
hashsigs-rs/
├── bin/
│   └── build-wasm.sh
├── docs/
│   └── hashsig-rs.md
├── solana/
│   ├── src/
│   └── tests/
├── src/
│   ├── account/
│   ├── shrincs/
│   ├── wasm/
│   ├── wotsplus/
│   └── lib.rs
└── tests/
    ├── generate_shrincs_vectors.rs
    ├── test_vectors.rs
    └── test_vectors/
```

## Cryptographic layout

### WOTS+ (legacy)

The `wotsplus` module provides the standalone Winternitz one-time signature
(WOTS+) primitive that shipped as the v1 wallet scheme. The module is legacy:
do not use it for new integrations. Use SHRINCS. The module is not a SHRINCS
component: the SHRINCS paths build on the separate target-sum `wots_c` module.

### SHRINCS

The SHRINCS code combines:

- a stateful WOTS+-style path for normal signing
- a stateless FORS (forest of random subsets) and hypertree path for recovery
  and rotation
- a fixed public-key model centered on:
  - `stateful_public_key`
  - `pk_seed`
  - `hypertree_root`
  - `public_key_commitment`

The long-lived public key is not message-specific. The verifier checks
stateless signatures against the original keygen public key.
`public_key_commitment` binds the bundle together.

### Account wrapper

The Rust account wrapper stays intentionally close to the Solidity example
wrapper. It remains an off-chain adaptation, not a runtime that matches
Solidity execution.

It owns and advances:

- `nonce`
- `keyVersion`
- `statefulPolicy`
- `nextStatefulLeafIndex`
- `statelessSignaturesUsed`
- `recoveryMode`

It exposes canonical verification and rotation paths for:

- `verifyStatefulAction(...)`
- `verifyStatelessAction(...)`
- `rotateToFreshKey(...)`
- `rotateFullKey(...)`

The wrapper derives its domain separator from stored `chainId` and
`contractAddress`, matching the Solidity-side intent.

## WebAssembly surface

The `src/wasm/` module provides TS-friendly bindings through `wasm-bindgen`.

Current exported capabilities include:

- SHRINCS key generation
- raw stateful and stateless signing
- raw and canonical verification helpers
- canonical action / rotation message-hash helpers
- account-wrapper construction, verification, policy changes, and recovery-mode
  transitions

Current known gaps:

- no WOTS+-specific wasm bindings yet
- no published npm package flow yet
- real wasm-target tests exist, but CI automation for them is still separate
  work

## Solana integration

The `solana/` workspace member is a separate integration surface for Solana
program use, not the core cryptographic crate. Treat it as a consumer and
integration layer, not as the normative definition of SHRINCS.

## Test coverage

The repository includes:

- unit tests for WOTS+, SHRINCS, account, and wasm helper paths
- wasm-bindgen tests for real wasm-target binding execution
- SHRINCS test-vector generation and replay tests
- Solana integration tests

The authoritative cryptographic regression checks remain the Rust unit tests
and vector tests in this crate.

## Future improvements

### Synchronization and cleanup

The crate is now more coherent than the earlier multi-surface state, but these
cleanup tasks remain:

- keep the Rust, Solidity, and generated test-vector surfaces synchronized on
  the same SHRINCS public-key model
- continue tightening documentation so README, wasm docs, and repository notes
  describe the same API surface and security model
- keep test-only helper paths separate from production signer and verifier
  flows
- keep the distinction between:
  - core cryptographic primitives in `shrincs` and `wotsplus`
  - policy/state management in `account`
  - JS/TS bindings in `wasm`

This separation is the right long-term shape for the repository. Keep it
explicit as new features arrive.

### Toward a stronger proof story

The current Rust crate is no longer just a WOTS+ library. It now forms a
hybrid SHRINCS-style construction with:

- a stateful path for normal use
- a stateless FORS and hypertree path for recovery and rotation
- an account wrapper that adds freshness and replay controls at the
  application layer

Frame future proof-oriented work around the current construction, not only
around standalone WOTS+.

Areas that would improve the proof story or specification clarity include:

- making domain separation rules more explicit across:
  - stateful signing
  - stateless FORS and hypertree signing
  - public-key commitment derivation
  - account-level action and rotation message hashing
- documenting which components are long-lived key material and which are
  per-signature or per-action values
- documenting where this crate intentionally diverges from proof-oriented
  reference formulations such as structured-address SPHINCS+/XMSS style
  presentations
- tightening invariants around one-time/stateful leaf use so misuse-resistant
  wrappers remain the default integration pattern

For the standalone `wotsplus` module, a future proof-hardening pass could
still revisit stricter address/domain separation and error-handling semantics.
Describe that work as one component of the crate, not as the whole repository
story.

### Replay and policy hardening

The Rust repository now has a clearer separation between:

- primitive verification logic in `shrincs`
- policy-enforcing wrapper logic in `account`
- transport/binding logic in `wasm`

That separation is good, but replay and misuse resistance still depend on
using the right layer for the right job.

Future hardening directions include:

- keeping raw verification paths marked as low-level or test-oriented where
  they do not enforce freshness by themselves
- continuing to steer production integrations toward canonical account-action
  flows rather than raw message verification
- making stateful leaf advancement and recovery-mode transitions durable and
  observable in higher-level integrations
- deciding whether the Rust account layer should eventually expose stronger
  observability primitives like Solidity-side events
- extending wasm examples and packaging guidance to steer JS/TS consumers
  toward canonical action/rotation transcripts instead of ad hoc raw-message
  use

The cryptographic primitives and the account-policy wrapper now exist in the
same crate, but they serve different purposes. Future work should keep the
unsafe-footgun surface small and make the canonical path the easiest path to
integrate.

## Documentation scope

This document is a repository-orientation note for the current Rust crate,
not a formal specification of the SHRINCS construction. It does not compare
every codebase in the wider HashSigs family.
