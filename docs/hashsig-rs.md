## hashsigs-rs

`hashsigs-rs` is the Rust implementation in the HashSigs workspace. The crate
now contains four main surfaces:

- `wotsplus`
  - standalone WOTS+ primitives and tests
- `shrincs`
  - SHRINCS signer / verifier primitives
  - stateful signing path
  - stateless signing, verification, and recovery/rotation helpers
- `account`
  - off-chain account-policy wrapper that tracks nonce, key version,
    stateful-leaf use, stateless usage, and recovery-mode transitions
- `wasm`
  - `wasm-bindgen` surface for TS/JS consumers
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

### WOTS+

The `wotsplus` module provides the lower-level Winternitz signature primitive
used independently in the repo and as a component inside the broader
SHRINCS-style construction.

### SHRINCS

The SHRINCS implementation combines:

- a stateful WOTS+-style path for normal signing
- a stateless FORS + hypertree path for recovery and rotation
- a fixed public-key model centered on:
  - `stateful_public_key`
  - `pk_seed`
  - `hypertree_root`
  - `public_key_commitment`

The long-lived public key is not message-specific. Stateless signatures are
verified against the original keygen public key, and the bundle is bound
together by `public_key_commitment`.

### Account wrapper

The Rust account wrapper is intentionally close to the Solidity example wrapper,
but it is still an off-chain adaptation rather than an execution-equivalent
runtime.

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

## WASM surface

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
program use. It is not the core cryptographic crate and should be treated as a
consumer/integration layer rather than the normative definition of SHRINCS.

## Test coverage

The repository currently includes:

- unit tests for WOTS+, SHRINCS, account, and wasm helper paths
- wasm-bindgen tests for real wasm-target binding execution
- SHRINCS test-vector generation and replay tests
- Solana integration tests

The authoritative cryptographic regression checks remain the Rust unit tests
and vector tests in this crate.

## Future improvements

### Synchronization and cleanup

The crate is now much more coherent than the earlier multi-surface state, but a
few cleanup tasks still remain important:

- keep the Rust, Solidity, and generated test-vector surfaces synchronized on
  the same SHRINCS public-key model
- continue tightening documentation so README, wasm docs, and repository notes
  describe the same API surface and security model
- keep test-only helper paths clearly separated from production signer and
  verifier flows
- preserve the distinction between:
  - core cryptographic primitives in `shrincs` and `wotsplus`
  - policy/state management in `account`
  - JS/TS bindings in `wasm`

This separation is the right long-term shape for the repo and should stay
explicit as new features are added.

### Toward a stronger proof story

The current Rust implementation is no longer just a WOTS+ library. It is a
hybrid SHRINCS-style construction with:

- a stateful path for normal use
- a stateless FORS + hypertree path for recovery and rotation
- an account wrapper that adds freshness and replay controls at the application
  layer

That means future proof-oriented work should be framed around the current
construction, not only around standalone WOTS+.

Areas that would improve the proof story or spec clarity include:

- making domain separation rules even more explicit across:
  - stateful signing
  - stateless FORS / hypertree signing
  - public-key commitment derivation
  - account-level action and rotation message hashing
- documenting which components are intended to be long-lived key material and
  which are per-signature or per-action values
- documenting more clearly where this implementation intentionally diverges from
  proof-oriented reference formulations such as structured-address SPHINCS+/XMSS
  style presentations
- tightening invariants around one-time/stateful leaf use so misuse-resistant
  wrappers remain the default integration pattern

For the standalone `wotsplus` module specifically, a future proof-hardening pass
could still revisit stricter address/domain separation and error handling
semantics, but that work should be described as one component of the crate
rather than the whole repository story.

### Replay and policy hardening

The Rust repo now has a clearer separation between:

- primitive verification logic in `shrincs`
- policy-enforcing wrapper logic in `account`
- transport/binding logic in `wasm`

That separation is good, but replay and misuse resistance still depend on using
the right layer for the right job.

Important future hardening directions include:

- keeping raw verification paths clearly marked as low-level or test-oriented
  where they do not enforce freshness by themselves
- continuing to steer production integrations toward canonical account-action
  flows rather than raw message verification
- making stateful leaf advancement and recovery-mode transitions durable and
  observable in higher-level integrations
- deciding whether the Rust account layer should eventually expose stronger
  observability primitives analogous to Solidity-side events
- extending wasm examples and packaging guidance so JS/TS consumers are pushed
  toward canonical action/rotation transcripts instead of ad hoc raw-message
  use

In other words, the cryptographic primitives and the account-policy wrapper now
exist in the same crate, but they still serve different purposes. Future work
should keep the unsafe-footgun surface small and make the canonical path the
easiest path to integrate.

## Documentation scope

This document is a repository-orientation note for the current Rust crate. It
is not a formal specification of the SHRINCS construction and it does not try
to compare every implementation in the wider HashSigs family.
