## hashsigs-rs

`hashsigs-rs` is the Rust implementation in the HashSigs workspace. The crate
currently exposes four main surfaces:

- `wotsplus`
  - standalone WOTS+ primitives and tests
- `shrincs`
  - SHRINCS signer / verifier primitives
  - stateless FORS-C plus hypertree signing and verification
  - JARDIN-style compact FORS-C slot keygen and signing
- `account`
  - off-chain account-policy wrapper that tracks nonce, key version, stateless
    usage, compact slots, and direct key rotation
- `wasm`
  - temporarily gated while the compact/stateless-only binding surface is
    rebuilt

## Current Repo Structure

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

## Cryptographic Layout

### WOTS+

The `wotsplus` module provides the lower-level Winternitz signature primitive
used independently in the repo and as a component inside the broader
SHRINCS-style construction.

### SHRINCS

The SHRINCS implementation combines:

- a stateless FORS-C plus hypertree path for account actions and key rotation
- a JARDIN-style compact FORS-C path for registered compact slots
- a direct public-key model centered on:
  - `pkSeed`
  - `hypertreeRoot`

The long-lived public key is not message-specific. Stateless signatures verify
against the installed `pkSeed` and `hypertreeRoot`, and compact signatures
verify against slot-specific `(subPkSeed, subPkRoot)` values registered by the
account wrapper.

### Account Wrapper

The Rust account wrapper is intentionally close to the Solidity example wrapper,
but it is still an off-chain adaptation rather than an execution-equivalent
runtime.

It owns and advances:

- `nonce`
- `keyVersion`
- `statelessSignaturesUsed`
- compact slot registrations

It exposes canonical verification and rotation paths for:

- stateless account actions
- compact-slot registration
- compact-slot revocation
- compact registered-slot actions
- full stateless key rotation

The wrapper derives its domain separator from stored `chainId` and
`contractAddress`, matching the Solidity-side intent.

## WASM Surface

The `src/wasm/` module is currently gated out of normal builds while the
compact/stateless-only bindings are rebuilt.

Current known gaps:

- no WOTS+-specific wasm bindings yet
- no published npm package flow yet
- compact/stateless account bindings still need a final JS/TS-facing API pass

## Solana Integration

The `solana/` workspace member is a separate integration surface for Solana
program use. It is not the core cryptographic crate and should be treated as a
consumer/integration layer rather than the normative definition of SHRINCS.

## Test Coverage

The repository currently includes:

- unit tests for WOTS+, SHRINCS, and account paths
- SHRINCS test-vector generation and replay tests
- Solidity-compatible compact/stateless vector fixtures
- Solana integration tests

The authoritative cryptographic regression checks remain the Rust unit tests
and vector tests in this crate.

## Future Improvements

### Synchronization And Cleanup

Important cleanup work remains:

- keep the Rust, Solidity, and generated test-vector surfaces synchronized on
  the same public-key model
- continue tightening documentation so README, wasm docs, and repository notes
  describe the same API surface and security model
- keep test-only helper paths clearly separated from production signer and
  verifier flows
- preserve the distinction between:
  - core cryptographic primitives in `shrincs` and `wotsplus`
  - policy/state management in `account`
  - JS/TS bindings in `wasm`

### Toward A Stronger Proof Story

The current Rust implementation is a hybrid SHRINCS-style construction with:

- a stateless FORS-C plus hypertree path
- a compact JARDIN-style registered-slot path
- an account wrapper that adds freshness and replay controls at the application
  layer

Areas that would improve the proof story or spec clarity include:

- making domain separation rules even more explicit across:
  - stateless FORS-C / hypertree signing
  - compact FORS-C signing
  - account-level action and rotation message hashing
- documenting which components are intended to be long-lived key material and
  which are per-signature or per-action values
- documenting more clearly where this implementation intentionally diverges from
  proof-oriented reference formulations such as structured-address SPHINCS+/XMSS
  style presentations

For the standalone `wotsplus` module specifically, a future proof-hardening pass
could still revisit stricter address/domain separation and error handling
semantics, but that work should be described as one component of the crate
rather than the whole repository story.

### Replay And Policy Hardening

The Rust repo has a clear separation between:

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
- deciding whether the Rust account layer should eventually expose stronger
  observability primitives analogous to Solidity-side events
- extending wasm examples and packaging guidance so JS/TS consumers are pushed
  toward canonical action/rotation transcripts instead of ad hoc raw-message
  use

## Documentation Scope

This document is a repository-orientation note for the current Rust crate. It
is not a formal specification of the SHRINCS construction and it does not try
to compare every implementation in the wider HashSigs family.
