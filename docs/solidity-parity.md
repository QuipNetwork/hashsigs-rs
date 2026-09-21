# Solidity parity

This document records feature and design parity between this crate and
hashsigs-solidity (`create-x-deployment` branch, commit `dd71249`). The last
audit, on 2026-07-22, used a two-sided surface inventory plus a line-by-line
account-wrapper audit. A 2026-07-24 pass refreshed the module paths for the
`hash/` split and the `primitives` dissolution.

## At parity

- Crypto core: verify and rotation paths for WOTS-C, FORS-C, the hypertree,
  UXMSS, SPHINCS+C, and SHRINCS. The six profiles, the commitment scheme,
  the four canonical message hashes, and the keccak and sha2 hash suites
  are also at parity. Rust-anchored vectors, consumed on both sides,
  cross-pin the core (256s keccak and sha2, and both 128s sha2 twins).
  `shrincs-128s-q18-sha2` and `shrincs-128s-q20-sha2` carry matching
  `contracts/profiles/` libraries, matching `PROFILE_ID` values, and the
  Rust-generated SPHINCS stateless vectors that
  `SHRINCSSphincs128sVectors.t.sol` verifies under each.
- Layering: the scheme-neutral building blocks (`src/hash/`, `src/abi.rs`,
  `src/buf.rs`, `src/profiles.rs`, `src/treehash.rs`) sit at the crate
  root. `src/sphincs_plus_c/` owns FORS-C and the hypertree (`fors_c` ↔
  `FORSMinusC.sol`, `hypertree` ↔ `Hypertree.sol`) and does not reference
  SHRINCS. `src/shrincs/` builds the hybrid on top of it.
- `shrincs::signature` (composite envelope codecs) and `shrincs::dispatch`
  (`prepare_stateless_delegation`): byte-exact Solidity ABI encoders and
  strict decoders for every envelope shape named in the Solidity contracts.
  This includes the ERC-1271 mode-1/2 action envelopes. The codecs build on
  the shared `crate::abi` primitives. Per-scheme signature bodies live in
  their scheme modules (`wots_c`,
  `sphincs_plus_c::{fors_c, hypertree, signature}`). Vector blobs exported
  from Solidity pin the codecs byte-for-byte.
- `shrincs::ShrincsVerifier` provides `verifier::VerifierInterface`
  (`verify`) and mirrors `SHRINCSVerifier.sol` (32-byte commitment key,
  stateful envelope, tri-state outcome, `version_tag()` pins).
  `SphincsPlusCVerifier` (also `VerifierInterface`) mirrors
  `SPHINCSPlusCVerifier.sol`.
- Solana program: verify-only instructions for SPHINCS+C, SHRINCS stateless,
  and SHRINCS stateful.

## Intentional divergences (do not port)

- EIP-1153 transient attestation (`verifyAndAttest`/`wasVerified`,
  `IERC7913TransientAttestation`): an EVM transaction-scoped mechanism with
  no host or Solana analogue.
- Calldata zero-copy acceptance widening (re-tag reads bounds-checked
  against `calldatasize`, and tail-truncated envelopes verify under
  masked-hash profiles): documented Solidity malleability. Rust decoders
  are strict and fail closed. A wrong-accept cannot happen in either
  direction.
- `read_bits` past the logical end: by design, Solidity reads adjacent
  calldata. Rust returns `None`.
- Deployment: the EVM side uses CreateX/CREATE3 deterministic addresses,
  and Solana uses program-id keypairs and verifiable builds.
- Typed `AccountError` (10 variants) instead of Solidity's boolean/revert
  model (approved in MR !2 review).
- Rust `SCREAMING_SNAKE_CASE` constants versus Solidity PascalCase
  specification names.

## Maintainer decisions pending

1. **Recovery-rotation freeze exemption (audit F1).** Solidity requires an
   unfrozen policy to enter `RecoveryRotation`. But the first stateful use
   freezes the policy, and only rotation unfreezes it. A used
   monotonic/bitmap account can never rotate. Rust exempts that
   one setter from the freeze check. The audit traced the Solidity behavior
   and confirmed the lockout. Recommendation: keep the Rust behavior and
   fix `SHRINCSAccountVerifierExample.sol` upstream.
2. **Stateless budget reset on full rotation (audit F2).** Solidity resets
   the budget unconditionally. Rust resets it only when the stateless key
   material changed, because a fresh budget for a reused few-time key
   permits over-use. Recommendation: adopt the Rust behavior upstream.
3. **Rotation calldata decoders.** The envelope codec does not parse the
   `rotateToFreshKey`/`rotateFullKey` `abi.encodeCall` shapes because
   `SHRINCS.sol` names no envelope for them. Oracle-decoded fields pin the
   rotation vectors instead.

## Cross-language vector status

- Solidity signs and Rust verifies at 256s (keccak and sha2). A fresh forge
  1.7.1 run of `dev/export-account-vectors.sh` reproduces the committed
  fixture byte-identically.
- Rust signs and Solidity verifies at 128s (q18 and q20). In-EVM 128s
  stateless signing is compute-infeasible, and the Solidity export test
  sits in the 128s skip lists. The Rust generator in
  `tests/generate_shrincs_vectors.rs` produces the fixtures, and
  `test/SHRINCSRustAccountVectors128s.t.sol` consumes them on the Solidity
  side. Each profile runs 12 checks: both action verifies with
  message-hash equality, both rotations with commitment equality, and
  tamper rejections. All pass at q18 and q20. Gas at 128s: stateful verify
  102,574, stateless verify 247,632, rotations ~255K. The Solidity-side
  test lives uncommitted in the hashsigs-solidity worktree pending
  upstream adoption. Regenerate a fixture with `cargo test --release
  --features experimental-profile-128s-q18 --test generate_shrincs_vectors
  generate_shrincs_account_wrapper_vectors -- --ignored --nocapture` (the
  run takes minutes per profile). The ten dependent tests in
  `solidity_account_vectors.rs` and `envelope_vectors.rs` run un-ignored
  under both 128s profiles.

## SHRINCS account example

The redesign removed the SHRINCS account state machine from the
`hashsigs-rs` core. The state machine now lives in
[`solana/examples/shrincs-account/`](../solana/examples/shrincs-account/),
a standalone workspace member built on the retained public primitives
(`ShrincsVerifier::verify_stateful`/`verify_stateless`, `ActionContext`).
See that crate's README for the full instruction set and policy model.

The example's key rotation authorizes through an ordinary action (an
`ActionContext` digest tagged `ACTION_ROTATE_STATEFUL`/`ACTION_ROTATE_FULL`),
not Solidity's dedicated `rotateStatefulViaStateless`/`statelessRotate`
preimage. A signature built for Solidity's rotation message hash does not
verify against this example. The reverse also fails. This is deliberate:
the example owns its own wrapper-message convention. The core crate stays
a pure signature primitive with no rotation conventions.

## Known gaps

- No test drives the account state machine against Solidity-produced call
  traces. The exported `*_verify_calldata`/`*_1271_envelope` blobs are
  byte-pinned through the codec but not replayed against a
  vector-controlled account instance. The vectors do not export the
  generating chain id or contract address.
- Upstream follow-ups for hashsigs-solidity: adopt
  `SHRINCSRustAccountVectors128s.t.sol` plus the two 128s fixtures, fix
  the rotation lockout (maintainer decision 1), and adopt the conditional
  stateless budget reset (decision 2).

## Solana compute units

All figures come from the real program binary in the SBF virtual machine.

| Instruction | 256s | 256s-sha2 | 128s-q18 | 128s-q18-sha2 |
|---|---|---|---|---|
| SPHINCS+C stateless verify | 1,028,136 | 930,115 | 106,555 | — |
| SHRINCS stateless verify | 1,029,780 | 931,804 | — | — |
| SHRINCS stateful verify | 111,586 | 101,909 | 58,461 | — |

No SBF run has covered `128s-q18-sha2` or `128s-q20-sha2`. The program builds
against them through `--features hashsigs-rs/experimental-profile-128s-q18-sha2`, so these
cells are unmeasured rather than unavailable. Do not copy the keccak twin's
figure across: the SHA-256 syscall and the keccak syscall charge differently.
`128s-q20` and `128s-q20-sha2` share every crypto constant with their q18
counterparts, so their costs derive rather than needing their own run.

WOTS+ v1 verify (legacy scheme, not for new integrations): 298,064 CU. The
instruction pins keccak hashing, so the figure does not depend on the
compiled profile (measured under the sha2 build).

The 256s-sha2 and WOTS+ figures come from a 2026-08-20 run with
platform-tools v1.54 (rustc 1.89). The crate's `rust-version = "1.95"` pin
makes `cargo build-sbf` refuse to compile with those tools, so the build
passed `--ignore-rust-version` through to cargo:

```bash
cargo build-sbf --manifest-path solana/Cargo.toml -- \
  --features hashsigs-rs/profile-256s-sha2 --ignore-rust-version
SBF_OUT_DIR=$PWD/target/deploy cargo test -p hashsigs-rs-solana \
  --features hashsigs-rs/profile-256s-sha2 --test solana_unit_tests -- \
  --nocapture test_sphincs_plus_c_verify_valid \
  test_shrincs_verify_stateless_valid test_shrincs_verify_stateful_valid \
  test_verify_valid_signature
```

Payloads carrying a 256s stateless signature (~30 KB) need
`ComputeBudgetInstruction::request_heap_frame`. The program ships an
unbounded bump allocator (`custom-heap`, default) because the entrypoint
default is compile-time capped at 32 KiB and ignores the granted frame.
A 256s signature also exceeds the 1,232-byte transaction MTU. Real
deployments need account-staged delivery or the 128s profile.
