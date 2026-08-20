# shrincs-account-example

A Solana program demonstrating the SHRINCS account pattern. State lives in a
Program Derived Address (PDA): an account owned by the program that installs
a commitment to a SHRINCS bundle and verifies stateful and stateless actions
against it. Owner-directed recovery and key rotation build on the same
verification primitives (`ShrincsVerifier::verify_stateful` / `verify_stateless`,
`ActionContext`) from the core `hashsigs-rs` crate.

This is reference and demonstration code. No audit has reviewed it, and it
isn't intended to hold or move production funds. It's a separate Cargo
workspace member, not part of `hashsigs-rs-solana`'s core library.

## Identity model

The account PDA (`ShrincsAccountState`) tracks:

- `current_public_key_commitment`: the installed SHRINCS bundle commitment,
  the account's trusted identity.
- `nonce` and `key_version`: consumed on every successful action and rotation,
  binding each signature to a specific point in the account's history.
- `owner`: the `Pubkey` allowed to change policy and arm recovery mode.

Every action verifies against an `ActionContext` built from `nonce`,
`key_version`, an action-type tag, a payload hash, and a domain separator:

```text
domain_separator = keccak256(keccak256("shrincs-account-v1") || program_id || account_pubkey)
```

The deployed program id stands in for Solidity's `chainid`; the PDA's own
pubkey stands in for `address(this)`. An off-chain signer must compute this
domain separator, or call `messages::domain_separator`, to build the context
an instruction accepts.

## Stateful leaf policy

A stateful signature's `auth_path` is an unbalanced authentication path whose
length is also its leaf index, so the leaf index is bound by the signature
itself and never taken from a caller-supplied field. Two policies guard
against leaf reuse, which would compromise the stateful key:

- `MonotonicIndex` (default): accepts only the leaf at
  `next_stateful_leaf_index`, then advances it by one.
- `LeafBitmap`: accepts any leaf not yet marked used, tracked in a per-word
  bitmap PDA created on first use (see "Intentional divergences from
  Solidity" below for a limitation on these PDAs after rotation).

A third policy, `RecoveryRotation`, disables the stateful path entirely and
hands authority to stateless recovery signatures (see "Recovery and
rotation").

## Instructions

One handler per `ShrincsAccountInstruction` variant, dispatched from
`process_instruction`:

- `Init`: creates the account PDA with an installed commitment and the
  default `MonotonicIndex` policy starting at leaf 1.
- `VerifyStatefulAction` / `VerifyStatelessAction`: verify a signed action
  against the installed commitment, advance `nonce`, and (stateful only)
  advance or mark the leaf policy.
- `SetPolicyMonotonic` / `SetPolicyRecoveryRotation` / `SetPolicyLeafBitmap`:
  owner-gated policy setters.
- `EnterRecoveryMode`: owner-gated; arms stateless recovery under
  `RecoveryRotation` policy.
- `RotateToFreshKey` / `RotateFullKey`: install a new commitment, authorized
  by a stateless recovery signature (see below).
- `IsValidSignature`: read-only ERC-1271-style query against the current
  commitment and nonce.
- `IsLeafUsed`: read-only bitmap query.

## Recovery and rotation

An owner switches the account to `RecoveryRotation` policy and calls
`EnterRecoveryMode`. From there, a stateless signature from the *current*
installed key authorizes installing a new commitment:

- `RotateToFreshKey` keeps the current stateless half and replaces only the
  stateful bundle.
- `RotateFullKey` replaces both halves.

Neither rotation instruction takes an owner signer. The stateless recovery
signature is the sole authorization once recovery mode is armed.

While recovery mode is armed, the stateless key holds full stateless-*action*
authority, not merely a single rotation: any number of `VerifyStatelessAction`
calls and rotations are accepted until a rotation clears `recovery_mode` (or
the owner reconfigures the policy). Arming recovery is an owner-gated grant of
that authority, not a one-shot ticket.

## Intentional divergences from Solidity

1. **Rotation authorizes through an ordinary action.** Solidity authorizes
   rotation through `rotateStatefulViaStateless`/`statelessRotate` over a
   dedicated message hash. This crate instead builds an `ActionContext` like
   any other action, tagged `ACTION_ROTATE_STATEFUL` or `ACTION_ROTATE_FULL`
   (`keccak256("shrincs-account-example/rotate-stateful")` /
   `keccak256("shrincs-account-example/rotate-full")`), and verifies it
   through the same public `verify_stateless` every other stateless action
   uses. A signature built for Solidity's rotation preimage won't verify
   here, and vice versa. The payload hashes:
   - `ACTION_ROTATE_STATEFUL`: `keccak256(next_stateful_public_key ||
     next_commitment)`
   - `ACTION_ROTATE_FULL`: `keccak256(next_stateful_public_key ||
     next_pk_seed || next_hypertree_root || next_commitment)`

   This is deliberate: the core `hashsigs-rs` crate stays a pure signature
   primitive with no rotation-shaped opinions (the account layer was removed
   from core in the redesign this example replaces), and this example owns
   its own wrapper-message convention.

2. **Rotation doesn't decrement `stateless_signatures_used`.** The deleted
   port did. The stateless recovery signature that authorizes each rotation
   isn't counted against the budget either. This is benign:
   `STATELESS_SIGNATURE_LIMIT` (2^18 to 2^20 depending on profile) is a policy
   cap on an effectively unlimited SPHINCS+C stateless key, and rotations are
   rare relative to that budget.

3. **Leaf-bitmap word PDAs are orphaned on rotation.** They're not closed or
   rent-refunded when the account rotates to a new `key_version`. This
   matches the last-shipped Solana behavior; it's a known limitation, not a
   fix made in this pass.

## Build and deploy

The example targets the `128s` profile (`profile-128s-q18` on
`hashsigs-rs`). A 256s stateless signature is ~30 KB, which exceeds the
Solana transaction Maximum Transmission Unit (1,232 bytes) and would need
delivery staged across several transactions. The 128s profile keeps
signatures small enough to fit a single instruction.

Build with:

```bash
cargo build-sbf
```

The crate is a `cdylib` with its own `entrypoint!`, and depends on
`hashsigs-rs-solana` with `no-entrypoint` to reuse its DTOs
(`ShrincsPublicKeyDto`, `StatefulSignatureDto`, `StatelessSignatureDto`)
without pulling in that crate's own entrypoint.

## Solidity parity

See [`docs/solidity-parity.md`](../../../docs/solidity-parity.md) for the
full parity inventory, including this example's rotation divergence.
