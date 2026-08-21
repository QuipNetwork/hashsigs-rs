# Security considerations

This document describes the security considerations for the hashsigs-rs project.

## Known security advisories

CI runs `cargo deny check` (the `supply-chain` job), which scans `Cargo.lock` against the RustSec advisory database. The policy lives in `deny.toml`. The list below is current as of 2026-08-20.

### Transitive dependencies from Solana

The following security advisories affect transitive dependencies from the Solana ecosystem that the project cannot directly control:

#### RUSTSEC-2024-0344 (timing variability in curve25519-dalek)
- Affected crate: `curve25519-dalek@3.2.0`
- Position: dev-dependencies only, through `ed25519-dalek@1.0.1` under `solana-program-test` (the validator test harness)
- Risk assessment: low
- Description: a timing side channel in scalar subtraction. Exploitation requires local access and precise timing measurements.
- Mitigation: the affected version never ships. The library, the wasm package, and the deployed Solana program build with the patched `curve25519-dalek@4.1.3`.

#### RUSTSEC-2022-0093 (double public key signing function oracle attack on ed25519-dalek)
- Affected crate: `ed25519-dalek@1.0.1`
- Position: dev-dependencies only, under `solana-program-test` (the validator test harness)
- Risk assessment: low
- Description: the attack requires signatures on crafted messages from the affected signer.
- Mitigation: the affected version never ships, and this project signs nothing with ed25519.

### Unmaintained dependencies

The RustSec database lists the following transitive crates as unmaintained. None is an active vulnerability:

- **RUSTSEC-2025-0141**: `bincode@1.3.3` is unmaintained. The Solana program dependency graph reaches it through `agave-precompiles`, so `deny.toml` carries a dated ignore entry.
- **RUSTSEC-2024-0388**: `derivative` is unmaintained. Dev-dependencies only (`solana-program-test`).
- **RUSTSEC-2024-0436**: `paste` is unmaintained. Dev-dependencies only (`solana-program-test`).
- **RUSTSEC-2025-0161**: `libsecp256k1` is unmaintained. Dev-dependencies only (`solana-program-test`). `cargo deny check` scopes unmaintained advisories to direct dependencies, so this entry needs no `deny.toml` ignore.

These are transitive dependencies from Solana and represent maintenance concerns rather than active security vulnerabilities.

#### Why these dependencies are not replaced

Replacement is not practical. The crates are transitive dependencies from Solana, and the maintained alternatives have incompatible APIs.

1. **`derivative`**: maintained alternatives exist (`derive_more`, `educe`, `derive-where`), but they have different APIs and feature sets. The Solana dependency tree uses `derivative` deep inside for specific derive macros.

2. **`paste`**: this proc-macro crate does token pasting in macros. The advisory flags it as unmaintained, but the crate still works. No drop-in replacement with an identical API exists.

3. **`bincode`**: `agave-precompiles` uses the 1.x line. The maintained 2.x line has a different API, so a `[patch]` substitution cannot work.

**Why patching fails**:
- These crates come from Solana's transitive dependencies, not this project's direct dependencies
- API differences between original and replacement crates prevent simple substitution
- Cargo's patch system requires identical APIs for successful replacement

**Mitigation**:
- Track Solana's progress on updated dependencies
- The security risk is minimal because these are maintenance warnings, not active vulnerabilities
- Dev-dependencies never appear in published artifacts. The crate, the wasm package, and the deployed program build only from normal dependencies.

## Security best practices

1. **Regular audits**: `cargo audit` runs as part of the CI/CD pipeline to catch new vulnerabilities.

2. **Dependency updates**: the project updates dependencies to their latest secure versions where possible.

3. **Advisory tracking**: the project tracks security advisories for the Solana ecosystem and updates dependencies as soon as secure versions become available.

4. **Risk assessment**: the project assesses each identified vulnerability for its practical impact on this specific use case.

## Cryptographic and integration security notes

This repository now contains more than low-level hash-based signature
primitives. It includes:

- the standalone `wotsplus` module
- core `shrincs` signer / verifier primitives
- a `wasm` export surface for JS/TS consumers

Those layers have different security responsibilities. The most important rule
for integrators is:

- low-level signature validity is not the same thing as replay protection or
  production-safe authorization

### Raw verification APIs are low-level

The core SHRINCS verifier exposes raw, low-level verification of exact
caller-supplied message bytes.

Security implication:

- these paths check cryptographic correctness only
- they do not provide freshness, nonce management, replay protection, or
  policy enforcement on their own

Guidance:

- the calling system owns freshness, nonce management, and replay state
- this library verifies signatures and nothing more
- build domain separation, nonces, and expiry into the message you hash before
  signing. The library cannot enforce them for you

### Freshness and replay protection are the caller's responsibility

Signatures from this crate carry no replay protection and no freshness
guarantee. `sign` produces a signature over exactly the 32-byte digest it
receives, and `verify` checks exactly that signature against exactly that
digest. Neither call knows whether anyone signed or verified the digest
before.

Integrators must build their own:

- nonce or sequence-number tracking
- domain separation (chain ID, contract address, action type, or a
  comparable value, folded into the digest before signing)
- expiry or freshness windows, if the use case needs them

For the stateful SHRINCS path, replay resistance also depends on leaf-use
discipline. The caller must persist key state and never resubmit a
signature produced by a leaf already consumed. See
[Stateful signing must not reuse leaves](#stateful-signing-must-not-reuse-leaves)
below.

Guidance:

- do not assume this library enforces nonces, sequence numbers, or domain
  separation. It does not
- design the signed message, the 32-byte digest, to carry whatever freshness
  and replay-prevention data your app needs before it reaches `sign`

### Seed entropy is the caller's responsibility

`keygen` and `reset` require a caller-supplied 32-byte seed. The library has
no RNG fallback and does not check seed quality.

Security implication:

- a weak or predictable seed produces a weak key. The library cannot detect
  this and derives a key from it regardless
- there is no library-side entropy source to fall back on if the caller
  supplies bad input

Guidance:

- generate the seed with a cryptographically secure source: `crypto.getRandomValues`
  in the browser, `crypto.randomBytes`/webcrypto in Node, or the platform CSPRNG
  in other host environments
- never derive a seed from predictable input such as a counter, timestamp, or
  user-supplied password without a proper key-derivation function
- the same rule applies to the seed passed to `reset`

### Stateful signing must not reuse leaves

The stateful SHRINCS path depends on one-time leaf use. Each `sign()` call
consumes one leaf and advances the in-memory key state. Signing twice from
the same state reuses a leaf, breaks the one-time-signature security the
scheme depends on, and can expose enough of the secret key to forge further
signatures under that leaf.

Security implication:

- signing from a stale copy of the key state (a clone, a snapshot taken
  before an earlier `sign()` call, or a value not yet written back after a
  crash) causes a leaf reuse
- the library enforces exhaustion: once the leaf budget runs out, `sign()`
  throws instead of reusing a leaf

Guidance:

- persist the current key state after every stateful `sign()` call, before
  you use the signature for anything. A crash between signing and
  persisting is exactly the window that causes reuse on restart
- never sign again from a snapshot or clone taken before a later `sign()`
  call succeeded
- once the stateful budget runs out, switch to the stateless path or call
  `reset` with a fresh seed. Do not work around the exhaustion error

Persisted-state rollback:

- the persisted secret carries the leaf counter, but `import` accepts any
  in-range counter. It cannot distinguish a current key from an older
  serialized snapshot restored from a backup. Restoring an older persisted
  copy and signing re-consumes already-used leaves: the same catastrophic
  reuse as signing from a stale in-memory clone.
- a stateless library owns no persistent state, so it cannot enforce
  anti-rollback on its own. The caller must persist a monotonic high-water
  mark for the leaf index and refuse to load or sign below it. The Solana
  example program (`solana/examples/shrincs-account`) enforces exactly this
  on-chain: its account state rejects a non-monotonic leaf index with
  `StatefulIndexRollback`. Treat that program as the reference for the
  guarantee off-chain callers must provide themselves.

### Public-key commitment binding is security-critical

The current SHRINCS design uses a fixed public-key model tied together by
`public_key_commitment`.

Security implication:

- verification depends on correctly binding:
  - `stateful_public_key`
  - `pk_seed`
  - `hypertree_root`
- callers must not treat those components as independently swappable fields

Guidance:

- always verify against the installed/original public key bundle
- do not reintroduce message-specific replacement public keys
- treat `public_key_commitment` as the installed key's identifier for every
  verification call

### WASM exports are low-level signature primitives only

The WASM layer exposes a single noble-style signing/verification surface
(`sphincsPlusC`/`shrincs`, from `loadHashSigs()`). No higher-level,
policy-enforcing wrapper exists.

Security implication:

- `sphincsPlusC.sign()`/`verify()` and `shrincs.sign()`/`verify()` apply no
  freshness, replay, or authorization checks. They sign and verify exactly
  the 32-byte digest they receive
- an integration invites misuse when it treats a valid signature alone as
  proof of authorization and keeps no freshness or replay state of its own

Guidance:

- build any authorization, freshness, or replay logic your app needs in the
  calling code, and fold the relevant context into the digest before
  signing: nonce, domain, action type, or whatever the use case requires
- see [Freshness and replay protection are the caller's responsibility](#freshness-and-replay-protection-are-the-callers-responsibility)

### Verifier timing / constant-time threat model

The SHRINCS verifier uses ordinary short-circuit equality (`==`) and early
`return false` on failed structural and root checks. It does not use
constant-time comparison (such as `subtle::ConstantTimeEq`) for
public-key commitment, hypertree root, or intermediate hash equality.

Threat-model assumption:

- verification is not assumed to resist a local timing adversary on the host
  that can measure sub-operation latency of `verify*` with chosen signatures
- remote network timing of full verification requests is outside the intended
  attacker model for this crate. Deployments that face that threat should treat
  this as residual risk and add their own defenses if needed

Future work, not implemented: constant-time equality on the final root and
commitment checks, or a documented constant-time verification profile.

### Browser signer threat model

Treat the wasm signer surface as code that runs inside the browser's normal
same-origin trust boundary, not inside a hardened enclave.

Security implication:

- secret key material is a set of plain `Uint8Array` fields the caller holds
  directly: `keys.secret.skSeed`/`prfSeed` for SPHINCS+C, and
  `keys.stateful.secret.skSeed`/`prfSeed` plus `keys.stateless.secret.skSeed`/`prfSeed`
  for SHRINCS, all returned by `sphincsPlusC.keygen()` / `shrincs.keygen()`
  (or reconstructed by `shrincsImportSigningKey`)
- any XSS, malicious same-origin script, compromised front-end dependency, or
  hostile extension able to run in the page context can read those fields
  directly from JS

Guidance:

- do not run the browser signer in pages that execute untrusted third-party JS
- treat browser local storage, IndexedDB, and ordinary JS heap state as a soft
  boundary, not a strong secret store
- for SHRINCS stateful signing, persist and reuse the same `keys` object.
  `shrincs.sign()` mutates `keys.stateful` in place on every call. Never sign
  from a clone or a snapshot taken before an earlier `sign()` call, or you
  reuse a one-time leaf and break the signature's security
- zero each secret field (`skSeed.fill(0)`, `prfSeed.fill(0)`) once the key
  material is no longer needed

### WOTS+ robustness note

The standalone `wotsplus` module is the legacy v1 scheme: do not use it for
new integrations. Use SHRINCS. It remains only to keep v1 wallets
verifiable.

The module still includes length-sensitive code paths that assume valid
message sizing.

Security implication:

- this is primarily a robustness / DoS concern rather than a known signature
  forgery issue

Guidance:

- check the length of untrusted messages in the caller before you pass them
  to a low-level WOTS+ API
- treat the WOTS+ module as a low-level primitive surface that enforces no
  policy

## Reporting security issues

To report a security vulnerability in this project, send a private email to:

**security at quip.network**

### PGP encryption (recommended)

For sensitive security reports, encrypt your message with the project PGP key (last updated 2024-11-14):

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: ProtonMail

xjMEaJt7+hYJKwYBBAHaRw8BAQdAYjy3Rqa6cdJsK1keoMTmfj1clsryEvQi
vEjaqTEa2xfNLXNlY3VyaXR5QHF1aXAubmV0d29yayA8c2VjdXJpdHlAcXVp
cC5uZXR3b3JrPsLAEQQTFgoAgwWCaJt7+gMLCQcJkNiLJOxMcokIRRQAAAAA
ABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmee0QrLmO7tOgWYl29h
GqHifldyZ2WPGmsc8ySr2ATCKAMVCggEFgACAQIZAQKbAwIeARYhBHNRtQVW
BVD7YgIrYdiLJOxMcokIAADj/wD+O85VPvR+Nblf+ooEgMQem8qRYNxBhUaP
1lyMSmoV3XgBAPi20j/UC4yfC0ZnfYtV058zfE7BST2q7aNvLY3T+qoBwsAe
BBAWCACQBYJom3w3BYMA7U4ACRDYBsGvWXjoxzUUAAAAAAAcABBzYWx0QG5v
dGF0aW9ucy5vcGVucGdwanMub3JnlhQSiICxkiypXOcKcTzkVywcb3BlbnBn
cC1jYUBwcm90b24ubWUgPG9wZW5wZ3AtY2FAcHJvdG9uLm1lPhYhBAqGUv5d
UzhgV4mf6dgGwa9ZeOjHAABzowD+MYKxGoCzLbl7U0Jd6/ZSZSwPXvWKJjpf
7JiYELMXm7IBANGVF5Mxgj8LA8LqNh6y0TxS14MqYRRk1jQNISLO6+0AzjgE
aJt7+hIKKwYBBAGXVQEFAQEHQG7ytnodbovlbtXvc6klzyGPtnVRPJ6EyiKE
4gxeC/l0AwEIB8K+BBgWCgBwBYJom3v6CZDYiyTsTHKJCEUUAAAAAAAcACBz
YWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jnt3zwK9JEzu9mrN5lajCGqt/I
ULIIwaKSgecqmFTtaoMCmwwWIQRzUbUFVgVQ+2ICK2HYiyTsTHKJCAAAA2UB
AK9+2eIPYiWJNt5kMaBYcx6dbjU7C62u2/86sw1DLArJAP9CK/C1LoTovZ89
pW7gWQHbPY6BA6dzdWbnxsDDY/fjBQ==
=SWOf
-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `7351 B505 5605 50FB 6202  2B61 D88B 24EC 4C72 8908`

#### Download the current PGP key

```bash
# Download from ProtonMail's key server
curl -s "https://api.protonmail.ch/pks/lookup?op=get&search=security@quip.network" | gpg --import

# Or download from a public key server
gpg --keyserver keyserver.ubuntu.com --recv-keys 0xD88B24EC4C728908

# Verify the key fingerprint matches the one listed above
gpg --fingerprint security@quip.network
```

Verify that the key fingerprint matches the fingerprint listed in this document before you encrypt sensitive information.

### What to include in your report

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes or mitigations

The maintainers acknowledge receipt of your report within 48 hours and send a detailed response within 7 days.

**Do not create public issues for security vulnerabilities.**

## Audit configuration

The audit configuration in `.cargo/audit.toml` documents all known issues that the project has assessed and chosen to ignore until upstream fixes arrive.

To run the security audit yourself:

```bash
cargo audit
```

The audit uses this configuration and shows only new, unaddressed security issues.
