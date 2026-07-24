# Security Considerations

This document outlines the security considerations for the hashsigs-rs project.

## Known Security Advisories

We regularly run `cargo audit` to check for known security vulnerabilities in our dependencies. As of the last update, we have identified and documented the following known issues:

### Transitive Dependencies from Solana

The following security advisories affect transitive dependencies from the Solana ecosystem that we cannot directly control:

#### RUSTSEC-2024-0344: Timing variability in curve25519-dalek
- **Affected crate**: `curve25519-dalek@3.2.0`
- **Source**: Solana's dependency on `ed25519-dalek@1.0.1`
- **Risk Assessment**: **Low**
- **Description**: This is a timing side-channel attack that would require local access and precise timing measurements to exploit.
- **Mitigation**: We are monitoring Solana's progress on updating their cryptographic dependencies. The vulnerability requires very specific conditions to exploit and is not practical in most deployment scenarios.

#### RUSTSEC-2022-0093: Double Public Key Signing Function Oracle Attack on ed25519-dalek
- **Affected crate**: `ed25519-dalek@1.0.1`
- **Source**: Solana's dependency on `ed25519-dalek@1.0.1`
- **Risk Assessment**: **Low**
- **Description**: This attack requires the ability to get signatures on crafted messages.
- **Mitigation**: Our use case does not allow arbitrary message signing, making this attack vector impractical.

### Unmaintained Dependencies

The following crates are flagged as unmaintained but do not pose immediate security risks:

- **RUSTSEC-2024-0375**: `atty` is unmaintained
- **RUSTSEC-2024-0388**: `derivative` is unmaintained
- **RUSTSEC-2024-0436**: `paste` is unmaintained
- **RUSTSEC-2021-0145**: `atty` potential unaligned read (unsound)

These are transitive dependencies from Solana and represent maintenance concerns rather than active security vulnerabilities.

#### Can These Dependencies Be Replaced?

**Short Answer**: Not practically, due to API incompatibilities and the fact that they're transitive dependencies from Solana.

**Detailed Analysis**:

1. **`atty` → `is-terminal`**: While `is-terminal` is the official replacement recommended by the `atty` maintainer, it has a different API. Cargo's `[patch]` feature cannot handle API changes, so this replacement would break the dependency chain.

2. **`derivative`**: Maintained alternatives exist (`derive_more`, `educe`, `derive-where`), but they have different APIs and feature sets. The `derivative` crate is used deep in the Solana dependency tree for specific derive macro functionality.

3. **`paste`**: This proc-macro crate is used for token pasting in macros. While flagged as unmaintained, it's still functional and has no direct drop-in replacement with identical API.

**Why Patching Doesn't Work**:
- These crates come from Solana's transitive dependencies, not our direct dependencies
- API differences between original and replacement crates prevent simple substitution
- Cargo's patch system requires identical APIs for successful replacement
- The unmaintained crates are used in test-only dependencies (`solana-program-test`), not production code

**Mitigation Strategy**:
- Monitor Solana's progress on updating their dependencies
- The security risk is minimal as these are maintenance warnings, not active vulnerabilities
- Consider using `--release` builds in production to minimize test dependency inclusion

## Security Best Practices

1. **Regular Audits**: We run `cargo audit` as part of our CI/CD pipeline to catch new vulnerabilities.

2. **Dependency Updates**: We regularly update dependencies to their latest secure versions where possible.

3. **Monitoring**: We monitor security advisories for the Solana ecosystem and will update our dependencies as soon as secure versions become available.

4. **Risk Assessment**: Each identified vulnerability is assessed for its practical impact on our specific use case.

## Cryptographic and Integration Security Notes

This repository now contains more than low-level hash-based signature
primitives. It includes:

- standalone `wotsplus` functionality
- core `shrincs` signer / verifier primitives
- a `wasm` export surface for JS/TS consumers

Those layers have different security responsibilities. The most important rule
for integrators is:

- low-level signature validity is not the same thing as replay protection or
  production-safe authorization

### Raw verification APIs are low-level

The core SHRINCS verifier exposes low-level raw verification functionality for
exact caller-supplied message bytes.

Security implication:

- these paths validate cryptographic correctness only
- they do **not** provide freshness, nonce management, replay protection, or
  policy enforcement on their own

Guidance:

- the calling system owns freshness, nonce management, and replay state; this
  library verifies signatures and nothing more
- build domain separation, nonces, and expiry into the message you hash before
  signing — the library has no place to enforce them for you

### Freshness and replay protection are the caller's responsibility

Signatures from this crate carry no replay protection and no freshness
guarantee. `sign` produces a signature over exactly the 32-byte digest it's
given, and `verify` checks exactly that signature against exactly that
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

- don't assume any nonce, sequence, or domain-separation enforcement exists
  inside this library — none does
- design the signed message, the 32-byte digest, to carry whatever freshness
  and replay-prevention data your app needs before it reaches `sign`

### Seed entropy is the caller's responsibility

`keygen` and `reset` require a caller-supplied 32-byte seed. The library has
no RNG fallback and performs no seed-quality check.

Security implication:

- a weak or predictable seed produces a weak key; the library can't detect
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
  using the signature for anything — a crash between signing and
  persisting is exactly the window that causes reuse on restart
- never sign again from a snapshot or clone taken before a later `sign()`
  call succeeded
- once the stateful budget runs out, switch to the stateless path or call
  `reset` with a fresh seed; don't work around the exhaustion error

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
- don't reintroduce message-specific replacement public keys
- treat `public_key_commitment` as the installed key's identifier for every
  verification call

### WASM exports are low-level signature primitives only

The WASM layer exposes a single noble-style signing/verification surface
(`sphincsPlusC`/`shrincs`, from `loadHashSigs()`). No higher-level,
policy-enforcing wrapper exists.

Security implication:

- `sphincsPlusC.sign()`/`verify()` and `shrincs.sign()`/`verify()` perform no
  freshness, replay, or authorization checks; they sign and verify exactly
  the 32-byte digest they're given
- misuse is possible if integrations treat a valid signature as proof of
  authorization by itself, without their own freshness and replay state

Guidance:

- build any authorization, freshness, or replay logic your app needs in the
  calling code, and fold the relevant context into the digest before
  signing: nonce, domain, action type, or whatever the use case requires
- see [Freshness and replay protection are the caller's responsibility](#freshness-and-replay-protection-are-the-callers-responsibility)

### Verifier timing / constant-time threat model

The SHRINCS verifier uses ordinary short-circuit equality (`==`) and early
`return false` on failed structural and root checks. It doesn't use
constant-time comparison (`subtle::ConstantTimeEq` or equivalent) for
public-key commitment, hypertree root, or intermediate hash equality.

Threat-model assumption:

- verification isn't assumed to resist a local timing adversary on the host
  that can measure sub-operation latency of `verify*` with chosen signatures
- remote network timing of full verification requests is outside the intended
  attacker model for this crate; deployments that face that threat should treat
  this as residual risk and add their own defenses if needed

Future work, not implemented: constant-time equality on the final root and
commitment checks, or a documented constant-time verification profile.

### Browser signer threat model

The wasm signer surface must be treated as running inside the browser's normal
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

- don't run the browser signer in pages that execute untrusted third-party JS
- treat browser local storage, IndexedDB, and ordinary JS heap state as a soft
  boundary, not a strong secret store
- for SHRINCS stateful signing, persist and reuse the same `keys` object.
  `shrincs.sign()` mutates `keys.stateful` in place on every call; never sign
  from a clone or a snapshot taken before an earlier `sign()` call, or you
  reuse a one-time leaf and break the signature's security
- zero each secret field (`skSeed.fill(0)`, `prfSeed.fill(0)`) once the key
  material is no longer needed

### WOTS+ robustness note

The standalone `wotsplus` module still includes length-sensitive code paths that
assume valid message sizing.

Security implication:

- this is primarily a robustness / DoS concern rather than a known signature
  forgery issue

Guidance:

- do not expose malformed or unvalidated untrusted message lengths to low-level
  WOTS+ APIs without caller-side validation
- treat the WOTS+ module as a low-level primitive surface, not a complete
  policy-enforcing application layer

## Reporting Security Issues

If you discover a security vulnerability in this project, please report it privately to:

**Email**: security at quip.network

### PGP Encryption (Recommended)

For sensitive security reports, please encrypt your message using our PGP key (Last Update 2024-11-14):

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

#### Download the Latest PGP Key

```bash
# Download from ProtonMail's key server
curl -s "https://api.protonmail.ch/pks/lookup?op=get&search=security@quip.network" | gpg --import

# Or download from a public key server
gpg --keyserver keyserver.ubuntu.com --recv-keys 0x1234567890ABCDEF

# Verify the key fingerprint matches the one listed above
gpg --fingerprint [email address]
```

**Note**: Please verify the key fingerprint matches the one listed above before encrypting sensitive information.

### What to Include in Your Report

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes or mitigations

We will acknowledge receipt of your report within 48 hours and provide a more detailed response within 7 days.

**Please do not create public issues for security vulnerabilities.**

## Audit Configuration

Our audit configuration is stored in `.cargo/audit.toml` and documents all known issues that we have assessed and decided to temporarily ignore while waiting for upstream fixes.

To run the security audit yourself:

```bash
cargo audit
```

This will use our configuration to show only new, unaddressed security issues.
