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
- an `account` policy wrapper
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

- use raw verification only when the calling system already owns freshness and
  replay state
- prefer the canonical action / rotation flows in the account wrapper when the
  use case is account authorization rather than bare signature checking

### Replay protection lives at the account-policy layer

Replay resistance is provided by the higher-level account wrapper, not by raw
signature verification alone.

The account layer binds signatures to wrapper-owned state such as:

- domain separator
- nonce
- key version
- stateful leaf-use policy
- stateless usage accounting
- recovery mode

Guidance:

- production integrations should prefer canonical account-action and recovery
  flows over raw message validation
- if you bypass the account layer, you must implement equivalent freshness
  protections yourself

### Stateful signing must not reuse leaves

The stateful SHRINCS path depends on one-time leaf use.

Security implication:

- reusing a stateful signing leaf is a real misuse hazard
- production callers should use the canonical stateful signing flow that
  advances leaf state automatically

Guidance:

- do not build production systems around explicit-leaf signing helpers
- do not clone, roll back, or restore signer state in a way that can cause the
  same stateful leaf to sign twice
- if durable state is externalized, treat state advancement as security-critical

### Stateless recovery rotation is policy-gated

Stateless signatures are supported for recovery and rotation flows, but they are
 not intended to bypass wrapper policy.

Current intended model:

- normal stateful actions happen through the stateful path
- stateless recovery rotation is gated by:
  - `RecoveryRotation`
  - explicit `recoveryMode`

Guidance:

- use recovery/stateless signatures only through the intended canonical wrapper
  flows
- do not treat stateless signatures as unrestricted general-purpose authority in
  account-style integrations

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
- treat `public_key_commitment` as the installed bundle identifier for account
  and rotation flows

### Rust account layer is an off-chain adaptation

The Rust `account` module is intentionally close to the Solidity example wrapper
but is not a chain-enforced runtime.

Security implication:

- owner/caller checks in Rust are integration-supplied checks
- they are not equivalent to `msg.sender` enforcement on-chain

Guidance:

- do not assume the Rust account wrapper is a drop-in authority model for
  on-chain execution environments
- treat it as an off-chain policy/state-management helper that still depends on
  correct embedding by the integrating application

### WASM exports include low-level and high-level surfaces

The WASM layer exposes both primitive and wrapper-oriented APIs.

Security implication:

- JS/TS callers can reach low-level raw signing/verification functionality
- misuse is possible if integrations ignore canonical message construction or
  freshness state

Guidance:

- prefer the canonical action / rotation message-hash helpers when using the
  account wrapper from JS/TS
- prefer wrapper-driven flows over ad hoc raw-message signing for production
  authorization use cases

### Browser signer threat model

The wasm signer surface must be treated as running inside the browser's normal
same-origin trust boundary, not inside a hardened enclave.

Security implication:

- `WasmShrincsKeypair` keeps live signing-key material in wasm memory while the
  handle exists
- `exportSigningKey()` copies full secret signing state into JS-visible values
- any XSS, malicious same-origin script, compromised front-end dependency, or
  hostile extension able to run in the page context can exfiltrate that key

Guidance:

- do not expose the browser signer in pages that execute untrusted third-party
  JS
- do not treat browser local storage, IndexedDB, or ordinary JS heap state as a
  strong secret boundary
- use `destroy()` on `WasmShrincsKeypair` once a handle is no longer needed;
  this performs a best-effort early wipe and invalidates the handle
- treat `exportSigningKey()` as a backup / migration primitive, not a routine
  operational call

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
