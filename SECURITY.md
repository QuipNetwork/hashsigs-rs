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
