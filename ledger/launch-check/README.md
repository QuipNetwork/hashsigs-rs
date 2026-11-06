# Gen5 launch control

`SHRINCS Launch` 0.1.0 is the minimal SDK-only control for the
[reset investigation](../docs/gen5-reset-reproduction.md). It uses the same
pinned Rust SDK, target, heap allocation, and NBGL home/exit API as HW Check.
It has no scheme dependency, key derivation, application NVM, permission probes,
or key-generation command. Its unused SLIP21 namespace and installation name
are separate; install flags are the same unverified-app flags as HW Check.

Build and test from the repository root:

```sh
make -C ledger test-launch-check
```

Artifacts are exported to `ledger/artifacts/launch-check/`. Archive the ELF and
generated installation script before installation. This target does not expose
USB or install an app. The two tests check the discovery/unsupported-command
behavior and ELF/install isolation. CLA is `E3`; `03` returns version `00 01 00`,
and `04` returns `hashsigs-ledger-launch-check`. Both take empty data and zero
P1/P2. The SDK supplies the normal on-device exit and BOLOS exit handling.

The first control ELF used on 2026-11-06 has SHA-256
`5dbf7f4af277182c5d2232fa2368926e08b151ec1485ce538be8e4a6bf4788bd`.
This controls the developer-app launch path, not the memory layout of the full
HW Check app. A clean control run does not prove the latter is safe.
