# SHRINCS on Ledger Nano Gen5

This folder contains the Ledger app, Docker build, native fixture generator,
APDU client, and Speculos/USB tests. Run everything from this repository; no
`hdwallets.dev` checkout or external scheme symlink is needed.

The first milestone is **stateful signature verification on the device** using
the real `hashsigs-rs` crate with `default-features = false`, `alloc`,
`profile-256s-sha2`, and `heap-buffers`. The host generates public deterministic
fixtures for four sequential signing leaves; the Gen5 app verifies their
canonical SHRINCS envelopes. The app also retains the SHA-256 and on-screen
approve/reject smoke flow from the Rust boilerplate.

Key generation and signing currently run in the host fixture generator.
The device app does not derive wallet secrets, sign, or persist key state.
Stateless verification and signing need a separate memory implementation:
the core ABI decoder creates temporary copies of the much larger stateless
envelope. Passing these tests is an embedded portability result, not a complete
hardware-wallet signer or an independent cryptographic audit.

## Build and test

Docker is the only host build dependency. From the `hashsigs-rs` root:

```sh
make -C ledger test
make -C ledger test PYTEST_ARGS="-v"
make -C ledger test PYTEST_ARGS="-k shrincs"
make -C ledger build
make -C ledger run
```

`test` builds the image, checks Rust formatting, runs the native fixture
generator during the build, and executes Ragger against the exact Gen5 ELF in
Speculos. Network access is disabled during the test run. Initial builds download
the pinned toolchain and locked dependencies; later builds use Docker's cache.

`build` writes `artifacts/app.elf`, `artifacts/vectors.json`, and their
`artifacts/SHA256SUMS` inside this folder. These generated files are ignored by
Git. `run` exposes the emulator UI at <http://localhost:5000>; Ctrl-C stops it.

Docker must be accessible to your user. If a new Docker group membership has
not reached your shell, use `sg docker -c 'make -C ledger test'`. The Docker
command and image tag can be overridden with `DOCKER` and `IMAGE`.

The Dockerfile is in this folder but uses the repository root as its build
context, so the app can depend on the current Rust source via `path = "../.."`.
`Dockerfile.dockerignore` limits the context. Python/Solana manifests are copied
for Cargo workspace resolution; their bindings are not linked into the device.
The app and host tool are independent Cargo workspaces with separate lockfiles.
Ordinary root `cargo test` does not build the Ledger SDK.

Validated on 2026-09-21: **45 Speculos tests passed**, including a canonical
4 KiB envelope, all four signing leaves, rejection/recovery, and repeated
verification. App and host Rust formatting checks passed. The ELF reports
API level 26 and target ID `0x33400004`; physical hardware has not been run.

## Physical Nano Gen5

Install this app using Ledger's development tooling and open **SHRINCS Lab**.
Confirm that the device LedgerOS supports the SDK/API used by the image before
sideloading. Installation is a separate operator action; these tests do not
install apps, change a wallet seed, or update firmware.

Find the connected device's USB node, then run:

```sh
make -C ledger test-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD
```

Replace `BBB/DDD` with the actual device node. Only this explicit target exposes
USB to the container, using Ragger's `ledgerwallet` backend. The same signature
vectors and APDU client are used on both backends. Automated touchscreen tests
and malformed transport frames are marked `emulator_only` and skipped on USB.
App-level invalid-input tests still run. Normal host USB access permissions
must allow the invoking user to open the device.

Physical-device execution has not been validated yet. The app contains no test
seed or private-key import command; the deterministic fixture seed lives only
in `host/src/main.rs`.

## Protocol version 1

CLA is `0xE0`; short APDUs carry at most 255 bytes. Integers are big-endian.
P1/P2 are zero except on `WRITE_VERIFY`, where they encode the byte offset.

| INS | Operation | Request | Successful response |
| --- | --- | --- | --- |
| `03` | Version | Empty | Three version bytes |
| `04` | App name | Empty | Cargo package name |
| `05` | Profile | Empty | Protocol byte, maximum envelope `u16`, profile ID `[32]`, profile name ASCII |
| `10` | SHA-256 | Message, P1=`0` or `1` for review | Digest `[32]` |
| `20` | Begin verification | Commitment `[32]`, prehash `[32]`, envelope length `u32` | Session ID `u32` |
| `21` | Write envelope | Session ID `u32`, 1–251 envelope bytes | Received byte count `u16` |
| `22` | Finish verification | Session ID `u32` | `00` valid, `01` invalid, `02` malformed |
| `23` | Cancel | Empty | Empty |

Only one upload can be active. A second begin, premature finish, and operation
without a session are rejected. Stale IDs, duplicate/reordered chunks, empty
chunks, overflow, and oversized envelopes are rejected without advancing the
upload. Completed verification consumes the session for every verdict. Cancel
discards it. IDs increase within one app run and are not persistent across
restart. Hosts must discard upload state when reconnecting.

Verification uses `ShrincsVerifier::verify`, including its canonical ABI
decoder and commitment/message domain binding. Cryptographic rejection is an
explicit verdict with APDU success (`9000`); callers must accept only verdict
`00`. Errors: `6985` review denied, `6986` wrong session state, `6A80` bad data,
`6A86` bad P1/P2, `6D00` unknown instruction, `6F00` internal error. The SDK
uses `6E00` for wrong CLA and `6E03` for malformed APDU length.

## Memory and build pins

The pinned Gen5 target reserves 40 KiB SRAM. This prototype assigns 20 KiB to
the SDK heap and limits incoming envelopes to 4 KiB. Positive tests use capacity
four; the input limit is not a claim of support for the core library's maximum
4096-leaf capacity. ELF section sizes are not a peak stack/heap measurement.
Hashing uses the core's portable SHA-256 and Keccak implementations; a Ledger
hash-acceleration backend is not implemented.

- Builder: immutable digest in `Dockerfile`.
- Rust: `nightly-2026-04-15`, satisfying the core's Rust 1.95 requirement.
- The Gen5 target specification is copied from the builder's pinned original
  toolchain. Newer Rust requires the custom-target flags configured here.
- Rust SDK: `ledger_device_sdk = 1.36.1`; transitive dependencies in
  `app/Cargo.lock`, with `--locked` builds.
- C SDK: `/opt/apex-secure-sdk` in the pinned builder.
- Speculos `0.27.0`, Ragger `1.47.3`, pytest `8.4.2`; Python pins are in
  `requirements.txt`.

The smoke app was adapted from [Ledger's Rust boilerplate at
66cbb087aa6a1c0fd20853119f7814a27cf8c43a](https://github.com/LedgerHQ/app-boilerplate-rust/tree/66cbb087aa6a1c0fd20853119f7814a27cf8c43a).
Its Apache-2.0 notice/license is retained in `app/LICENSE.md`, including for
the two crab icons. The combined SHRINCS app and new code use AGPL-3.0-or-later,
matching the core library.

## Next implementation milestones

1. Measure stack/heap peaks and verification latency on real Gen5 hardware.
2. Define isolated device key derivation and a versioned persistent record.
3. Add on-device key generation and stateful signing, with user review and
   durable leaf reservation before producing signature bytes.
4. Test interruption, exhaustion, restart, and lost-state recovery behavior.
5. Add bounded-memory stateless operations and host verification of signatures
   produced by the device. Retain independent vectors for cryptographic checks;
   the host fixture generator here uses the same Rust implementation.
