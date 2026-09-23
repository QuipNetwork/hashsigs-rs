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

Make and Docker are the host build dependencies. From the `hashsigs-rs` root:

```sh
make -C ledger test
make -C ledger test PYTEST_ARGS="-v"
make -C ledger test PYTEST_ARGS="-k shrincs"
make -C ledger build
make -C ledger run
```

`test` builds the image, checks Rust formatting, runs the native fixture
generator during the build, and executes Ragger against the exact Gen5 ELF in
Speculos. The image includes both `ragger[speculos,ledgerwallet]` backends and
checks their concrete imports during the build, without needing USB access.
Network access is disabled during the test run. Initial builds download
the pinned toolchain and locked dependencies; later builds use Docker's cache.

`build` writes `artifacts/app.elf`, `artifacts/vectors.json`, and their
`artifacts/SHA256SUMS` inside this folder. These generated files are ignored by
Git. `run` exposes the emulator UI at <http://localhost:5000>; Ctrl-C stops it.

Every build checks Docker availability before doing any work. A missing CLI,
an unreachable daemon, or denied access stops the flow with Docker's diagnostic
(when available) and instructions to install Docker, start the daemon, or fix
user access. Run just this check with `make -C ledger check-docker`.

Docker must be accessible to your user. If a new Docker group membership has
not reached your shell, use `sg docker -c 'make -C ledger test'`. The Docker
command and image tag can be overridden with `DOCKER` and `IMAGE`; the availability
check uses the same `DOCKER` command and selected context as the build.

The Dockerfile is in this folder but uses the repository root as its build
context, so the app can depend on the current Rust source via `path = "../.."`.
`Dockerfile.dockerignore` limits the context to the root crate and Ledger files.
The app and host tool are independent Cargo workspaces with separate lockfiles;
the Python and Solana bindings are not needed in the image or build context.
Ordinary root `cargo test` does not build the Ledger SDK.

Validated on 2026-09-23: **45 Speculos tests passed**, including a canonical
4 KiB envelope, all four signing leaves, rejection/recovery, and repeated
verification. App and host Rust formatting checks passed. The ELF reports
API level 26 and target ID `0x33400004`. The physical Nano Gen5 suite also
passed: **41 tests passed**, with 4 emulator-only cases deselected.

## Physical Nano Gen5

Install this app using Ledger's development tooling and open **SHRINCS Lab**.
Confirm that the device LedgerOS supports the SDK/API used by the image before
sideloading. Installation is a separate operator action; these tests do not
install apps, change a wallet seed, or update firmware.

Find the connected device's USB node, then run:

```sh
make -C ledger test-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD
```

Replace `BBB/DDD` with the actual device node. The explicit `test-hardware` and
`bench-hardware` targets expose USB to the container, using Ragger's
`ledgerwallet` backend. The same signature
vectors and APDU client are used on both backends. Automated touchscreen tests
and malformed transport frames are marked `emulator_only` and skipped on USB.
App-level invalid-input tests still run. Normal host USB access permissions
must allow the invoking user to open the device.

The hardware target stops at the first failure and uses a thread watchdog for
its 60-second per-test timeout. The pinned `ledgerwallet` transport can block
indefinitely waiting for the first HID response; Python's signal-based timeout
may not interrupt that native read. On timeout, the watchdog prints thread
stacks and terminates pytest, so fixture teardown and normal summary output may
be absent. The test fails rather than waiting indefinitely. This bounds a lost
USB response; it does not establish why the device stopped responding.

For a focused retry of the third signature (32-byte chunks), use:

```sh
make -C ledger test-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD \
  PYTEST_ARGS="-v --tb=short -k 'test_valid_signatures and apex_p-2-32'"
```

Add `--log-cli-level=INFO` to `PYTEST_ARGS` when debugging to display each APDU
and response as it happens. Close any previous test runner and reopen the app
before retrying after a timeout; do not run two USB test processes concurrently.

The hardware backend runs inside Docker. Installing `ledgerblue` in a host
virtual environment for sideloading does not install the separate `ledgerwallet`
Python dependency in the image. If an older image reports `This backend needs
LedgerWallet`, rerun this target with the current checkout to rebuild it with the
pinned hardware dependencies.

Validated on a physical Nano Gen5 on 2026-09-23, with operator-reported
LedgerOS 1.1.1: **41 passed, 4 deselected in 22.04 seconds**, using the thread
watchdog and `PYTEST_ARGS="-v --tb=short --log-cli-level=INFO"`. This includes all four host-generated stateful
signatures, the one-byte upload case, invalid-input handling, and the 4 KiB
boundary case. The excluded cases are automated hash approval/rejection and two
malformed transport frames. Manual hardware approval/rejection and peak stack/heap
measurements remain outstanding; the app still does not generate keys or sign.

An earlier attempt stopped after 30 passes because USB disconnected during the
one-byte upload. After reconnecting and reopening the app, the complete suite
passed without changing the app or weakening the tests. The disconnect's cause
was not established.

After a reconnect, unlock the wallet, open **SHRINCS Lab**, and rerun
`lsusb -d 2c97:` to find its current bus/device number before setting `USB_DEVICE`. Close
Ledger Wallet and other test processes so they do not compete for USB access.
The app contains no test seed or private-key import command; the deterministic
fixture seed lives only in `host/src/main.rs`.

## Verification timing and parameters

With **SHRINCS Lab** open on the connected device, run from the repository root:

```sh
make -C ledger bench-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD
```

The benchmark verifies each of the four public fixture signatures five times
for warmup, then records 30 measurements per signature. All uploads use
251-byte chunks (12 WRITE commands per envelope), allowing comparisons between
leaves without changing the upload chunk size. Every measured verdict must be
valid. No keys or signatures are generated on the device.

`FINISH_VERIFY` is timed separately from `BEGIN_VERIFY` and signature upload,
using the host's monotonic `perf_counter_ns` clock. Its duration includes the USB
round trip, host/firmware processing, canonical ABI decoding, and cryptographic
verification. It is not an instrumented device CPU measurement. The total
covers BEGIN, all WRITE commands, and FINISH; setup, warmup, and the separate
version query are excluded. Ragger APDU logging is disabled during measurement.
A version-command round trip is recorded for transport context and is not
subtracted from the results.

Override `BENCH_SAMPLES` and `BENCH_WARMUP` if needed. The existing thread
watchdog still applies per leaf; for longer runs, increase its limit with
`PYTEST_ARGS="--timeout=180"`. Raw nanosecond samples, min/median/p95/max,
app/profile information, package versions, and build/vector/script hashes are
saved to `artifacts/benchmarks/<UTC timestamp>/verify-leafN.json`. Override
`BENCH_OUTPUT` to choose a different output directory. The recorded build ELF
hash identifies the expected local build; it is not an attestation of the
installed device binary. This opt-in benchmark is outside the default `tests/`
path and does not increase the ordinary test suite's case count.

Measured on 2026-09-23 on the physical Nano Gen5, with operator-reported
LedgerOS 1.1.1 and app version 0.1.0. Run `20260923T120251Z` completed all four
benchmark cases: 120 measured successful verifications plus 20 warmups.

| Leaf | Envelope bytes | Verify median (ms) | Verify p95 (ms) | Upload median (ms) | Total median (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 2784 | 123.082 | 124.021 | 129.991 | 258.066 |
| 2 | 2816 | 123.071 | 124.993 | 130.993 | 259.076 |
| 3 | 2848 | 124.018 | 124.119 | 130.025 | 259.036 |
| 4 | 2880 | 124.079 | 124.653 | 132.963 | 263.055 |

Across all 120 samples, median verification was **123.999 ms** and median total
was **260.012 ms**. The median version-command round trip was **3.968 ms**.
p95 uses the nearest-rank method. These results measure four fixed signatures
from one key and do not characterize every key, message, or tree capacity.

Expected build ELF SHA-256:
`4b832e0552fcbb2e95d1d8d854649006c9deb017b1387321ffedd1b266e5206b`.
Fixture JSON SHA-256:
`6e0fd371e4109793b46e326f748c102e687bf4d968bb7fc252bdff160c106828`.

The app and host select [`shrincs-256s-sha2`](../src/profiles/p256s_sha2.rs).
The measured signatures use its stateful UXMSS/WOTS-C path:

| Parameter | Value |
| --- | --- |
| Scheme hash suite | SHA-256; 32-byte hash output |
| WOTS-C base / chain length parameter | 16; at most 15 hash steps per chain |
| WOTS-C chains | 64 |
| WOTS-C target digit sum | 480 |
| Stateful key capacity | 4 signatures in these fixtures |
| Leaves / authentication path nodes | Leaves 1–4; respectively 1–4 nodes in an unbalanced tree |
| Message prehash | 32 bytes; fixture N uses byte N repeated 32 times |
| Commitment and domain binding | Keccak-256 |

The profile ID reported by the device is
`807de98ac65ab9f03289950d1878e5ec5261f162af5593ccba2f1709c793c2bb`.
The deterministic public fixture seed and key generation/signing are in
[`host/src/main.rs`](host/src/main.rs). Envelope sizes above include the ABI
encoding and public-key bundle, not just the packed stateful signature.

The same profile also defines the stateless component: signature limit
2^20, hypertree height 64 with 8 layers, 22 FORS trees of height 14, and a
FORS-C grinding-counter limit of 2^24. **Those stateless operations are not
exercised by this benchmark.** Hashing currently uses portable Rust code;
Ledger hash acceleration is not implemented.

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

1. Measure stack/heap peaks on real Gen5 hardware. Host-observed verification
   latency is recorded above; instrument device CPU time if needed.
2. Define isolated device key derivation and a versioned persistent record.
3. Add on-device key generation and stateful signing, with user review and
   durable leaf reservation before producing signature bytes.
4. Test interruption, exhaustion, restart, and lost-state recovery behavior.
5. Add bounded-memory stateless operations and host verification of signatures
   produced by the device. Retain independent vectors for cryptographic checks;
   the host fixture generator here uses the same Rust implementation.
