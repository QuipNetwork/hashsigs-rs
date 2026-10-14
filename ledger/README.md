# SHRINCS on Ledger Nano Gen5

This folder contains the Ledger app, Docker build, native fixture generator,
APDU client, and Speculos/USB tests. Run everything from this repository; no
`hdwallets.dev` checkout or external scheme symlink is needed.

The app implements **full hybrid key creation, persistent reload, public-key
export, and stateful signature verification** using
the real `hashsigs-rs` crate with `default-features = false`, `alloc`,
`profile-256s-sha2`, and `heap-buffers`. The host generates public deterministic
fixtures for four sequential signing leaves; the Gen5 app verifies their
canonical SHRINCS envelopes. The app also retains the SHA-256 and on-screen
approve/reject smoke flow from the Rust boilerplate.

App **0.2.0, protocol 2** derives an isolated SLIP21 key from the active wallet,
generates a fresh public generation ID after approval, and stores the complete
capacity-four hybrid key in authenticated NVM. Both tree roots are computed
on-device. Key creation never replaces an existing identity. Signing remains
host-only; the device advertises capabilities `0x00000003`, with signing disabled.
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
make -C ledger measure
```

`test` builds the image, checks Rust formatting, runs the native fixture
generator and storage fault tests, and executes Ragger against the exact Gen5 ELF in
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
The app, host tool, and device-independent `common/` storage crate are independent
Cargo workspaces with separate lockfiles;
the Python and Solana bindings are not needed in the image or build context.
Ordinary root `cargo test` does not build the Ledger SDK.

The original verification baseline passed 45 Speculos tests and 41 hardware
tests (4 deselected) on 2026-09-23. The ELF targets API 26, ID `0x33400004`.
The new key-management tests additionally cover SLIP21/public-key agreement,
approval/rejection, restart, lost replies, wrong-seed and corrupted-record locks,
competing APDUs during review, and a fresh identity after simulated reinstall.
See [validation evidence](docs/hashsig-spec.md#8-acceptance-evidence-and-remaining-device-assumptions).

Validated on 2026-10-12: **61 Speculos/ELF tests passed in 33.17 seconds**;
all three Rust formatting checks and **8 native storage tests** passed.
Normal app ELF SHA-256:
`8a1699d36e87f0d392fa147cd4ad22146f0a3baf092b9d6755ec660cf6cfe5bb`.

The eight native storage tests exercise 1,539 interrupted-write prefixes across
the three creation writes, every single-byte corruption in both 512-byte blocks,
silent short writes, authenticated metadata inconsistencies, and exhaustion.
They model storage faults; they do not establish physical flash guarantees.

Pinned Speculos 0.27.0 excludes Rust apps from its NVRAM file support. The
[explicit test adapter](tests/enable_rust_nvram.py) supplies the Rust memory
region to its existing C persistence implementation. Restart tests initialize
the first file from ELF data (including SDK PIC tables), then reuse the written
file across separate processes. Ordinary tests leave that adapter inactive.
The firmware ELF is unmodified and contains no seed-import or storage-edit APDU.

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
malformed transport frames. That result applies to app 0.1.0. No Ledger was
connected for the 2026-10-12 implementation session, so app 0.2.0 installation,
physical key creation/reboot, actual flash interruption, watchdog behavior, and
hardware memory/timing measurements remain unvalidated. The ordinary USB suite
does not approve key creation automatically.

An earlier attempt stopped after 30 passes because USB disconnected during the
one-byte upload. After reconnecting and reopening the app, the complete suite
passed without changing the app or weakening the tests. The disconnect's cause
was not established.

After a reconnect, unlock the wallet, open **SHRINCS Lab**, and rerun
`lsusb -d 2c97:` to find its current bus/device number before setting `USB_DEVICE`. Close
Ledger Wallet and other test processes so they do not compete for USB access.
The app contains no test seed or private-key import command; the deterministic
fixture seeds live only in host tools and Speculos test configuration.

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

These verification commands remain available in protocol 2. `GET_PROFILE` now
reports protocol `2`; the version command reports app `0.2.0`.

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

## Protocol version 2 key management

The [signer contract](docs/hashsig-spec.md) specifies all byte layouts and state
rules. This slice implements the following commands; P1/P2 are zero.

| INS | Operation | Request | Successful response |
| --- | --- | --- | --- |
| `06` | Get info | Empty | Protocol/spec/capabilities, profile, boot nonce and limits (69 bytes) |
| `30` | Create key | Profile ID `[32]`, capacity `u32=4` | Commitment `[32]`, public length `u16=480`, after approval and durable storage |
| `31` | Get public key | Commitment `[32]`, offset `u16`, length `u8=1..200` | Commitment, total length, offset, exact requested chunk |
| `32` | Get state | Empty | State, commitment, generation, counters, sequence and operation (110 bytes) |

Create requires EMPTY and IDLE. The device displays the complete commitment
after durable creation; either final acknowledgement button closes that screen.
If the success response is lost, recover with state/public-key reads. Repeating
create cannot replace the key. Cancel clears only verification RAM. There is
no host reset, import, replacement, or secret-export command. Signing commands
`40`–`43` return `6D00`.

Storage uses a 512-byte payload and a separate, 512-byte-aligned commit marker.
MAC verification precedes secret parsing. A torn or invalid record locks the
wallet; there is no fallback to an earlier record. A coherent older snapshot
is outside this experiment's rollback model. Losing app state requires a fresh
identity, even with the same mnemonic. Installation grants only SLIP21 mask
`08` and namespace `quip.network/SHRINCS/v1`; the ELF test checks the actual TLV.

Additional errors: `6984` locked record, `6A81` unsupported profile/capacity,
`6A88` unknown commitment, `6581` storage failure (locks this app instance).
Competing commands during review receive `6986`; the reviewed request stays
unchanged and touch processing continues.

## Memory and build pins

The pinned Gen5 target reserves 40 KiB SRAM. This prototype assigns 20 KiB to
the SDK heap and limits incoming envelopes to 4 KiB. Positive tests use capacity
four; the input limit is not a claim of support for the core library's maximum
4096-leaf capacity. ELF section sizes are not a peak stack/heap measurement.
Hashing uses the core's portable SHA-256 and Keccak implementations; a Ledger
hash-acceleration backend is not implemented.

`make -C ledger measure` builds a separate `memory-metrics` ELF in a disposable
container. It uses the SDK's allocator implementation with allocation counters
and the SDK stack paint/scan tracker. Its app-name APDU ends in `-metrics`; the
read-only `E0 F0` metrics command exists only in this build. The normal app and
its exported `artifacts/app.elf` stay unchanged. The report and metrics ELF are
saved under `artifacts/benchmarks/<timestamp>/`; `BENCH_OUTPUT` overrides it.

On 2026-10-12, run `20261012-keygen` measured:

| Operation reached | Peak heap bytes | Peak app stack bytes | Stack headroom bytes |
| --- | ---: | ---: | ---: |
| Startup | 72 | 7,768 | 10,720 |
| Full keygen, commit and public export | 2,732 | 11,272 | 7,216 |
| Then verify a canonical 4 KiB envelope | 16,796 | 11,272 | 7,216 |

The heap allocation was 20,480 bytes and measured app stack capacity 18,488
bytes. Keygen-to-completion-screen elapsed time was **1.928 s**, including
automated approval navigation. This is one emulator run, not hardware CPU
latency or a worst-case bound. Peaks accumulate from startup; syscall stack
usage is not measured. Metrics ELF SHA-256:
`d2fbbd3b7180faf3eadbe00f7b463c82b42a123f6319728de663b808be5d922a`.

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

The [signer contract](docs/hashsig-spec.md) defines protocol 2,
SLIP-0021 derivation namespace, authenticated persistent record, leaf reservation,
and retry behavior for a capacity-four signer. It includes a public KDF check
vector and initial resource acceptance bounds. Key creation/storage/public
queries are implemented; signing and durable leaf reservation remain future work.

1. Install app 0.2.0 on a disposable Gen5 setup, validate the narrow derivation
   permissions, create a key, record its public key/state, and verify it after
   actual app exit and device power cycle. Measure keygen/watchdog/memory behavior.
2. Validate physical NVM ordering, durability, erase isolation and interrupted
   writes; emulator persistence is supporting evidence only.
3. Add stateful signing, with digest/key/leaf review and durable reservation
   before producing signature bytes, once those hardware gates pass.
4. Test interruption, exhaustion, restart, and lost-state recovery behavior.
5. Add bounded-memory stateless operations and host verification of signatures
   produced by the device. Retain independent vectors for cryptographic checks;
   the host fixture generator here uses the same Rust implementation.
