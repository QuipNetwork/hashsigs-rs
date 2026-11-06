# Gen5 full-budget key-generation measurement — 2026-11-06

The operator requested a real-size key generation and hardware timing after
the capacity-four measurements. This run uses the core library's maximum
supported **4,096 stateful signatures**, with the complete `shrincs-256s-sha2`
stateless parameters. There is no single mandatory production capacity; 4,096
is the supported maximum chosen for this experiment.

The separate [SHRINCS Keygen](../keygen-bench/README.md) app computes a fresh
hybrid key from device randomness, retains its public encoding, and drops the
secret key. It has no application NVM or signing API. This measures full hybrid
key generation, not persistent-wallet creation or signing at capacity 4,096.
Neither the ordinary app's capacity-four contract nor the archived incident
firmware was changed.

## Build and validation

Source base: `d318a45`, plus the separate benchmark and recorded transport.
SDK 1.36.1, Gen5 `apex_p`, API 26; portable SHA-256 scheme hashing and the
same 20,480-byte measured allocator. Local evidence is retained under
`ledger/artifacts/benchmarks/20261106-full-keygen/` (ignored by Git).

| Artifact | SHA-256 |
| --- | --- |
| Installed `app.elf` | `fa34f84503befd5b16f1ed47fabd687ac19884fb14544f090c2865f380a09075` |
| Host `check.py` | `14842954c6632a541c16e4e86ac08053cea814c4411af8c6520bf20d2a366391` |
| Recorded transport | `b62b30cbcaf278efaec9b70b2eb2b56d77c91a600fd553075a33e1abc8872d6d` |
| Public source archive | `fbf95e371e6ab5f3bd39435b8924f459b4e408130706b2bf07fa0684cc9280b6` |
| Installation APDU script | `40e6d024b044fd5a82626ea0c1f61598a6ec6a04c9dfaff02fda7da6f7f041eb` |

Both emulator tests passed on the exact installed ELF. The complete emulator
calculation observed 4,352 leaves and 1,088 event polls in 109.024576 seconds.
Peak heap was 2,808 bytes, peak app stack 5,776 / 18,488 bytes, headroom 12,712
bytes. These are emulator measurements, not physical timings. Independent
Python checks validate the canonical public-key encoding, its capacity, and
its Keccak commitment. Rejection, token consumption/cancellation/replay, and
installation/storage isolation are covered.

The first emulator attempt stalled because Ragger's rejection exception left
the simulated ticker paused. Resuming the ticker restored computation. The
test now balances that pause after rejection. This occurred before physical
installation; it is not evidence about the earlier device-reset incident.
Build/failure/retry logs are preserved. `make -C ledger check` passed all seven
Rust formatting checks, 11 native common tests, and nine host tests.

## Physical procedure

Same Gen5 as the reset investigation: LedgerOS 1.1.1, MCU 8.1.2, bootloader
7.1.2 (read earlier that day). The operator confirmed the fresh, unfunded
wallet and temporarily disabled auto-lock for this run. The separately named
app was installed successfully, and the operator opened it manually.

One physical approval authorizes one timed execution. Host monotonic timing
starts after the approval response. It includes device RNG, complete hybrid
key generation, progress rendering/event servicing, public serialization and
the completion response. It excludes user-review time, later public readback,
wallet-seed derivation, and application storage writes. Thus it differs from
the earlier 73.679-second capacity-four persistent-wallet creation operation.

The on-device counter shows completed leaves out of 4,352: 256 for the
stateless root and 4,096 for the stateful root. It refreshes every 64 leaves;
device events are serviced every four leaves. It does not show elapsed seconds.

## Physical result

One execution started at **15:24:40 UTC** and completed successfully after
**1,249.591232 seconds — 20 minutes 49.6 seconds**. The host then read the full
public key and independently checked its capacity, canonical ABI encoding, and
commitment. The recorder closed normally with no outstanding requests.

| Measurement | Gen5 result |
| --- | --- |
| Stateful signature capacity | 4,096 |
| Stateless-root / stateful leaves | 256 / 4,096 |
| Total completed leaves | 4,352 |
| Event polls | 1,088 |
| Public-key ABI length | 480 bytes |
| Peak heap | 2,808 / 20,480 bytes |
| Heap at completion | 660 bytes |
| Peak app stack | 9,872 / 18,488 bytes |
| App-stack headroom | 8,616 bytes; passes the 4,096-byte target |
| Keygen / resource checks | Both passed |
| Persistent application key | None; benchmark key was not saved |

Public commitment:
`8afc0efe84aa8f51aa1a2f9cac735b2899fc0b46a12a0a9dc9f36ffde131b685`.
The complete public key and monotonic duration are in `physical.json`; the
APDU timeline and status words are in `physical.events.jsonl`. Approval-token
bytes are redacted. The operator restored **one-minute auto-lock** afterward.

This is one measured sample of the dedicated benchmark, not a statistical
latency estimate, an optimized implementation, or full-wallet acceptance.
It does not resolve the older wallet-creation stack-budget failure or the reset
incident. Persistent capacity-4,096 signing, large authentication paths, and
recovery/rotation remain outside this benchmark. No signing was performed.
