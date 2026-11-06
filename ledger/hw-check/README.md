# SHRINCS Gen5 hardware checks

**Hardware testing stopped on 2026-11-05 after an operator-reported stall and
factory reset following a held power button.** The device showed initialization
pages for a name and PIN. The cause is unresolved. Original-wallet preservation
was not verified after this run. Keep the evidence below, but do not treat this
as successful hardware acceptance. The
[reproduction plan](../docs/gen5-reset-reproduction.md) scopes controlled replay
to this Gen5 with a fresh, unfunded test wallet. The operator confirmed that
setup on November 6; see the [ongoing evidence](../docs/gen5-reset-20261106.md).

`SHRINCS HW Check` 0.1.0 measures the wallet's key generation, event servicing,
heap/stack peaks, derivation permissions, and rejection behavior in a separate
installed app. It reuses `../app/src/main.rs` and the wallet implementation,
profile, 20 KiB allocator, and 1,024-byte persistent layout. Its installation
name, CLA `E2`, and sole SLIP21 label `quip.network/SHRINCS/HW-CHECK/v1` are
distinct from SHRINCS Lab and SHRINCS NVM Diag. It grants no EC derivation or
master-seed access. Both signing capabilities and signing commands stay disabled.

The normal manifest rejects the `hardware-tests` feature at build time. Its
ordinary ELF contains neither the permission probes nor the extra commands.
The hardware-check ELF and install script have isolation tests, including the
script's exact app-deletion target. Updating this diagnostic app loses only its
own test identity; do not install its artifact under the normal app name.

## Build and run

From the `hashsigs-rs` root:

```sh
make -C ledger test-hw-check
make -C ledger check
```

`build-hw-check` exports a separate ELF, generated installation APDUs, and hash
under `ledger/artifacts/hw-check/`. Archive them in a new benchmark directory
before installing the separate app with Ledger's development tooling. Leave the
existing SHRINCS Lab installation intact. Record its public identity/counters
with [`wallet_check.py`](../hardware/wallet_check.py) before installation and
after the experiment, using its original archived `--expected-elf`.

Open **SHRINCS HW Check**, close Ledger Live and other USB clients, and discover
the current node using `lsusb -d 2c97:`. Only one runner may use the device.
Example invocation after archiving `app.elf` in the report directory:

```sh
docker run --rm --network none --user 1000:1000 \
  --device /dev/bus/usb/BBB/DDD --group-add 0 \
  --mount type=bind,src=/absolute/hashsigs-rs/ledger,dst=/lab,readonly \
  --mount type=bind,src=/absolute/report-directory,dst=/out \
  hashsigs-ledger:local timeout 600 python -B -u /lab/hw-check/check.py \
  permissions --expected-elf /out/app.elf --output /out/02-permissions.json
```

Use the invoking user's UID/GID and the USB node's group. Run actions in this
order with a new output filename for each:

1. `permissions`: the allowed label succeeds; three other labels and three EC
   requests must fail with the pinned OS permission errors. No review is needed.
2. `reject`: on an EMPTY app, tap **Reject** on the ordinary creation screen.
   State and both actual NVM-page digests must remain unchanged.
3. `create`: approve **Create key**. The host then sends the one-use approval
   token immediately and starts its monotonic timer. Creation returns directly
   to the home screen after durable storage; there is no final Done tap in
   this measurement flow. The usual `30` flow still has its commitment screen.
4. `benchmark --samples 3`: recompute the existing diagnostic identity three
   times, then once more while probing responsiveness. No approval, signature,
   leaf consumption, or NVM write occurs. Allow about five minutes on Gen5.
5. `verify`: process the canonical maximum-size 4 KiB public fixture and read
   cumulative memory peaks. Its extended authentication path must return
   Invalid (`01`), exercising the decoder's allocation path. Persistent
   identity and counters must stay unchanged.

`snapshot` reads public state, metrics, and storage fingerprints. It also checks
resource targets and can fail even when public reads succeed. After any lost
creation response, use this action before deciding whether another creation is
appropriate. Existing identities cannot be replaced by the APDU interface.
Reports refuse overwrite, contain public data only, and retain available
measurements on failure. `passed:false` must not be relabeled as a pass just
because cryptographic computation completed. The expected ELF hash identifies
the archived build; it does not attest the installed binary.

## Measurement and protocol

Timing is host request-to-response after approval, including USB, UI/event
handling, and (for creation) durable storage. It excludes operator review time;
it is not CPU-only timing. The initial target remains 120 seconds. Heap peaks
use the SDK's allocator implementation/capacity, with allocation counters;
stack peaks use the SDK paint/scan tracker. Peaks accumulate from app startup,
including UI and previous probes. The targets remain heap at most 18 KiB and
stack headroom at least 4 KiB. OS syscall stack and the watchdog threshold are
not measured. Instrumentation and the different diagnostic label can change
the layout; final functional acceptance must use the uninstrumented artifact.

Key generation completes 260 leaves (256 stateless-tree and four stateful-tree
leaves), calling the existing event handler after every four leaves: 65 polls.
Four early `GET_INFO` probes must each receive `6986`, followed by the original
keygen result. Only one probe is outstanding at a time. Probing stops well
before completion to avoid racing the final response in the SDK transport.
These sampled latencies do not bound the maximum gap over the whole operation
or establish the device watchdog margin.

All integers below are big-endian. P2 is zero; P1 is zero except on `F1`.
The app retains the normal key-management/verification commands under CLA `E2`.

| INS | Request | Response |
| --- | --- | --- |
| `F0` | Empty | Five `u32`: heap capacity/peak/current, app stack capacity/peak |
| `F1` | Empty, P1 probe 0–6 | Version `u8=1`, probe `u8`, OS status `u32`, nonzero-result flag `u8`, erased-scratch flag `u8` |
| `F2` | Empty | Version `u8=1`; leaves, event polls, busy replies, app NVM write calls (four `u32`); SHA-256 of marker `[32]` and payload `[32]` |
| `F3` | Profile `[32]`, capacity `u32=4` | After approval, random one-use token `[16]`; no derivation/keygen/write yet |
| `F4` | Token `[16]` | Commitment `[32]`, public length `u16=480`, after creation |
| `F5` | Empty; existing identity required | Recomputed commitment `[32]`; no NVM writes |

Other decoded commands clear the pending measurement token. Execute consumes
it even if its supplied token is invalid. Restart also discards it. Probe,
report, arm, execute, and benchmark reject an active verification session.
Counters reset per generated key except NVM write calls, which accumulate per
boot. NVM fingerprints hash the actual pages without exporting their contents.

The C probe requests allowed/neighbor/parent/normal-wallet labels, secp256k1,
secp256r1, and ed25519 SLIP10. For pinned API 26, label denial must be `4215`
(`SWO_PAR_VAL_15`) and curve denial `4214` (`SWO_PAR_VAL_14`); a generic error
does not count as permission evidence. Only status and flags leave the shim.
Raw derived key, chain-code, and path scratch are erased and checked after
each probe. This runtime check does not constitute a compiler-wide erasure
audit. See Ledger's [permission reference](https://developers.ledger.com/docs/device-app/references/app-permissions)
and the pinned [Speculos allowlist implementation](https://github.com/LedgerHQ/speculos/blob/v0.27.0/src/bolos/os_bip32.c).

## 2026-11-05 results

Source base: `nano-main` at `6e41e27`, plus this slice's working changes.
Physical device: Nano Gen5, LedgerOS 1.1.1, MCU 8.1.2, target `0x33400004`.
Rust SDK 1.36.1, secure-sys 1.16.4, C SDK
`22d1131a03fcd89c5d2e660de886c8b0417b0789` / API 26; the builder digest and
other pins are in [`../Dockerfile`](../Dockerfile) and lockfiles.

Diagnostic ELF SHA-256:
`48768fecbfc74e76df2a3a8f0378933ef0198504db4a15fb4f624556e6f63781`.
Local raw reports, archived ELF/APDUs, and logs:
`ledger/artifacts/benchmarks/20261105-hw-check/` (ignored by Git).

The seven physical permission probes passed, including exact `4214`/`4215`
denials and scratch-erasure flags. Rejection of the ordinary create request
returned `6985`, left EMPTY, did no key generation or app NVM writes, and
preserved both zero-page SHA-256 digests. Timed creation then completed in
**73.680920 seconds**: READY, next leaf 1, sequence 1, zero stateless uses,
260 leaves, 65 event polls, exactly three app NVM writes, and no restart.
The canonical public export and independent Keccak commitment check succeeded.

**The physical stack target failed.** Creation reached peak heap **2,756 bytes**
and app stack **16,832 bytes** in an 18,472-byte stack, leaving only **1,640
bytes** versus the required 4,096. The original creation reporter raised before
storing its post-creation snapshot; `04-created-state.json` immediately
reconciled the committed state and measurements. Both failed reports are kept.
The reporter now saves that snapshot before checking acceptance bounds.

Further measurements were taken after this resource failure; they are retained
as evidence, not justification for continuing physical testing:

| Measurement | Physical result before the reported stall/reset |
| --- | --- |
| Three recomputations, seconds including USB | 73.263977, 73.256859, 73.265904 (median 73.263977) |
| Recomputation with four early busy probes | 72.907905 s |
| Sampled busy-response latencies | 2.411580, 1.016966, 1.017935, 1.017967 s |
| Canonical 4 KiB fixture | Expected Invalid (`01`) verdict |
| Peak heap after maximum fixture | 16,804 / 20,480 bytes; below the 18 KiB target |
| Final cumulative app stack | 16,832 / 18,472 bytes; **1,640-byte headroom fails** |

At the last successful public read, recomputations and verification had left
the diagnostic identity, counters, both NVM digests, and three-write count
unchanged. Each recomputation completed 260 leaves/65 polls; the probe run
recorded four busy replies. Both reports correctly remain `passed:false`
because of the stack margin. These observations precede the reported reset.

The first installer attempt returned `5515` while the device was locked; the
unlocked retry succeeded. The initial emulator responsiveness helper raced a
probe against completion and timed out; the bounded four-probe helper fixes
that test transport race. The failed log and passing reruns are retained.

Software validation: nine diagnostic emulator/ELF cases, 67 normal app
emulator/ELF regressions, 11 native common tests, two host recorder tests, and
all five crates' formatting checks passed. The normal-manifest feature guard
was also exercised and rejected the diagnostic feature. Tests cover approval
rejection, token invalidation/replay, malformed commands, independent host
SLIP21/KDF/public-key agreement using the public emulator seed, recomputation,
responsiveness, maximum verification, and install/API isolation.

### Stall and reset incident

The operator reported that the device stalled, that they held its power
button, and that it then displayed initialization pages asking for a name and
PIN. They later clarified that the frozen screen was asking permission to open
the HW app, and that they held the button for approximately 10–15 seconds because
the screen was unresponsive. The exact prompt text and timing were not captured.
They confirmed privately having a recovery backup; no PIN or recovery
words were requested or recorded. No further USB requests were made after
the report, and a host process check found no remaining hardware test runner.

Evidence sequence (UTC report timestamps mark action start, not completion):

| Report / action | Observation |
| --- | --- |
| `01-wallet-before.json`, 18:48:08 | Original SHRINCS Lab identity/counters matched the earlier NVM-diagnostic baseline |
| `04-created.json`, 18:58:09 | Timed creation completed; stack target failed |
| `04-created-state.json`, 19:01:52 | Diagnostic READY state and 1,640-byte headroom confirmed |
| `05-benchmarks.json`, 19:03:05 | Four recomputations completed; resource check failed |
| `06-max-verify.json`, 19:08:20 | Expected Invalid verdict, unchanged diagnostic NVM, resource check failed |
| Subsequent host commands | App exit `B0 A7 00 00 00` returned success; OS version query returned `5515` (locked) |
| Requested original-wallet read | Operator reported stall/reset before it occurred; **no post-run original-wallet snapshot exists** |

No factory-reset command was issued by the host workflow. The exact timing
of the physical stall relative to those host commands is unknown. The stack
shortfall is a concrete defect to investigate, but the logs do not establish
stack overflow, a watchdog fault, an OS fault, or a cause of seed/state erasure.
Ledger's [Gen5 manual (Ledger-authored mirror)](https://device.report/m/70081e17b48cbb95b4d4361d1b8542a39b3c8698254948f69623f9e7c1797892)
documents a settings reset with warning/PIN confirmation, automatic reset after
three incorrect PIN entries, and a separate Protection mode that can lead to
reset after an event is interpreted as an attack. A held power button alone is
not listed as a factory-reset procedure. No Protection-mode screen or three
incorrect PIN entries were reported here; none of those mechanisms is an
established explanation for this incident.
Do not infer successful preservation of the original wallet from earlier
diagnostic reads. Treat its experimental app state as lost unless independently
shown otherwise; ordinary recovery-phrase restoration does not restore the
SHRINCS app's generation ID and persistent counter history. There is no
supported import or same-key counter reconstruction path.

Controlled replay resumed on November 6 with a fresh unfunded wallet, durable
APDU logs, and an SDK-only launch control. See the
[dated evidence](../docs/gen5-reset-20261106.md) for the completed launch,
creation, and auto-lock comparisons. The bounded run ended after an ambiguous
opening-warning report, a visible lock screen, and normal unlock to the device
home screen. No persistent freeze or reset was confirmed in this replay; the
broader matrix remains incomplete. Offline review of the reproducible creation
stack-budget failure is next. The 4 KiB stack target
stays unchanged, and ordinary hardware acceptance remains suspended.
In-flight NVM interruption, ordering/durability, and physical erase-isolation
evidence remain separate signing prerequisites. These measurements do not
enable signing or replace final uninstrumented hardware acceptance.
