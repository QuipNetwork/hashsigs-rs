# Gen5 NVM diagnostics

`SHRINCS NVM Diag` 0.1.0 is a **separate, disposable application**. It has its
own 2,048-byte NVM allocation and installation name. It never derives a wallet
seed, generates a private wallet identity, signs, or accepts host record bytes.
Its four embedded records contain deliberately **public test secrets** generated
on the host from MAC key `07` repeated 32 times and generation `09` repeated
32 times. Never use these keys for funds or signatures.

The normal `SHRINCS Lab` app remains installed with its existing key. Do not
replace it with a diagnostic build. The ELF test checks the distinct name,
installation script's delete target, NVM layout, flags, and absence of the seed
derivation syscall. The SDK treats an empty curve list as all curves, so the
diagnostic manifest instead declares SLIP21-only permissions with the unused,
distinct `quip.network/SHRINCS/NVM-DIAG/v1` namespace. It has no derivation code.
This manifest inspection is not a negative hardware permission test.
The UI reuses the wallet's crab icons under the retained
[Apache-2.0 notice](../app/LICENSE.md); new diagnostic code is AGPL-3.0-or-later.

## What this measures

The app uses the wallet's common authenticated-record validation and commit
routine, and the same C `nvm_write` exception boundary. `diagnostics` is an
explicit Cargo feature used only by this separate binary and host generator.
The wallet does not expose replacement, reset, import, diagnostic, or signing
commands. The diagnostic `PREPARE` operation deliberately resets **only its own
public fixture storage**.

Three transitions are exercised: EMPTY to leaf 1; leaf 1 to leaf 2; and leaf 4
to EXHAUSTED (next leaf 5). Counter advancement is simulated with authenticated
public fixture records, not an implementation of leaf reservation or signing.

| Checkpoint | Last action | Creation reload | Existing-record reload |
| --- | --- | --- | --- |
| 1 | Before marker invalidation | EMPTY | Old READY record; no write begun |
| 2, 3, 4 | Invalidation returned / readback verified / before payload | EMPTY | LOCKED |
| 5, 6, 7 | Payload returned / readback verified / before marker commit | LOCKED | LOCKED |
| 8, 9 | Commit returned / readback verified | New READY | New READY or EXHAUSTED |
| 0 | Complete transaction | New READY | New READY or EXHAUSTED |

The checkpoint callback returns an error to stop the common routine before it
can perform another write. The app then reports freshly loaded NVM. An app
restart or operator power cycle verifies that same state independently of its
RAM. Stage 10 means completed; stage 0 in a subsequent snapshot means fresh RAM.
Boot nonces are also compared. Speculos tests use distinct explicit RNG streams
per process to avoid collisions in quick time-seeded restarts.

Pages are `[front canary, marker, payload, back canary]`, each 512-byte aligned.
Every completed write checks the SHA-256 digest of all three other pages. The
common routine separately reads back and validates the written record. Reports
compare exact marker/payload digests, both canaries, and the entire public state.
This detects neighbouring **logical block** changes in completed writes.

**These are controlled stops between syscalls, not in-flight flash interruption.**
No code here cuts device power or interrupts `nvm_write` while it executes.
Logical canaries and successful readback do not establish physical erase-unit
isolation, atomicity, or power-failure durability. Disconnecting USB does not
power off the battery-powered Gen5. Signing remains disabled.

## Build and software tests

```sh
make -C ledger test-nvm-diag PYTEST_ARGS='-x --tb=short'
make -C ledger test
```

Artifacts are exported separately to `ledger/artifacts/nvm-diag/`: `app.elf`,
the installation `.apdu`, `fixtures.bin`, and `SHA256SUMS`. The host generator is
`common/examples/diagnostic_records.rs`; fixtures are reproducibly generated,
not accepted from the host over USB. The Python checker independently verifies
their HMACs and expected public-state bytes.

The diagnostic suite starts fresh Speculos processes at all 30 transition/stop
combinations, checks malformed requests leave NVM unchanged, tests four saved
record corruptions, and checks ELF/install isolation. Native common tests also
model every partial-write prefix for creation and both counter transitions.
The normal wallet regression suite remains required after common code changes.

`tests/enable_rust_nvram.py` explicitly adapts pinned Speculos 0.27.0. It records
Rust PIC tables plus application NVM, validates contiguous ELF flash offsets,
and extends the mapped size through the second flash PT_LOAD. Without that size
fix, layouts crossing a host page boundary crash in the launcher's initial
NVM `memset`. The adapter changes emulator metadata, never the app ELF.

## Hardware procedure

Keep Ledger Live closed; use one USB client at a time. Archive the exact ELF,
fixtures, OS/MCU versions, and public JSON reports. Record a normal-wallet
snapshot with `hardware/wallet_check.py` before installation, using its archived
installed ELF as `--expected-elf`, not a newly rebuilt wallet artifact.

Install only `SHRINCS NVM Diag` after verifying the ELF/install isolation test.
Its generated delete-by-name command targets only that diagnostic name. Approve
the developer-app prompts and open the diagnostic app. No normal-wallet app
deletion or seed reset is part of this procedure.

Run the checker inside the pinned container, with this ledger directory mounted
read-only at `/lab`, a writable report directory at `/out`, and only the chosen
USB character device passed through. Bound native HID reads with `timeout`:

```sh
timeout 90 python -B -u /lab/nvm-diag/check.py matrix \
  --fixtures /lab/artifacts/nvm-diag/fixtures.bin \
  --expected-elf /lab/artifacts/nvm-diag/app.elf --output /out/matrix.json
timeout 45 python -B -u /lab/nvm-diag/check.py case --source 1 --target 2 --cut 5 \
  --fixtures /lab/artifacts/nvm-diag/fixtures.bin \
  --expected-elf /lab/artifacts/nvm-diag/app.elf --output /out/locked-before.json
```

Exit/reopen the diagnostic app, or fully power off/on using the device menu,
then record a read-only snapshot with the preceding report as the baseline:

```sh
timeout 45 python -B -u /lab/nvm-diag/check.py snapshot \
  --baseline /out/locked-before.json --restart-kind operator-power-cycle \
  --fixtures /lab/artifacts/nvm-diag/fixtures.bin \
  --expected-elf /lab/artifacts/nvm-diag/app.elf --output /out/locked-after.json
```

Use `--restart-kind app-reopen` for app exit/reopen. The operator's power-cycle
classification is recorded, not independently measured. Exercise EMPTY, LOCKED,
READY, and EXHAUSTED recovery; repeat other boundary cases as required. Reports
refuse overwrite and contain only public fixtures/state, not wallet secrets.
Finally reopen the original SHRINCS Lab and compare its identity and counters
to the pre-installation snapshot. Artifact hashes are not installed-code
attestation.

## SDK evidence and remaining hardware gate

The pinned builder uses C SDK commit
`22d1131a03fcd89c5d2e660de886c8b0417b0789`, API 26, and Rust SDK 1.36.1 /
`ledger_secure_sdk_sys` 1.16.4. Its
[`include/os_nvm.h`](https://github.com/LedgerHQ/ledger-secure-sdk/blob/22d1131a03fcd89c5d2e660de886c8b0417b0789/include/os_nvm.h)
declares the write syscall, application data-segment constraints, and zero-fill
semantics for a null source. It does not specify a Gen5 power-failure transaction
contract. Ledger's [persistent-storage documentation](https://developers.ledger.com/docs/device-app/explanation/memory/persistent-storage)
describes application-owned flash and generic 64-byte page alignment guidance;
that is not a device/OS-specific atomicity or erase-isolation guarantee for these
512-byte records. The [SDK API mapping](https://github.com/LedgerHQ/ledger-secure-sdk)
associates API 26 with Gen5 OS 1.1.1.

Closing the signing prerequisite requires device/OS-specific evidence for
completed-write durability and ordering, and failures during marker/payload
writes without restoring an old reusable counter. Use an appropriate physical
power/fault fixture or authoritative Ledger guarantees plus targeted validation.
Controlled app exits, menu power cycles between writes, emulator persistence,
and software-injected prefixes remain separately labelled supporting evidence.

## 2026-11-05 results

Starting source: `nano-main` at `b34fc7f`, with the diagnostic changes uncommitted.
The physical Gen5 reported LedgerOS 1.1.1, MCU 8.1.2, target `0x33400004`.
Ledger Live was closed. The separately installed diagnostic ELF SHA-256 is
`3bef448147040a29aded8370d644beb770fba40045d3c376307d2c0a0d6a0069`;
fixture SHA-256 is
`35a190e6618e05ede662c6449735e28e9235473c69b472c7ecb3cedd7b73bef6`.
The final clean container rebuild reproduced both hashes.

| Check | Result |
| --- | --- |
| Diagnostic emulator/ELF suite | 36 passed in 37.71 s; includes 30 fresh-process transition/stop cases |
| Normal wallet emulator/ELF regressions | 62 passed in 48.16 s |
| Common native tests | 11 passed; 4,617 partial-write prefix cases across creation and two counter transitions |
| Host wallet recorder | 2 passed; Rust formatting passed for all four crates |
| Physical diagnostic matrix | All 30 transition/stop cases passed with expected state, counters, marker/payload digests, and intact canaries |
| LOCKED after payload write (1 to 2, checkpoint 5) | Survived operator-confirmed full power-off/on; bytes unchanged and boot nonce changed |
| EMPTY after invalidation (0 to 1, checkpoint 2) | Survived host-requested app exit and operator reopen |
| READY after commit (1 to 2, checkpoint 8) | Survived exit/reopen with next leaf and sequence both 2 |
| EXHAUSTED after commit (4 to 5, checkpoint 8) | Survived exit/reopen with next leaf and sequence both 5 |
| Original SHRINCS Lab identity | Exact public key, generation, commitment, and counters matched the pre-installation snapshot; READY, next leaf 1, sequence 1, zero stateless uses |

Reports and archived artifacts are in
`ledger/artifacts/benchmarks/20261105-nvm-diag/`. The report sequence is
`01-wallet-before.json`, `02-diag-installed.json`, `03-hardware-matrix.json`,
`05-locked-before-power.json` through `12-exhausted-reopened.json`, and
`13-wallet-after.json`; `device-info.txt` records firmware versions. The original
normal app was not reinstalled. Its archived ELF remains the previously measured
`b45cbfc40296e38ca35458f37c46328d447f1a15c35b45c0ef221db3614407d4`.

An initial manual reopen attempt after the matrix did not reset the checkpoint
RAM and was correctly rejected by the checker; no passing `04` report was
written. Later reopen cases explicitly exited via the SDK's common quit command
before operator reopening and verified both fresh RAM and a changed nonce.
Initial emulator failures are retained in `build-and-diagnostics.log` and
`diagnostics-retry.log`: first the loader mapping issue described above, then a
time-seeded RNG collision during rapid restarts. `diagnostics-final.log`,
`wallet-regressions.log`, and `final-build-check.log` record the passing checks.

These results close the controlled-boundary diagnostic slice. **No in-flight
physical write was interrupted**, physical erase isolation remains unproven,
and the signing capability remains disabled.
