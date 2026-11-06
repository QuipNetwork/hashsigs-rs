# Full-budget Gen5 key generation

Measured on the physical Gen5 on November 6: **1,249.591232 seconds (20 min
49.6 s)** for all 4,352 leaves. Peak heap 2,808 bytes; app-stack headroom 8,616
bytes. Keygen and resource checks passed. See the
[dated result](../docs/gen5-full-keygen-20261106.md) for the exact build,
measurement boundaries, and evidence. This is one sample.

`SHRINCS Keygen` 0.1.0 generates a real `shrincs-256s-sha2` hybrid key at the
library's maximum supported **4,096 stateful signatures**. Its callback must
observe 256 stateless-root leaves plus 4,096 stateful leaves: **4,352 total**.
This is a key-generation benchmark, not a capacity upgrade to the wallet app.
The wallet's persistent-record/signing contract still supports capacity four.

The separate installation uses CLA `E4`, a separate narrow derivation label,
and the pinned SDK/toolchain/hash implementation. It takes a fresh 32-byte
seed from the device RNG, computes both real roots, encodes the public key,
then drops the secret owners (zeroized on drop). It has no application NVM,
wallet-seed derivation, signing, private-key export, or key import. The public
key survives only in app RAM. Installing it does not replace HW Check or Lab.

The small main loop and non-inlined generation/command functions avoid keeping
the wallet app's large command frame active. The same 20 KiB measured allocator
and app-stack painter are used. Require peak heap at most 18 KiB and at least
4 KiB stack headroom. The older wallet-creation stack failure remains separate.
The SDK's OS syscall stack is outside this measurement.

The device approves one timed run, returning a one-use random token. Any other
command invalidates the token; an incorrect execute token consumes it. A
completed run cannot be repeated until app restart. The UI shows leaf progress
every 64 leaves and services device events every four leaves; concurrent
requests receive `6986`. The spinner text stays alive until replaced by home.

| Instruction | Request | Successful response |
| --- | --- | --- |
| `03`, `04` | Empty | Version / package name |
| `06` | Empty | Profile ID `[32]`, capacity `u32=4096`, leaves `u32=4352` |
| `F0` | Empty | Five `u32`: heap capacity/peak/current, app-stack capacity/peak |
| `F3` | Empty | Physical approval, token `[16]`; rejection is `6985` |
| `F4` | Token `[16]` | Commitment `[32]`, leaves `u32`, event polls `u32`, metrics `[20]` |
| `31` | Offset `u16`, length `u8=1..200` | Requested slice of the 480-byte public ABI |

All commands require P1=P2=0. There is no APDU to reduce the budget or replace
the real stateless root with a fixture.

Build/test with `make -C ledger test-keygen-bench`. The emulator test executes
the entire 4,352-leaf calculation, checks resource budgets and public encoding,
and recomputes the commitment independently in Python. It also checks rejection,
token consumption/cancellation/replay, and installation/storage isolation.

For a physical run, archive the exact ELF and installation APDU, install this
separate app, and have the operator open it. Expose only that USB device to the
container. Run once:

```sh
timeout 2150 python -B -u keygen-bench/check.py \
  --expected-elf /out/app.elf --output /out/physical.json
```

Use the same durable transport as the reset investigation. It allows five
minutes for review and 30 minutes for this full-budget execute command; all
ordinary reads remain bounded to ten seconds. Tokens are redacted. Do not
retry a timed-out run automatically. Keep only one pending operator instruction.

Host timing starts after approval and includes RNG, full hybrid generation,
progress/event handling, public serialization, and the completion response.
It excludes installation, launch, user-review delay, and subsequent public-key
readback. It also excludes wallet-seed derivation and NVM storage, so it is not
identical to the earlier capacity-four wallet-creation timing. The report keeps
keygen completion and resource acceptance separate; it never grants general
wallet hardware acceptance. No physical time is established by extrapolation
or by the emulator result.
