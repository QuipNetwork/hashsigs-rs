# Physical evidence recorders

`wallet_check.py` is the existing operator-assisted normal-wallet recorder.
The reset investigation uses `../hw-check/reproduce.py` and `event_record.py`
to record individual actions before they touch USB. It never installs an app,
retries a failed command, or starts another test automatically.

Each action creates an exclusive `.events.jsonl` file before device discovery,
plus a final `.json` result when the process can finish. Events carry UTC,
monotonic elapsed time, sequence numbers, and APDU request identifiers. Every
event is flushed and fsynced. The approval token is redacted from logs; app
responses contain no private keys. Source hashes and the expected ELF hash are
recorded; an expected ELF hash is not device-code attestation.

Use the pinned Docker image, expose exactly one explicit USB device, and close
other clients. For example, with archived firmware and a new output filename:

```sh
docker run --rm --network none --user 1000:1000 \
  --device /dev/bus/usb/BBB/DDD --group-add 0 \
  --mount type=bind,src=/absolute/hashsigs-rs/ledger,dst=/lab,readonly \
  --mount type=bind,src=/absolute/report-directory,dst=/out \
  hashsigs-ledger:local timeout 45 python -B -u /lab/hw-check/reproduce.py \
  read --expected-elf /out/app.elf --output /out/empty.json
```

Adjust UID/GID and USB group for the host. `note --note 'observation'` records
operator evidence without opening USB. Other single actions are `os-version`,
`launch --app hardware|control`, `exit`, `control-read`, `read`, `probe --probe
0..6`, `reject`, `create`, `recompute`, `responsive`, and `verify`.
`recompute` performs exactly one keygen without busy probes. `responsive` is a
separate single keygen with four early probes. Unlike the old benchmark action,
neither silently adds another computation.

The recorder bounds public reads/open/close/writes at 10 seconds, computation
at 120 seconds, and explicit launch/creation approval waits at 300 seconds.
A process watchdog exits with status 124 if the pinned native HID read blocks.
Use an outer timeout as well: 320 seconds for a launch and 450 for creation
including review, versus 45 for public reads. If native code retains the GIL,
the outer timeout may be the only termination; the preceding send event is
already durable. A missing final JSON is an incomplete action, not a pass.

No extra identity read follows launch or exit. This keeps those transitions
isolated; record the visible screen separately before the next command. Only
the selected `responsive` action may overlap a keygen with one outstanding
GET_INFO probe. The log associates its `6986` busy reply with the probe while
retaining the original keygen request until completion.

After key creation, the post-operation snapshot is persisted before resource
checks. A committed key with failed stack headroom therefore remains visible
in failure evidence. All reports carry `hardware_acceptance:false`; a successful
individual reproduction action does not close hardware acceptance. Resource
targets remain unchanged, and a failed action never schedules a next step.

The host tests exercise timeout/process-death retention, token redaction,
unexpected statuses, busy-response ordering, rejection of competing requests,
one-generation isolation, and post-commit evidence after a resource failure.
Run them without USB using `python -B -m pytest hardware --confcutdir=hardware -q`
inside the pinned image. `make -C ledger check` includes them.
