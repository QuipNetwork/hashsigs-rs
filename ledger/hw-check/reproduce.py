"""One explicitly selected reproduction action; no retries or installations."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from check import (CLA, CREATE, PROBES, AppClient, snapshot, unchanged, check_creation,
                   check_resources, check_progress, responsive_keygen, require)  # noqa: E402
from event_record import EventLog, RecordedBackend  # noqa: E402

APPS = {"hardware": ("SHRINCS HW Check", CLA), "control": ("SHRINCS Launch", 0xe3)}


def execute(args, backend, log, result):
    if args.action == "os-version":
        from ledgerwallet.client import VersionInfo
        raw = backend.exchange(cla=0xe0, ins=1).data
        result["version_info"] = str(VersionInfo.parse(raw))
        return
    if args.action == "launch":
        backend.exchange(cla=0xe0, ins=0xd8, data=APPS[args.app][0].encode())
        return  # No hidden follow-up query after an app launch.
    if args.action == "exit":
        backend.exchange(cla=0xb0, ins=0xa7)
        return  # Record the on-device transition separately.
    if args.action == "control-read":
        client = AppClient(backend, 0xe3)
        require(client.name() == "hashsigs-ledger-launch-check" and client.version() == (0, 1, 0),
                "Unexpected launch-control app")
        result["identity"] = "hashsigs-ledger-launch-check 0.1.0"
        return

    version = tuple(map(int, args.app_version.split(".")))
    before = result["before"] = snapshot(backend, expected_version=version)
    log.emit("snapshot_before", value=before)
    client = AppClient(backend, CLA)
    if args.action == "probe":
        raw = backend.exchange(ins=0xf1, p1=args.probe).data
        result["probe_response"] = raw.hex()
        expected = 0 if args.probe == 0 else (0x4215 if args.probe <= 3 else 0x4214)
        require(len(raw) == 8 and raw[:2] == bytes([1, args.probe])
                and int.from_bytes(raw[2:6], "big") == expected
                and raw[6:] == bytes([int(args.probe == 0), 1]), "Unexpected permission-probe result")
    elif args.action == "reject":
        require(before["state"]["state"] == 0, "Rejection requires EMPTY")
        print("Tap REJECT on Create SHRINCS key?", flush=True)
        require(not backend.exchange(ins=0x30, data=CREATE, expected=0x6985).data,
                "Rejection returned data")
    elif args.action == "create":
        require(before["state"]["state"] == 0, "Creation requires EMPTY")
        print("Approve Create key; timing starts after approval.", flush=True)
        token = backend.exchange(ins=0xf3, data=CREATE).data
        require(len(token) == 16 and token != bytes(16), "Invalid approval token")
        start = time.monotonic()
        reply = backend.exchange(ins=0xf4, data=token).data
        result["creation_seconds"] = time.monotonic() - start
        result["creation_response"] = reply.hex()
    elif args.action in ("recompute", "responsive"):
        require(before["state"]["state"] == 1, "Existing diagnostic identity required")
        commitment = bytes.fromhex(before["state"]["commitment"])
        if args.action == "recompute":
            start = time.monotonic()
            require(backend.exchange(ins=0xf5).data == commitment, "Recomputed identity changed")
            result["keygen_seconds"] = time.monotonic() - start
        else:
            result["responsiveness"] = responsive_keygen(backend.write, backend.read, commitment)
    elif args.action == "verify":
        vectors = json.loads((ROOT.parent / "artifacts/vectors.json").read_text())
        result["verification_verdict"] = client.verify(
            dict(vectors["cases"][0], envelope=vectors["boundary_envelope"]))
        require(result["verification_verdict"] == 1, "Expected Invalid for extended-path 4 KiB fixture")

    after = result["after"] = snapshot(backend, expected_version=version)
    log.emit("snapshot_after", value=after)
    if args.action == "create":
        require(result["creation_seconds"] <= 120, "Creation latency target exceeded")
        check_creation(before, after, reply)
    else:
        unchanged(before, after)
    if args.action in ("recompute", "responsive"):
        check_progress(after["runtime"])
    if args.action == "responsive":
        require(after["runtime"]["busy_replies"] == 4, "Missing busy replies")
    check_resources(after["metrics"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("note", "os-version", "launch", "exit", "control-read",
                                          "read", "probe", "reject", "create", "recompute", "responsive", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-elf", type=Path)
    parser.add_argument("--app", choices=APPS, default="hardware")
    parser.add_argument("--app-version", choices=("0.1.0", "0.1.1"), default="0.1.1",
                        help="Expected HW Check version; select 0.1.0 for archived incident firmware")
    parser.add_argument("--probe", type=int, choices=range(7))
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    require(not args.output.exists(), "Refusing to overwrite evidence")
    require(args.action in ("note", "os-version") or args.expected_elf is not None,
            "Archive and specify the expected ELF")
    require(args.action != "probe" or args.probe is not None, "Select one probe")
    require(args.action != "note" or bool(args.note.strip()), "Provide an observation")
    events = args.output.with_suffix(".events.jsonl")
    log = EventLog(events)
    result = {"schema": 1, "action": args.action, "note": args.note,
              "expected_hardware_app_version": args.app_version,
              "expected_elf_sha256": hashlib.sha256(args.expected_elf.read_bytes()).hexdigest()
                  if args.expected_elf else None,
              "recorder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "transport_sha256": hashlib.sha256((ROOT.parent / "hardware/event_record.py").read_bytes()).hexdigest(),
              "events": events.name, "hardware_acceptance": False}
    log.emit("run_start", **result)
    backend = None
    try:
        if args.action != "note":
            backend = RecordedBackend(log)
            execute(args, backend, log, result)
        result["action_passed"] = True
    except BaseException as error:
        result["action_passed"] = False
        result["error"] = f"{type(error).__name__}: {error}"
        log.emit("error", detail=result["error"])
        raise
    finally:
        try:
            # Save before close: even a blocked close must retain the result.
            with args.output.open("x") as output:
                json.dump(result, output, indent=2)
                output.write("\n")
            log.emit("result", value=result)
            if backend is not None:
                backend.close()
        finally:
            log.close()
    print(f"Recorded {args.action}: {args.output}", flush=True)


if __name__ == "__main__":
    main()
