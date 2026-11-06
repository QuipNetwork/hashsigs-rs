"""One full-budget computation, timed after physical approval; public evidence only."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

from Crypto.Hash import keccak

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "hardware"))
from event_record import EventLog, RecordedBackend  # noqa: E402

CLA = 0xe4
PROFILE = bytes.fromhex("807de98ac65ab9f03289950d1878e5ec5261f162af5593ccba2f1709c793c2bb")
CAPACITY = 4096
LEAVES = 256 + CAPACITY


def require(condition, message):
    if not condition:
        raise ValueError(message)


def metrics(raw):
    require(len(raw) == 20, "Malformed memory metrics")
    result = dict(zip(("heap_capacity", "heap_peak", "heap_current", "stack_capacity", "stack_peak"),
                      (int.from_bytes(raw[i:i+4], "big") for i in range(0, 20, 4))))
    result["stack_headroom"] = result["stack_capacity"] - result["stack_peak"]
    return result


def check_resources(value):
    require(value["heap_capacity"] == 20480 and 0 < value["heap_peak"] <= 18 * 1024
            and 0 < value["heap_current"] <= value["heap_peak"], "Heap budget failed")
    require(value["stack_peak"] > 0 and value["stack_headroom"] >= 4096, "Stack budget failed")


def check_public(raw, commitment):
    require(len(raw) == 480 and int.from_bytes(raw[:32], "big") == 32, "Bad public encoding")
    fields, cursor = [], 128
    for i, length in enumerate((68, 32, 32, 32)):
        offset = int.from_bytes(raw[32 + i*32:64 + i*32], "big")
        require(offset == cursor, "Noncanonical public offsets")
        begin = 32 + offset
        require(int.from_bytes(raw[begin:begin+32], "big") == length, "Bad public field length")
        field = raw[begin+32:begin+32+length]
        padded = (length + 31) // 32 * 32
        require(raw[begin+32+length:begin+32+padded] == bytes(padded - length), "Bad public padding")
        fields.append(field)
        cursor += 32 + padded
    stateful, embedded_commitment, seed, root = fields
    require(int.from_bytes(stateful[64:], "big") == CAPACITY, "Wrong stateful capacity")
    require(all(part != bytes(32) for part in (stateful[:32], stateful[32:64], seed, root)),
            "Empty public root or seed")
    expected = keccak.new(digest_bits=256, data=b"shrincs-public-key/shrincs-256s-sha2"
                         + stateful + seed + root).digest()
    require(expected == embedded_commitment == commitment, "Public commitment mismatch")


def read_public(exchange):
    return b"".join(exchange(cla=CLA, ins=0x31,
                            data=offset.to_bytes(2, "big") + bytes([min(200, 480-offset)])).data
                    for offset in range(0, 480, 200))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-elf", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "Refusing to overwrite evidence")
    events = args.output.with_suffix(".events.jsonl")
    log = EventLog(events)
    result = {"schema": 1, "profile": "shrincs-256s-sha2", "stateful_capacity": CAPACITY,
              "stateless_root_leaves": 256, "expected_leaves": LEAVES,
              "application_storage": "absent", "secret_persisted": False,
              "hardware_acceptance": False, "keygen_passed": False, "resource_passed": False,
              "expected_elf_sha256": hashlib.sha256(args.expected_elf.read_bytes()).hexdigest(),
              "recorder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "transport_sha256": hashlib.sha256((ROOT.parent / "hardware/event_record.py").read_bytes()).hexdigest(),
              "events": events.name}
    log.emit("run_start", **result)
    backend = None
    try:
        backend = RecordedBackend(log)
        exchange = backend.exchange
        require(exchange(cla=CLA, ins=4).data == b"hashsigs-ledger-keygen-bench", "Wrong app")
        require(exchange(cla=CLA, ins=3).data == bytes([0, 1, 0]), "Wrong version")
        require(exchange(cla=CLA, ins=6).data == PROFILE + CAPACITY.to_bytes(4, "big")
                + LEAVES.to_bytes(4, "big"), "Wrong profile or budget")
        result["before_metrics"] = metrics(exchange(cla=CLA, ins=0xf0).data)
        check_resources(result["before_metrics"])
        print("Approve Start benchmark on the device. Timing excludes the approval wait.", flush=True)
        token = exchange(cla=CLA, ins=0xf3).data
        require(len(token) == 16 and token != bytes(16), "Invalid approval token")
        started = time.monotonic()
        log.emit("computation_start")
        print("Computing 4096-stateful-budget key; waiting for the single completion response.", flush=True)
        raw = exchange(cla=CLA, ins=0xf4, data=token).data
        result["seconds_excluding_approval"] = time.monotonic() - started
        require(len(raw) == 60, "Malformed keygen result")
        result.update(commitment=raw[:32].hex(), leaves=int.from_bytes(raw[32:36], "big"),
                      event_polls=int.from_bytes(raw[36:40], "big"), after_metrics=metrics(raw[40:]))
        log.emit("computation_result", **result)
        require(result["leaves"] == LEAVES and result["event_polls"] == LEAVES // 4,
                "Incomplete computation or event servicing")
        public = read_public(exchange)
        result["public_key"] = public.hex()
        check_public(public, raw[:32])
        result["keygen_passed"] = True
        check_resources(result["after_metrics"])
        result["resource_passed"] = True
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        log.emit("error", detail=result["error"])
        raise
    finally:
        try:
            with args.output.open("x") as output:
                json.dump(result, output, indent=2)
                output.write("\n")
            log.emit("result", value=result)
            if backend is not None:
                backend.close()
        finally:
            log.close()
    print(json.dumps({key: result[key] for key in
                      ("seconds_excluding_approval", "stateful_capacity", "leaves", "after_metrics")}), flush=True)


if __name__ == "__main__":
    main()
