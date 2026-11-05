"""Public reports for the separate SHRINCS HW Check app. Never installs apps."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "tests"))
sys.path.insert(0, str(ROOT.parent / "hardware"))
from app_client import AppClient  # noqa: E402
from wallet_check import Backend, PROFILE, check_public, public_json, require  # noqa: E402

CLA = 0xE2
CREATE = PROFILE + (4).to_bytes(4, "big")
PROBES = ("allowed label", "neighbor label", "parent label", "normal wallet label",
          "secp256k1", "secp256r1", "ed25519 SLIP10")


def metrics(backend):
    raw = backend.exchange(cla=CLA, ins=0xf0).data
    require(len(raw) == 20, "Malformed metrics")
    result = dict(zip(("heap_capacity", "heap_peak", "heap_current", "stack_capacity", "stack_peak"),
                      (int.from_bytes(raw[i:i + 4], "big") for i in range(0, 20, 4))))
    result["stack_headroom"] = result["stack_capacity"] - result["stack_peak"]
    return result


def check_resources(value):
    require(value["heap_capacity"] == 20480, "Unexpected heap capacity")
    require(0 < value["heap_peak"] <= 18 * 1024, "Heap target exceeded")
    require(0 <= value["heap_current"] <= value["heap_peak"], "Invalid heap accounting")
    require(value["stack_headroom"] >= 4 * 1024 and value["stack_peak"] > 0,
            "Stack headroom target missed")


def runtime(backend):
    raw = backend.exchange(cla=CLA, ins=0xf2).data
    require(len(raw) == 81 and raw[0] == 1, "Malformed hardware report")
    result = dict(zip(("leaves", "event_polls", "busy_replies", "nvm_write_calls"),
                      (int.from_bytes(raw[i:i + 4], "big") for i in range(1, 17, 4))))
    result.update(marker_sha256=raw[17:49].hex(), payload_sha256=raw[49:81].hex())
    return result


def snapshot(backend):
    client = AppClient(backend, CLA)
    require(client.name() == "hashsigs-ledger-hw-check-metrics" and client.version() == (0, 1, 0),
            "Expected separate hardware-check app 0.1.0")
    info, state = client.info(), client.state()
    require(info["profile_id"] == PROFILE and info["capabilities"] == 3
            and info["boot_nonce"] != bytes(16), "Unexpected hardware-check configuration")
    public = b""
    if state["state"] in (1, 2):
        public = client.public_key(state["commitment"])
        check_public(public, state["commitment"])
        require(state["state"] == 1 and state["next_leaf"] == 1 and state["sequence"] == 1,
                "Unexpected counter in signing-disabled app")
    return public_json({"info": info, "state": state, "public_key": public,
                        "metrics": metrics(backend), "runtime": runtime(backend)})


def unchanged(before, after):
    for field in ("info", "state", "public_key"):
        require(before[field] == after[field], f"Changed {field}")
    for field in ("nvm_write_calls", "marker_sha256", "payload_sha256"):
        require(before["runtime"][field] == after["runtime"][field], f"Changed {field}")


def permissions(backend):
    before = snapshot(backend)
    results = []
    for probe, name in enumerate(PROBES):
        raw = backend.exchange(cla=CLA, ins=0xf1, p1=probe).data
        require(len(raw) == 8 and raw[:2] == bytes([1, probe]), "Malformed probe response")
        status = int.from_bytes(raw[2:6], "big")
        # Pinned API-26 path/curve allowlist errors (SWO_PAR_VAL_15 / _14).
        # A generic failure is not accepted as evidence of permission enforcement.
        expected = 0 if probe == 0 else (0x4215 if probe <= 3 else 0x4214)
        require(status == expected, f"Unexpected derivation result for {name}: {status:08x}")
        require(raw[6] == int(probe == 0) and raw[7] == 1, "Probe output/erasure check failed")
        results.append({"probe": name, "os_status": f"0x{status:08x}",
                        "returned_nonzero": bool(raw[6]), "scratch_erased": bool(raw[7])})
    unchanged(before, snapshot(backend))
    return results


def check_creation(before, after, response):
    require(len(response) == 34 and response[-2:] == (480).to_bytes(2, "big"), "Malformed creation response")
    require(before["state"]["state"] == 0 and after["state"]["state"] == 1, "Creation did not transition EMPTY to READY")
    require(after["state"]["commitment"] == response[:32].hex(), "Wrong created commitment")
    require(after["info"] == before["info"], "App restarted during creation")
    require(after["runtime"]["nvm_write_calls"] - before["runtime"]["nvm_write_calls"] == 3,
            "Expected exactly three app NVM writes")
    check_progress(after["runtime"])
    check_resources(after["metrics"])


def check_progress(value):
    require(value["leaves"] == 260 and value["event_polls"] == 65, "Incomplete tree generation or event servicing")


def responsive_keygen(write, read, commitment):
    """Four early status probes, with one USB reader and one probe outstanding.

    Stop probing well before completion; racing another APDU against the final
    reply can lose that request in the SDK transport. These are sampled response
    latencies, not the maximum gap over the entire computation.
    """
    start = time.monotonic()
    write(bytes.fromhex("e2f5000000"))
    time.sleep(0.05)
    latencies = []
    for _ in range(4):
        probe_start = time.monotonic()
        write(bytes.fromhex("e206000000"))
        require(bytes(read()) == bytes.fromhex("6986"), "Expected busy reply during keygen")
        latencies.append(time.monotonic() - probe_start)
    require(bytes(read()) == commitment + bytes.fromhex("9000"), "Unexpected keygen completion")
    elapsed = time.monotonic() - start
    return {"seconds_including_usb_and_probes": elapsed,
            "busy_response_seconds": latencies, "max_busy_response_seconds": max(latencies)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot", "permissions", "reject", "create", "benchmark", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-elf", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    require(not args.output.exists(), "Refusing to overwrite evidence")
    require(1 <= args.samples <= 5, "Use one to five benchmark samples")
    backend = Backend()
    report = {"schema": 1, "utc": datetime.now(timezone.utc).isoformat(), "action": args.action,
              "expected_elf_sha256": hashlib.sha256(args.expected_elf.read_bytes()).hexdigest(),
              "limits": "Instrumented app stack only; OS syscall stack and watchdog threshold unmeasured"}
    try:
        before = report["before"] = snapshot(backend)
        client = AppClient(backend, CLA)
        if args.action == "permissions":
            report["probes"] = permissions(backend)
        elif args.action == "reject":
            require(before["state"]["state"] == 0, "Rejection requires EMPTY")
            print("Tap REJECT on Create SHRINCS key?", flush=True)
            reply = backend.exchange(cla=CLA, ins=0x30, data=CREATE, expected=0x6985)
            require(not reply.data, "Rejection returned data")
        elif args.action == "create":
            require(before["state"]["state"] == 0, "Creation requires EMPTY")
            print("Approve Create key; computation starts after approval is acknowledged.", flush=True)
            token = backend.exchange(cla=CLA, ins=0xf3, data=CREATE).data
            require(len(token) == 16 and token != bytes(16), "Invalid approval token")
            start = time.monotonic()
            print("Approved; starting timed keygen and durable creation.", flush=True)
            reply = backend.exchange(cla=CLA, ins=0xf4, data=token).data
            report["creation_seconds_excluding_review_including_usb"] = time.monotonic() - start
            report["creation_response"] = reply.hex()
            after = report["after"] = snapshot(backend)
            require(report["creation_seconds_excluding_review_including_usb"] <= 120, "Creation latency target exceeded")
            check_creation(before, after, reply)
        elif args.action == "benchmark":
            require(before["state"]["state"] == 1, "Benchmark requires an existing diagnostic key")
            expected = bytes.fromhex(before["state"]["commitment"])
            report["keygen_seconds_including_usb"] = []
            for sample in range(args.samples):
                start = time.monotonic()
                reply = backend.exchange(cla=CLA, ins=0xf5).data
                elapsed = time.monotonic() - start
                require(reply == expected, "Recomputed public identity changed")
                report["keygen_seconds_including_usb"].append(elapsed)
                print(f"Keygen sample {sample + 1}: {elapsed:.3f}s", flush=True)
            report["responsiveness"] = responsive_keygen(backend.device.device.write,
                lambda: backend.device.device.read(timeout=180000), expected)
        elif args.action == "verify":
            vectors = json.loads((ROOT.parent / "artifacts/vectors.json").read_text())
            report["verification_verdict"] = client.verify(
                dict(vectors["cases"][0], envelope=vectors["boundary_envelope"]))
            require(report["verification_verdict"] == 1,
                    "Canonical 4 KiB verification failed")
        after = report["after"] = snapshot(backend)
        if args.action != "create": unchanged(before, after)
        if args.action in ("benchmark", "create"): check_progress(after["runtime"])
        if args.action == "benchmark":
            require(max(report["keygen_seconds_including_usb"]) <= 120
                    and report["responsiveness"]["seconds_including_usb_and_probes"] <= 120,
                    "Keygen latency target exceeded")
            require(after["runtime"]["busy_replies"] == 4, "Missing sampled busy replies")
        check_resources(after["metrics"])
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = str(error)
        raise
    finally:
        backend.device.close()
        with args.output.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(f"PASS {args.action}; report {args.output}", flush=True)


if __name__ == "__main__": main()
