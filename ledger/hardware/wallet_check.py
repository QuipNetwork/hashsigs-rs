"""Operator-assisted key lifecycle checks. Saves public data only; never installs apps.

Run inside the pinned image with the selected USB node and this ledger directory
mounted at /lab. An outer `timeout` must bound HID reads, which can block in C.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace

from Crypto.Hash import keccak
from ledgerwallet.client import LedgerClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from app_client import AppClient, CLA  # noqa: E402

PROFILE = bytes.fromhex("807de98ac65ab9f03289950d1878e5ec5261f162af5593ccba2f1709c793c2bb")


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Backend:
    def __init__(self):
        self.device = LedgerClient()

    def exchange(self, cla=CLA, ins=0, p1=0, p2=0, data=b"", expected=0x9000):
        require(len(data) <= 255, "APDU too large")
        started = time.monotonic()
        if cla == CLA and (ins == 0x30 or (ins == 0x10 and p1 == 1)):
            print(f"Review request {ins:02x} sent at {datetime.now(timezone.utc).isoformat()}", flush=True)
        try:
            reply = self.device.raw_exchange(bytes([cla, ins, p1, p2, len(data)]) + data)
        except Exception:
            print(f"INS {ins:02x}: transport failed after {time.monotonic() - started:.3f}s", flush=True)
            raise
        require(len(reply) >= 2, "Truncated response")
        status = int.from_bytes(reply[-2:], "big")
        require(status == expected, f"INS {ins:02x}: expected {expected:04x}, got {status:04x}")
        return SimpleNamespace(data=reply[:-2], status=status)


def check_public(public, commitment):
    """Independently check fixed canonical ABI and recompute its Keccak commitment."""
    require(len(public) == 480, "Public ABI must be 480 bytes")
    word = lambda offset: int.from_bytes(public[offset:offset + 32], "big")
    require(word(0) == 32, "Invalid outer ABI offset")
    fields = []
    cursor = 160
    for index, length in enumerate([68, 32, 32, 32]):
        require(word(32 + index * 32) == cursor - 32, "Noncanonical ABI offset")
        require(word(cursor) == length, "Invalid public field length")
        start = cursor + 32
        end = start + length
        cursor = start + ((length + 31) // 32) * 32
        require(public[end:cursor] == bytes(cursor - end), "Nonzero ABI padding")
        fields.append(public[start:end])
    stateful, claimed, seed, root = fields
    require(int.from_bytes(stateful[64:], "big") == 4, "Wrong public capacity")
    digest = keccak.new(digest_bits=256)
    digest.update(b"shrincs-public-key/shrincs-256s-sha2" + stateful + seed + root)
    require(digest.digest() == claimed == commitment, "Public commitment mismatch")


def public_json(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: public_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [public_json(item) for item in value]
    return value


def snapshot(client):
    name, version = client.name(), client.version()
    require(name == "hashsigs-ledger" and version in [(0, 2, 0), (0, 2, 1), (0, 2, 2)],
            f"Expected normal app 0.2.0/0.2.1/0.2.2, got {name} {version}")
    info, state = client.info(), client.state()
    require(info["profile_id"] == PROFILE and info["protocol"] == 2
            and info["spec"] == 1 and info["capabilities"] == 3
            and info["capacity"] == 4 and info["digest_len"] == 32
            and info["max_envelope"] == 4096 and info["public_len"] == 480
            and info["max_chunk"] == 200 and info["record_version"] == 1,
            "Unexpected device capabilities")
    require(info["boot_nonce"] != bytes(16), "Zero boot nonce")
    require(state["operation"] == 0 and state["signer_token"] == bytes(20), "Device is busy")
    public = b""
    if state["state"] in (1, 2):
        public = client.public_key(state["commitment"])
        check_public(public, state["commitment"])
        require(state["generation"] != bytes(32) and state["capacity"] == 4
                and state["next_leaf"] == 1 and state["sequence"] == 1
                and state["stateless_used"] == 0 and state["stateless_limit"] == 1048576,
                "Unexpected counters for the signing-disabled app")
    return public_json({"name": name, "version": version, "info": info,
                        "state": state, "public_key": public})


def compare(baseline, current, new_boot):
    for field in ("name", "version", "state", "public_key"):
        require(current[field] == baseline[field], f"Changed {field} after reload")
    for key, value in baseline["info"].items():
        if key != "boot_nonce":
            require(current["info"][key] == value, f"Changed device info: {key}")
    if new_boot:
        require(current["info"]["boot_nonce"] != baseline["info"]["boot_nonce"],
                "Boot nonce did not change; app restart not observed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["snapshot", "reject", "create", "hash-approve", "hash-reject"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-elf", type=Path, default=ROOT / "artifacts/app.elf",
                        help="Build artifact to record; this is not installed-code attestation")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--new-boot", action="store_true")
    parser.add_argument("--expect-state", choices=["empty", "ready", "locked"])
    args = parser.parse_args()
    require(not args.output.exists(), "Output already exists; choose a new report path")
    require(not args.new_boot or args.baseline, "--new-boot requires --baseline")
    baseline = json.loads(args.baseline.read_text())["after"] if args.baseline else None
    backend = Backend()
    try:
        client = AppClient(backend)
        before = snapshot(client)
        elapsed = None
        if args.action in ("create", "reject"):
            require(before["state"]["state"] == 0, "Creation check requires EMPTY; never replaces a key")
            verb = "APPROVE creation, then acknowledge the full commitment" if args.action == "create" else "REJECT creation"
            print(f"On the Gen5: {verb}.", flush=True)
            start = time.monotonic()
            reply = backend.exchange(ins=0x30, data=PROFILE + (4).to_bytes(4, "big"),
                                     expected=0x9000 if args.action == "create" else 0x6985)
            elapsed = time.monotonic() - start
            if args.action == "create":
                require(len(reply.data) == 34 and reply.data[32:] == (480).to_bytes(2, "big"),
                        "Invalid creation response")
            else:
                require(not reply.data, "Rejection returned unexpected data")
        elif args.action.startswith("hash-"):
            message = b"SHRINCS Gen5 physical review 2026-11-05"
            approve = args.action == "hash-approve"
            print(f"On the Gen5: {'APPROVE' if approve else 'REJECT'} the test hash.", flush=True)
            reply = backend.exchange(ins=0x10, p1=1, data=message,
                                     expected=0x9000 if approve else 0x6985)
            require(reply.data == (hashlib.sha256(message).digest() if approve else b""),
                    "Incorrect reviewed hash response")
        after = snapshot(client)
        if args.action == "create":
            require(after["state"]["state"] == 1 and after["state"]["commitment"] == reply.data[:32].hex(),
                    "Created identity does not match stored state")
            backend.exchange(ins=0x30, data=PROFILE + (4).to_bytes(4, "big"), expected=0x6986)
            require(snapshot(client) == after, "Repeated creation changed state")
        else:
            require(before == after, "Read-only or rejected operation changed state")
        if args.expect_state:
            require(after["state"]["state"] == {"empty": 0, "ready": 1, "locked": 3}[args.expect_state],
                    f"Expected state {args.expect_state}, got {after['state']['state']}")
        if baseline:
            compare(baseline, after, args.new_boot)
        report = {"schema": 1, "utc": datetime.now(timezone.utc).isoformat(), "action": args.action,
                  "before": before, "after": after,
                  "request_seconds_including_operator_review": elapsed,
                  "baseline": str(args.baseline) if args.baseline else None,
                  "new_boot_observed": bool(args.new_boot),
                  "expected_build_elf_sha256": hashlib.sha256(args.expected_elf.read_bytes()).hexdigest(),
                  "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        with args.output.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        print(json.dumps(after, indent=2), flush=True)
        print(f"PASS; public report saved to {args.output}", flush=True)
    finally:
        backend.device.close()


if __name__ == "__main__":
    main()
