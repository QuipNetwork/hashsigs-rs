"""PUBLIC-fixture NVM checks. Never installs apps or accesses wallet secrets.

Hardware use requires the separately installed/open SHRINCS NVM Diag app and an
outer timeout for HID. Checkpoint stops happen BETWEEN syscalls, not within them.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLA = 0xE1
STAGES = {
    0: "complete", 1: "before invalidation", 2: "after invalidation write",
    3: "after invalidation readback", 4: "before payload write",
    5: "after payload write", 6: "after payload readback",
    7: "before commit marker", 8: "after commit marker write",
    9: "after commit marker readback",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def fixtures(path):
    data = path.read_bytes()
    require(len(data) == 2048, "Invalid fixture size")
    records = {n: data[i * 512:(i + 1) * 512] for i, n in enumerate((1, 2, 4, 5))}
    for n, record in records.items():
        key = hmac.digest(bytes([7]) * 32,
                          b"shrincs-ledger/state-mac/v1\0" + record[24:88], "sha256")
        require(hmac.compare_digest(hmac.digest(key, record[:480], "sha256"), record[480:]),
                "Invalid PUBLIC fixture MAC")
        require(record[:8] == b"SHRINCS2" and record[56:88] == bytes([9]) * 32,
                "Invalid fixture generation")
        require(int.from_bytes(record[12:20], "big") == n
                and int.from_bytes(record[124:128], "big") == n
                and int.from_bytes(record[268:272], "big") == n, "Invalid fixture counters")
        require(record[88:120] == records[1][88:120], "Fixture commitment changed")
    return records


def decode(data):
    require(len(data) == 203 and data[:11] == b"NVM-DIAG\x00\x01\x00",
            "Expected separate NVM diagnostic app 0.1.0")
    require(data[11] <= 10 and data[12] <= 3, "Invalid diagnostic flags")
    require(data[13:29] != bytes(16), "Zero boot nonce")
    state = data[29:139]
    return {"stage": data[11], "guards": data[12], "boot_nonce": data[13:29].hex(),
            "state_bytes": state.hex(), "state": state[0],
            "next_leaf": int.from_bytes(state[69:73], "big"),
            "sequence": int.from_bytes(state[81:89], "big"),
            "commitment": state[1:33].hex(),
            "marker_sha256": data[139:171].hex(), "payload_sha256": data[171:203].hex()}


def exchange(backend, ins=2, p1=0, p2=0):
    response = backend.exchange(cla=CLA, ins=ins, p1=p1, p2=p2)
    require(response.status == 0x9000, f"Unexpected status {response.status:04x}")
    return decode(response.data)


def expected(records, source, target, cut):
    require((source, target) in ((0, 1), (1, 2), (4, 5)), "Invalid transition")
    require(cut in STAGES, "Invalid checkpoint")
    old = records[source] if source else bytes(512)
    if cut == 1:
        marker, payload, next_leaf = bytes([0xa5 if source else 0]) * 512, old, source
    elif cut in (2, 3, 4):
        marker, payload, next_leaf = bytes(512), old, 0
    elif cut in (5, 6, 7):
        marker, payload, next_leaf = bytes(512), records[target], 0
    else:
        marker, payload, next_leaf = bytes([0xa5]) * 512, records[target], target
    state = bytearray(110)
    state[0] = (2 if next_leaf == 5 else 1) if next_leaf else (0 if payload == bytes(512) else 3)
    if next_leaf:
        record = records[next_leaf]
        state[1:33], state[33:65] = record[88:120], record[56:88]
        state[65:69] = (4).to_bytes(4, "big")
        state[69:73] = next_leaf.to_bytes(4, "big")
        state[77:81] = (1 << 20).to_bytes(4, "big")
        state[81:89] = next_leaf.to_bytes(8, "big")
    return {"state_bytes": state.hex(), "guards": 3,
            "marker_sha256": hashlib.sha256(marker).hexdigest(),
            "payload_sha256": hashlib.sha256(payload).hexdigest()}


def check_state(actual, wanted):
    for key, value in wanted.items():
        require(actual[key] == value, f"Unexpected {key}: {actual[key]} != {value}")


def run_case(backend, records, source, target, cut):
    wanted = expected(records, source, target, cut)
    # Verify the app identity read-only before any mutation, even PREPARE.
    exchange(backend)
    prepared = exchange(backend, 0x10, source)
    check_state(prepared, expected(records, source, target, 1))
    after = exchange(backend, 0x11, target, cut)
    check_state(after, wanted)
    require(after["stage"] == (cut or 10), "Wrong stop point")
    require(after["boot_nonce"] == prepared["boot_nonce"], "App restarted during write")
    return {"source": source, "target": target, "cut": cut,
            "checkpoint": STAGES[cut], "prepared": prepared, "after": after}


def compare_restart(baseline, after):
    check_state(after, {key: baseline[key] for key in
                      ("guards", "state_bytes", "marker_sha256", "payload_sha256")})
    require(after["stage"] == 0, "Checkpoint RAM survived; app restart not observed")
    require(after["boot_nonce"] != baseline["boot_nonce"], "Boot nonce did not change")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("matrix", "case", "snapshot"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--expected-elf", type=Path, required=True)
    parser.add_argument("--source", type=int, choices=(0, 1, 4))
    parser.add_argument("--target", type=int, choices=(1, 2, 5))
    parser.add_argument("--cut", type=int, choices=range(10))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--restart-kind", choices=("app-reopen", "operator-power-cycle"))
    args = parser.parse_args()
    require(not args.output.exists(), "Refusing to overwrite evidence")
    require(bool(args.baseline) == bool(args.restart_kind), "Restart comparison needs baseline and kind")
    require(not args.baseline or args.action == "snapshot", "Baseline applies only to snapshots")
    records = fixtures(args.fixtures)
    # Shared thin USB transport; no seed/configuration or installation operation.
    import sys
    sys.path.insert(0, str(ROOT.parent / "hardware"))
    from wallet_check import Backend
    backend = Backend()
    report = {"schema": 1, "utc": datetime.now(timezone.utc).isoformat(),
              "evidence": "completed-syscall boundaries; NOT in-flight power interruption",
              "expected_elf_sha256": hashlib.sha256(args.expected_elf.read_bytes()).hexdigest(),
              "fixture_sha256": hashlib.sha256(args.fixtures.read_bytes()).hexdigest()}
    if args.action == "case":
        require(None not in (args.source, args.target, args.cut), "Case requires source, target and cut")
        report.update(run_case(backend, records, args.source, args.target, args.cut))
    elif args.action == "matrix":
        report["cases"] = [run_case(backend, records, source, target, cut)
                           for source, target in ((0, 1), (1, 2), (4, 5)) for cut in range(10)]
        report["after"] = exchange(backend)
    else:
        report["after"] = exchange(backend)
        if args.baseline:
            baseline = json.loads(args.baseline.read_text())
            require(baseline["expected_elf_sha256"] == report["expected_elf_sha256"]
                    and baseline["fixture_sha256"] == report["fixture_sha256"], "Artifact changed")
            compare_restart(baseline["after"], report["after"])
            report["restart_kind"] = args.restart_kind
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(f"PASS {args.action}; state={report['after']['state']} next={report['after']['next_leaf']}; {args.output}")


if __name__ == "__main__":
    main()
