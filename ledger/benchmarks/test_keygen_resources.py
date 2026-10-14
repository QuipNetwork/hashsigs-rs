"""Resource measurements from the separately identified emulator metrics ELF."""
import hashlib
import json
import os
from pathlib import Path

from app_client import CLA
from test_wallet import approve_creation, expected_public


def metrics(backend):
    data = backend.exchange(cla=CLA, ins=0xf0).data
    assert len(data) == 20
    names = ["heap_capacity", "heap_peak", "heap_current", "stack_capacity", "stack_peak"]
    result = dict(zip(names, [int.from_bytes(data[i:i+4], "big") for i in range(0, 20, 4)]))
    result["stack_headroom"] = result["stack_capacity"] - result["stack_peak"]
    return result


def test_keygen_resources(client, backend, navigator, vectors):
    assert client.name().endswith("-metrics")
    output = Path(os.environ["LEDGER_BENCH_OUTPUT"])
    report = {"backend": "Speculos 0.27.0", "device": "apex_p", "profile": "shrincs-256s-sha2",
              "elf_sha256": hashlib.sha256((output / "app-metrics.elf").read_bytes()).hexdigest(),
              "startup": metrics(backend)}
    commitment, seconds = approve_creation(client, backend, navigator)
    assert client.public_key(commitment) == expected_public(client.state()["generation"])
    report["keygen_seconds_including_approval_navigation"] = seconds
    report["after_keygen"] = metrics(backend)
    assert client.verify(dict(vectors["cases"][0], envelope=vectors["boundary_envelope"])) == 1
    report["after_max_envelope"] = metrics(backend)
    (output / "resources.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    for measurement in [report["after_keygen"], report["after_max_envelope"]]:
        assert measurement["heap_peak"] <= 18 * 1024
        assert measurement["stack_headroom"] >= 4 * 1024
