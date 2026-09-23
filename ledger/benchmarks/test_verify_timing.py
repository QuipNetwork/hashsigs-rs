"""Host-observed timings of the installed app; not instrumented CPU timings."""
import hashlib
import importlib.metadata
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from time import perf_counter_ns

import pytest


CHUNK_SIZE = 251


def summarize_ns(values):
    ordered = sorted(values)
    return {
        "min": ordered[0] / 1_000_000,
        "median": median(ordered) / 1_000_000,
        "p95": ordered[math.ceil(0.95 * len(ordered)) - 1] / 1_000_000,
        "max": ordered[-1] / 1_000_000,
    }


def measure(client, case, chunks, expected_version):
    start = perf_counter_ns()
    version = client.version()
    version_done = perf_counter_ns()
    assert version == expected_version

    begin = perf_counter_ns()
    session = client.begin(case)
    begun = perf_counter_ns()
    for offset, chunk in chunks:
        assert client.write(session, offset, chunk) == offset + len(chunk)
    uploaded = perf_counter_ns()
    verdict = client.finish(session)
    finished = perf_counter_ns()
    assert verdict == 0, "Only successfully verified signatures count as timing samples"
    return {
        "version_round_trip_ns": version_done - start,
        "begin_ns": begun - begin,
        "upload_ns": uploaded - begun,
        "finish_verify_ns": finished - uploaded,
        "total_ns": finished - begin,
    }


@pytest.mark.parametrize("index", range(4), ids=["leaf1", "leaf2", "leaf3", "leaf4"])
def test_verify_timing(client, vectors, pytestconfig, monkeypatch, index):
    # Ragger installs its own INFO handler; pytest capture alone does not prevent
    # formatting and writing every packet. Restore normal logging after this test.
    monkeypatch.setattr(client.backend.apdu_logger, "disabled", True)
    samples = int(os.environ.get("LEDGER_BENCH_SAMPLES", "30"))
    warmup = int(os.environ.get("LEDGER_BENCH_WARMUP", "5"))
    assert samples > 0 and warmup >= 0
    case = vectors["cases"][index]
    envelope = bytes.fromhex(case["envelope"])
    chunks = [(offset, envelope[offset:offset + CHUNK_SIZE])
              for offset in range(0, len(envelope), CHUNK_SIZE)]
    info = client.profile()
    assert info["protocol"] == 1
    assert info["name"] == vectors["profile"] == "shrincs-256s-sha2"
    assert info["profile_id"] == vectors["profile_id"]
    assert len(envelope) <= info["max_envelope"]
    assert client.name() == "hashsigs-ledger"
    version = client.version()
    for _ in range(warmup):
        measure(client, case, chunks, version)
    measured = [measure(client, case, chunks, version) for _ in range(samples)]
    stats = {key.removesuffix("_ns") + "_ms": summarize_ns([row[key] for row in measured])
             for key in measured[0]}
    root = Path(__file__).resolve().parents[1]
    report = {
        "schema": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "device": pytestconfig.getoption("device"),
        "backend": pytestconfig.getoption("backend"),
        "app_version": list(version),
        "profile": info,
        "leaf": case["leaf"],
        "envelope_bytes": len(envelope),
        "chunk_bytes": CHUNK_SIZE,
        "write_apdus": len(chunks),
        "warmup_per_leaf": warmup,
        "samples": samples,
        "message_digest": case["hash"],
        "public_key_commitment": case["commitment"],
        "build_elf_sha256": hashlib.sha256(
            (root / "app/target/apex_p/release/hashsigs-ledger").read_bytes()).hexdigest(),
        "vectors_sha256": hashlib.sha256((root / "artifacts/vectors.json").read_bytes()).hexdigest(),
        "benchmark_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "packages": {name: importlib.metadata.version(name)
                     for name in ("ragger", "ledgerwallet", "pytest")},
        "method": {
            "clock": "time.perf_counter_ns, host wall clock",
            "apdu_logging": "Disabled during warmup and measurement",
            "finish_verify": "FINISH_VERIFY round trip: USB, host/firmware processing, ABI decoding and cryptographic verification; excludes signature upload",
            "total": "BEGIN_VERIFY plus all WRITE_VERIFY chunks plus FINISH_VERIFY; excludes setup, version query, warmup and cleanup",
            "version_round_trip": "Separate version APDU for transport context; not subtracted from verification timings",
            "p95": "Nearest rank, ceil(0.95 * samples)",
            "scope": "Repeated verification of four public fixtures from one capacity-four key; no signing and no pure CPU measurement",
        },
        "summary": stats,
        "raw_samples_ns": measured,
    }
    out = Path(os.environ.get("LEDGER_BENCH_OUTPUT", root / "artifacts/benchmarks"))
    out.mkdir(parents=True, exist_ok=True)
    (out / f"verify-leaf{case['leaf']}.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nleaf={case['leaf']} bytes={len(envelope)} samples={samples} "
          f"finish_median_ms={stats['finish_verify_ms']['median']:.3f} "
          f"finish_p95_ms={stats['finish_verify_ms']['p95']:.3f} "
          f"upload_median_ms={stats['upload_ms']['median']:.3f} "
          f"total_median_ms={stats['total_ms']['median']:.3f}", flush=True)
