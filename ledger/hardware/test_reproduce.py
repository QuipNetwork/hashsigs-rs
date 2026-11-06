"""Reproduction steps must not silently schedule additional expensive work."""
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hw-check"))
import reproduce  # noqa: E402


def public_snapshot():
    return {"info": {"boot_nonce": "01" * 16}, "state": {"state": 1, "commitment": "ab" * 32},
            "public_key": "public", "runtime": {"leaves": 260, "event_polls": 65, "nvm_write_calls": 3,
            "marker_sha256": "marker", "payload_sha256": "payload"},
            "metrics": {"heap_capacity": 20480, "heap_peak": 2756, "heap_current": 80,
                        "stack_peak": 11000, "stack_headroom": 7000}}


def test_plain_recompute_is_exactly_one_generation(monkeypatch):
    value = public_snapshot()
    monkeypatch.setattr(reproduce, "snapshot", lambda _, **kw: deepcopy(value))
    calls = []

    def exchange(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(data=bytes.fromhex(value["state"]["commitment"]))

    result = {}
    reproduce.execute(SimpleNamespace(action="recompute", app_version="0.1.1"), SimpleNamespace(exchange=exchange),
                      SimpleNamespace(emit=lambda *a, **kw: None), result)
    assert calls == [{"ins": 0xf5}]
    assert result["before"] == result["after"]


def test_failed_resource_check_retains_committed_state(monkeypatch):
    after = public_snapshot()
    after["metrics"].update(stack_peak=16832, stack_headroom=1640)
    before = deepcopy(after)
    before["state"]["state"] = 0
    before["runtime"]["nvm_write_calls"] = 0
    snapshots = iter([before, after])
    monkeypatch.setattr(reproduce, "snapshot", lambda _, **kw: next(snapshots))
    calls, events = [], []

    def exchange(**kwargs):
        calls.append(kwargs)
        data = bytes([1]) * 16 if kwargs["ins"] == 0xf3 else bytes.fromhex("ab" * 32) + b"\x01\xe0"
        return SimpleNamespace(data=data)

    result = {}
    with pytest.raises(ValueError, match="Stack headroom target missed"):
        reproduce.execute(SimpleNamespace(action="create", app_version="0.1.1"), SimpleNamespace(exchange=exchange),
                          SimpleNamespace(emit=lambda event, **kw: events.append((event, kw))), result)
    assert [call["ins"] for call in calls] == [0xf3, 0xf4]
    assert result["after"] == after
    assert events[-1] == ("snapshot_after", {"value": after})
    assert result["creation_response"].endswith("01e0")


@pytest.mark.parametrize("reported,expected", [((0, 1, 0), (0, 1, 1)), ((0, 1, 1), (0, 1, 0))])
def test_snapshot_rejects_wrong_firmware_version_before_state_reads(reported, expected):
    calls = []

    def exchange(**kwargs):
        calls.append(kwargs["ins"])
        if kwargs["ins"] == 4:
            return SimpleNamespace(data=b"hashsigs-ledger-hw-check-metrics")
        if kwargs["ins"] == 3:
            return SimpleNamespace(data=bytes(reported))
        pytest.fail("Wrong-version preflight must not read state or start an operation")

    with pytest.raises(ValueError, match="Expected separate hardware-check app"):
        reproduce.snapshot(SimpleNamespace(exchange=exchange), expected_version=expected)
    assert calls == [4, 3]
