"""Exercise failure evidence and request ordering without exposing USB."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from event_record import EventLog, RecordedBackend  # noqa: E402


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def backend(log, replies):
    value = RecordedBackend.__new__(RecordedBackend)
    value.log, value.pending, value.counter = log, [], 0
    remaining = iter(replies)
    writes = []
    value.device = SimpleNamespace(device=SimpleNamespace(
        write=writes.append, read=lambda: next(remaining)), close=lambda: None)
    return value, writes


@pytest.mark.parametrize("cla", [0xe2, 0xe4])
def test_permission_denial_and_approval_token_redaction(tmp_path, cla):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    token = bytes.fromhex("9a" * 16)
    transport, writes = backend(log, [b"\x69\x85", token + b"\x90\x00", b"\x90\x00"])
    with pytest.raises(ValueError, match="got 6985"):
        transport.exchange(cla=cla, ins=0xf3)
    assert transport.exchange(cla=cla, ins=0xf3).data == token
    transport.exchange(cla=cla, ins=0xf4, data=token)
    transport.close()
    log.close()
    assert len(writes) == 3 and writes[-1][5:] == token
    assert token.hex() not in path.read_text()
    observations = records(path)
    assert [r["sequence"] for r in observations] == list(range(1, len(observations) + 1))
    assert observations[1]["response"] == "6985"
    execute = next(r for r in observations if r["event"] == "apdu_send" and r["apdu"][2:4] == "f4")
    assert execute["deadline_seconds"] == (1800 if cla == 0xe4 else 120)
    with pytest.raises(FileExistsError):
        EventLog(path)


def test_busy_probe_does_not_lose_original_request(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    transport, _ = backend(log, [b"\x69\x86", bytes(32) + b"\x90\x00"])
    transport.write(bytes.fromhex("e2f5000000"))
    with pytest.raises(ValueError, match="outstanding"):
        transport.exchange(ins=0x32)
    transport.write(bytes.fromhex("e206000000"))
    with pytest.raises(ValueError, match="outstanding"):
        transport.write(bytes.fromhex("e206000000"))
    assert transport.read() == b"\x69\x86"
    assert transport.read() == bytes(32) + b"\x90\x00"
    assert not transport.pending
    log.close()
    assert [r["request_id"] for r in records(path) if r["event"] == "apdu_receive"] == [2, 1]


@pytest.mark.parametrize("mode", ["deadline", "killed"])
def test_request_evidence_survives_blocked_read_or_process_death(tmp_path, mode):
    path = tmp_path / "events.jsonl"
    code = """
import sys, time
from event_record import EventLog, deadline
log = EventLog(sys.argv[1])
log.emit('apdu_send', apdu='e206000000')
with deadline(log, 0.15 if sys.argv[2] == 'deadline' else 60, 'read'):
    time.sleep(60)
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
    process = subprocess.Popen([sys.executable, "-c", code, str(path), mode], env=env)
    try:
        if mode == "killed":
            stop = time.monotonic() + 5
            while time.monotonic() < stop:
                if path.exists() and path.stat().st_size:
                    break
                time.sleep(0.01)
            else:
                pytest.fail("Child failed to record its request")
            process.kill()
        status = process.wait(timeout=5)
        assert status == (124 if mode == "deadline" else -9)
        events = records(path)
        assert events[0]["event"] == "apdu_send"
        assert [r["event"] for r in events] == (["apdu_send", "timeout"] if mode == "deadline" else ["apdu_send"])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
