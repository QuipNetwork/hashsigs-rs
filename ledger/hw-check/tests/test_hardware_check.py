"""Shared wallet flows in a separate namespace; public emulator seed only."""
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import time

from elftools.elf.elffile import ELFFile
from ledgered.devices import Devices
import pytest
from ragger.backend.speculos import SpeculosBackend
from ragger.error import ExceptionRAPDU
from ragger.navigator import TouchNavigator, NavInsID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from check import (CLA, CREATE, PROFILE, AppClient, snapshot, unchanged, permissions,
                   check_creation, check_resources, check_progress, responsive_keygen)  # noqa: E402
from raw_apdu import connection, send, receive  # noqa: E402
from test_wallet import PUBLIC_SEED, ORACLE  # noqa: E402

APP = ROOT / "target/apex_p/release/hashsigs-ledger-hw-check"
LABEL = b"quip.network/SHRINCS/HW-CHECK/v1"


@pytest.fixture
def setup():
    device = Devices.get_by_name("apex_p")
    with SpeculosBackend(APP, device, args=["--seed", "hex:" + PUBLIC_SEED.hex()]) as backend:
        yield backend, AppClient(backend, CLA), TouchNavigator(backend, device)


def expect_status(backend, status, **kwargs):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(cla=CLA, **kwargs)
    assert error.value.status == status


def arm(backend, navigator):
    with backend.exchange_async(cla=CLA, ins=0xf3, data=CREATE):
        backend.wait_for_text_on_screen("Create SHRINCS key?")
        navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
    token = backend.last_async_response.data
    assert len(token) == 16 and token != bytes(16)
    return token


def expected_public(generation):
    master = hmac.digest(b"Symmetric key seed", PUBLIC_SEED, "sha512")
    app_key = hmac.digest(master[:32], b"\0" + LABEL, "sha512")[32:]
    seed = hmac.digest(app_key, b"shrincs-ledger/keygen/v1\0" + PROFILE + generation
                       + (4).to_bytes(4, "big"), "sha256")
    return bytes.fromhex(subprocess.check_output([str(ORACLE), "--keygen-public", seed.hex()], text=True).strip())


def test_namespace_and_curve_permissions(setup):
    backend, _, _ = setup
    results = permissions(backend)
    print(json.dumps(results, indent=2))
    assert len(results) == 7


@pytest.mark.parametrize("instruction", [0x30, 0xf3])
def test_rejection_keeps_exact_empty_nvm(setup, instruction):
    backend, _, navigator = setup
    before = snapshot(backend)
    assert before["state"]["state"] == 0
    assert before["runtime"]["marker_sha256"] == hashlib.sha256(bytes(512)).hexdigest()
    assert before["runtime"]["payload_sha256"] == hashlib.sha256(bytes(512)).hexdigest()
    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async(cla=CLA, ins=instruction, data=CREATE):
            backend.wait_for_text_on_screen("Create SHRINCS key?")
            navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT], screen_change_before_first_instruction=False)
    assert error.value.status == 0x6985
    after = snapshot(backend)
    unchanged(before, after)
    assert after["runtime"]["leaves"] == 0 and after["runtime"]["nvm_write_calls"] == 0
    expect_status(backend, 0x6986, ins=0xf4, data=bytes(16))


@pytest.mark.parametrize("cancel", ["wrong-token", "read", "cancel"])
def test_approval_token_is_single_use_and_cancelled_by_other_commands(setup, cancel):
    backend, client, navigator = setup
    before = snapshot(backend)
    token = arm(backend, navigator)
    if cancel == "wrong-token":
        expect_status(backend, 0x6986, ins=0xf4, data=bytes([token[0] ^ 1]) + token[1:])
    elif cancel == "read":
        client.state()
    else:
        client.cancel()
    expect_status(backend, 0x6986, ins=0xf4, data=token)
    unchanged(before, snapshot(backend))


def test_malformed_commands_do_not_write(setup):
    backend, _, _ = setup
    before = snapshot(backend)
    for ins, p1, p2, data, status in [
        (0xf1, 7, 0, b"", 0x6a86), (0xf2, 1, 0, b"", 0x6a86),
        (0xf3, 0, 1, CREATE, 0x6a86), (0xf1, 0, 0, b"x", 0x6a80),
        (0xf2, 0, 0, b"x", 0x6a80), (0xf3, 0, 0, b"", 0x6a80),
        (0xf3, 0, 0, bytes(36), 0x6a81), (0xf5, 0, 0, b"x", 0x6a80),
        (0xf5, 0, 0, b"", 0x6986), (0xf4, 0, 0, bytes(16), 0x6986),
    ]:
        expect_status(backend, status, ins=ins, p1=p1, p2=p2, data=data)
    unchanged(before, snapshot(backend))


def test_measured_creation_recomputation_responsiveness_and_max_verification(setup):
    backend, client, navigator = setup
    before = snapshot(backend)
    token = arm(backend, navigator)
    start = time.monotonic()
    reply = backend.exchange(cla=CLA, ins=0xf4, data=token).data
    seconds = time.monotonic() - start
    after = snapshot(backend)
    check_creation(before, after, reply)
    assert seconds < 120
    assert client.public_key(reply[:32]) == expected_public(client.state()["generation"])
    expect_status(backend, 0x6986, ins=0xf4, data=token)
    expect_status(backend, 0x6986, ins=0xf3, data=CREATE)
    expect_status(backend, 0x6986, ins=0x30, data=CREATE)
    with connection(backend) as stream:
        response_times = responsive_keygen(lambda data: send(stream, data), lambda: receive(stream), reply[:32])
    recomputed = snapshot(backend)
    unchanged(after, recomputed)
    check_progress(recomputed["runtime"])
    assert recomputed["runtime"]["busy_replies"] == len(response_times["busy_response_seconds"])
    vectors = json.loads((ROOT.parent / "artifacts/vectors.json").read_text())
    assert client.verify(dict(vectors["cases"][0], envelope=vectors["boundary_envelope"])) == 1
    final = snapshot(backend)
    unchanged(after, final)
    check_resources(final["metrics"])
    print(json.dumps({"creation_seconds_excluding_review": seconds, "after_creation": after["metrics"],
                      "final_metrics": final["metrics"], "responsiveness": response_times}, indent=2))


def test_install_isolation():
    with APP.open("rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        parameters = symbols.get_symbol_by_name("install_parameters")[0]
        section = elf.get_section(parameters["st_shndx"])
        offset = parameters["st_value"] - section["sh_addr"]
        raw = section.data()[offset:offset + parameters["st_size"]]
        tags = {}
        while raw:
            tag, length = raw[:2]
            assert length < 128 and tag not in tags
            tags[tag], raw = raw[2:2 + length], raw[2 + length:]
        name = b"SHRINCS HW Check"
        assert tags[1] == name
        assert tags[4] == bytes([8, 0x80 | (len(LABEL) + 1), 0]) + LABEL + b"\0"
        assert elf.get_section_by_name("ledger.app_flags").data().strip(b"\0\n") == b"0x200"
        storage = [s for s in symbols.iter_symbols() if "WALLET_NVM" in s.name]
        assert len(storage) == 1 and storage[0]["st_size"] == 1024
        assert storage[0]["st_value"] % 512 == 0
        assert symbols.get_symbol_by_name("hardware_probe")
    scripts = list(APP.parent.glob("*.apdu"))
    assert len(scripts) == 1
    first = bytes.fromhex(scripts[0].read_text().splitlines()[0])
    assert first == bytes([0xe0, 0, 0, 0, len(name) + 2, 0x0c, len(name)]) + name
    normal = ROOT.parent / "app/target/apex_p/release/hashsigs-ledger"
    with normal.open("rb") as source:
        elf = ELFFile(source)
        assert b"HW-CHECK" not in elf.get_section_by_name(".rodata").data()
        assert not elf.get_section_by_name(".symtab").get_symbol_by_name("hardware_probe")
