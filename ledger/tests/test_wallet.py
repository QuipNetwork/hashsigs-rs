"""Protocol-2 key management. Only emulator tests approve creation."""
import hashlib
import hmac
import subprocess
import time
from pathlib import Path

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from app_client import CLA
from test_shrincs import assert_status

PROFILE = bytes.fromhex("807de98ac65ab9f03289950d1878e5ec5261f162af5593ccba2f1709c793c2bb")
PUBLIC_SEED = bytes.fromhex("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8")
ORACLE = Path(__file__).parents[1] / "host/target/release/hashsigs-ledger-vectors"


def expected_public(generation):
    # Independent SLIP21/HMAC implementation checks the OS output convention,
    # namespace, domain separators and the complete native-vs-device keygen.
    master = hmac.digest(b"Symmetric key seed", PUBLIC_SEED, "sha512")
    app_key = hmac.digest(master[:32], b"\0quip.network/SHRINCS/v1", "sha512")[32:]
    seed = hmac.digest(app_key, b"shrincs-ledger/keygen/v1\0" + PROFILE + generation + (4).to_bytes(4, "big"), "sha256")
    return bytes.fromhex(subprocess.check_output([str(ORACLE), "--keygen-public", seed.hex()], text=True).strip())


def approve_creation(client, backend, navigator):
    with client.create_key(PROFILE):
        backend.wait_for_text_on_screen("Create SHRINCS key?")
        start = time.monotonic()
        navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
        backend.wait_for_text_on_screen("Key created", timeout=120)
        elapsed = time.monotonic() - start
        screen = "".join(event.get("text", "") for event in backend._client.get_current_screen_content()["events"])
        navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
    reply = backend.last_async_response
    assert reply.status == 0x9000 and len(reply.data) == 34
    assert reply.data[32:] == (480).to_bytes(2, "big")
    assert reply.data[:32].hex() in "".join(screen.split()), "Full commitment must be visible"
    return reply.data[:32], elapsed


def test_info(client):
    info = client.info()
    assert info.pop("boot_nonce") != bytes(16)
    assert info == {"protocol": 2, "spec": 1, "capabilities": 3, "profile_id": PROFILE,
                    "capacity": 4, "digest_len": 32, "max_envelope": 4096,
                    "public_len": 480, "max_chunk": 200, "record_version": 1}
    assert client.state()["signer_token"] == bytes(20)


@pytest.mark.parametrize("ins", [0x06, 0x30, 0x31, 0x32])
def test_bad_key_headers(client, backend, ins):
    for p1, p2 in [(1, 0), (0, 1)]:
        assert_status(0x6A86, lambda: backend.exchange(cla=CLA, ins=ins, p1=p1, p2=p2))
    assert_status(0x6A80, lambda: backend.exchange(cla=CLA, ins=ins, data=b"x"))


@pytest.mark.parametrize("ins", [0x40, 0x41, 0x42, 0x43, 0xf0])
def test_signing_unavailable(client, backend, ins):
    assert_status(0x6D00, lambda: backend.exchange(cla=CLA, ins=ins))


@pytest.mark.emulator_only
def test_empty_rejection_and_creation(client, backend, navigator, vectors, record_property):
    assert client.state()["state"] == 0
    before = client.state()
    assert_status(0x6A81, lambda: backend.exchange(cla=CLA, ins=0x30, data=bytes(32) + (4).to_bytes(4, "big")))
    assert_status(0x6A81, lambda: backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (5).to_bytes(4, "big")))
    assert_status(0x6986, lambda: client.public_key(bytes(32)))
    with pytest.raises(ExceptionRAPDU) as error:
        with client.create_key(PROFILE):
            backend.wait_for_text_on_screen("Create SHRINCS key?")
            navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT], screen_change_before_first_instruction=False)
    assert error.value.status == 0x6985
    assert client.state() == before
    session = client.begin(vectors["cases"][0])
    assert session and client.state()["operation"] == 1
    assert_status(0x6986, lambda: backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (4).to_bytes(4, "big")))
    assert_status(0x6986, lambda: client.sha256(b"busy"))
    client.cancel()
    commitment, elapsed = approve_creation(client, backend, navigator)
    state = client.state()
    assert state["state"] == 1 and state["commitment"] == commitment
    assert state["generation"] != bytes(32)
    assert state["capacity"] == 4 and state["next_leaf"] == 1 and state["sequence"] == 1
    assert state["stateless_used"] == 0 and state["stateless_limit"] == 1048576
    assert state["operation"] == 0 and state["signer_token"] == bytes(20)
    public = client.public_key(commitment)
    assert len(public) == 480
    assert public == expected_public(state["generation"])
    assert client.public_chunk(commitment, 479, 1) == public[-1:]
    assert_status(0x6A88, lambda: client.public_key(bytes(32)))
    for offset, length in [(0, 0), (0, 201), (480, 1), (479, 2), (65535, 1)]:
        assert_status(0x6A80, lambda: backend.exchange(cla=CLA, ins=0x31, data=commitment + offset.to_bytes(2, "big") + bytes([length])))
    assert_status(0x6986, lambda: backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (4).to_bytes(4, "big")))
    assert client.verify(vectors["cases"][0]) == 0
    client.cancel()
    assert client.state() == state
    assert client.sha256(b"after keygen") == hashlib.sha256(b"after keygen").digest()
    record_property("keygen_speculos_seconds", elapsed)
    print(f"\nFull hybrid keygen and durable commit in Speculos: {elapsed:.3f}s")
