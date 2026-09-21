"""Run real APDUs and screen interactions against the Gen5 ELF in Speculos."""

import hashlib
from pathlib import Path
import tomllib

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from app_client import CLA


def test_app_identity(client):
    manifest = tomllib.loads((Path(__file__).parents[1] / "app" / "Cargo.toml").read_text())
    assert client.name() == manifest["package"]["name"]
    assert client.version() == tuple(map(int, manifest["package"]["version"].split(".")))


@pytest.mark.parametrize("length", [0, 1, 55, 56, 63, 64, 65, 255])
def test_sha256(client, length):
    message = bytes(range(length))
    assert client.sha256(message) == hashlib.sha256(message).digest()


def test_known_sha256_vector(client):
    assert client.sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


@pytest.mark.emulator_only
def test_approve_hash(client, backend, navigator):
    message = b"hashsigs-rs"
    with client.review_hash(message):
        backend.wait_for_text_on_screen("Approve test hash?")
        navigator.navigate(
            [NavInsID.USE_CASE_CHOICE_CONFIRM],
            screen_change_before_first_instruction=False,
        )
    assert backend.last_async_response.status == 0x9000
    assert backend.last_async_response.data == hashlib.sha256(message).digest()
    assert client.sha256(b"after approval") == hashlib.sha256(b"after approval").digest()


@pytest.mark.emulator_only
def test_reject_hash(client, backend, navigator):
    with pytest.raises(ExceptionRAPDU) as error:
        with client.review_hash(b"reject this"):
            backend.wait_for_text_on_screen("Approve test hash?")
            navigator.navigate(
                [NavInsID.USE_CASE_CHOICE_REJECT],
                screen_change_before_first_instruction=False,
            )
    assert error.value.status == 0x6985
    assert error.value.data == b""
    assert client.sha256(b"after rejection") == hashlib.sha256(b"after rejection").digest()


@pytest.mark.parametrize(
    "command,status",
    [
        ({"cla": CLA + 1, "ins": 0x03}, 0x6E00),
        ({"cla": CLA, "ins": 0xFF}, 0x6D00),
        ({"cla": CLA, "ins": 0x03, "p1": 1}, 0x6A86),
        ({"cla": CLA, "ins": 0x10, "p1": 2}, 0x6A86),
        ({"cla": CLA, "ins": 0x10, "p2": 1}, 0x6A86),
        ({"cla": CLA, "ins": 0x03, "data": b"unexpected"}, 0x6A80),
        ({"cla": CLA, "ins": 0x04, "data": b"unexpected"}, 0x6A80),
    ],
)
def test_invalid_command(client, backend, command, status):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(**command)
    assert error.value.status == status
    assert error.value.data == b""
    assert client.name() == "hashsigs-ledger"


@pytest.mark.parametrize("apdu", [bytes.fromhex("e00300"), bytes.fromhex("e003000005")])
@pytest.mark.emulator_only
def test_malformed_apdu(client, backend, apdu):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu)
    assert error.value.status == 0x6E03
    assert error.value.data == b""
    assert client.version() == (0, 1, 0)
