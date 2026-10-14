"""A new host APDU must not freeze review or change the approved operation."""
import hashlib
import pytest
from ragger.navigator import NavInsID
from raw_apdu import connection, send, receive
from test_wallet import PROFILE

pytestmark = pytest.mark.emulator_only


def test_commands_during_key_review_are_busy(client, backend, navigator):
    before = client.state()
    assert before["state"] == 0
    with connection(backend) as stream:
        send(stream, bytes.fromhex("e030000024") + PROFILE + (4).to_bytes(4, "big"))
        backend.wait_for_text_on_screen("Create SHRINCS key?")
        for command in ["e023000000", "e032000000", "b0a7000000", "e010000001ff", "e030000000"]:
            send(stream, bytes.fromhex(command))
            assert receive(stream) == bytes.fromhex("6986")
        navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT], screen_change_before_first_instruction=False)
        assert receive(stream) == bytes.fromhex("6985")
    assert client.state() == before


def test_hash_review_keeps_original_digest(client, backend, navigator):
    message = b"original reviewed input"
    with connection(backend) as stream:
        send(stream, bytes([0xe0, 0x10, 1, 0, len(message)]) + message)
        backend.wait_for_text_on_screen("Approve test hash?")
        send(stream, bytes.fromhex("e010000003") + b"new")
        assert receive(stream) == bytes.fromhex("6986")
        navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
        assert receive(stream) == hashlib.sha256(message).digest() + bytes.fromhex("9000")
