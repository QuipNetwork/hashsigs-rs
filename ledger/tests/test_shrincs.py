"""Exercise the compiled no_std verifier through real Gen5 APDUs."""
import pytest
from ragger.error import ExceptionRAPDU

from app_client import CLA


def assert_status(status, operation):
    with pytest.raises(ExceptionRAPDU) as error:
        operation()
    assert error.value.status == status
    assert error.value.data == b""


def test_profile(client, vectors):
    info = client.profile()
    assert info == {
        "protocol": 1, "max_envelope": 4096,
        "profile_id": vectors["profile_id"], "name": "shrincs-256s-sha2",
    }


@pytest.mark.parametrize("index,chunk_size", [(0, 251), (1, 127), (2, 32), (3, 1)])
def test_valid_signatures(client, vectors, index, chunk_size):
    case = vectors["cases"][index]
    assert client.verify(case, chunk_size=chunk_size) == 0


@pytest.mark.parametrize("field", ["hash", "commitment", "envelope"])
def test_tampering(client, vectors, field):
    case = dict(vectors["cases"][0])
    changed = bytearray.fromhex(case[field])
    # The last byte of the envelope is a node, not an ABI length or offset.
    changed[-1] ^= 1
    case[field] = changed.hex()
    assert client.verify(case) == 1
    assert client.verify(vectors["cases"][0]) == 0


@pytest.mark.parametrize("payload", [b"\0", b"\0" * 4096, b"\xff" * 4096], ids=["one-zero", "max-zero", "max-ff"])
def test_malformed_envelope(client, vectors, payload):
    case = dict(vectors["cases"][0], envelope=payload.hex())
    assert client.verify(case) == 2
    assert client.verify(vectors["cases"][0]) == 0


@pytest.mark.parametrize("change", ["truncated", "trailing"])
def test_noncanonical_envelope(client, vectors, change):
    data = bytes.fromhex(vectors["cases"][0]["envelope"])
    data = data[:-1] if change == "truncated" else data + b"\0"
    assert client.verify(dict(vectors["cases"][0], envelope=data.hex())) == 2


@pytest.mark.parametrize("length", [0, 4097, 0xffffffff])
def test_length_limit(client, vectors, length):
    assert_status(0x6A80, lambda: client.begin(vectors["cases"][0], length=length))


def test_session_ordering(client, vectors):
    case = vectors["cases"][0]
    envelope = bytes.fromhex(case["envelope"])
    assert_status(0x6986, lambda: client.write(1, 0, b"x"))
    assert_status(0x6986, lambda: client.finish(1))
    session = client.begin(case)
    assert_status(0x6986, lambda: client.begin(case))
    assert_status(0x6986, lambda: client.finish(session))
    assert_status(0x6A80, lambda: client.write(session, 1, envelope[:20]))
    assert_status(0x6A80, lambda: client.write(session + 1, 0, envelope[:20]))
    assert client.write(session, 0, envelope[:20]) == 20
    assert_status(0x6A80, lambda: client.write(session, 0, envelope[:20]))
    assert_status(0x6A80, lambda: client.write(session, 20, b""))
    for offset in range(20, len(envelope), 251):
        client.write(session, offset, envelope[offset:offset + 251])
    assert_status(0x6A80, lambda: client.write(session, len(envelope), b"x"))
    assert_status(0x6A80, lambda: client.finish(session + 1))
    assert client.finish(session) == 0
    assert_status(0x6986, lambda: client.finish(session))


def test_cancel_and_stale_session(client, vectors):
    case = vectors["cases"][0]
    first = client.begin(case)
    client.write(first, 0, bytes.fromhex(case["envelope"])[:30])
    client.cancel()
    second = client.begin(case)
    assert second != first
    assert_status(0x6A80, lambda: client.write(first, 0, b"x"))
    assert_status(0x6A80, lambda: client.finish(first))
    client.cancel()
    assert client.verify(case) == 0


@pytest.mark.parametrize("ins,data,p1", [(0x05, b"x", 0), (0x20, b"x", 0), (0x23, b"x", 0), (0x22, b"", 1)])
def test_bad_verifier_commands(client, backend, ins, data, p1):
    assert_status(0x6A86 if p1 else 0x6A80, lambda: backend.exchange(cla=CLA, ins=ins, data=data, p1=p1))


def test_repeated_verification_releases_buffers(client, vectors):
    for _ in range(16):
        assert client.verify(vectors["cases"][0]) == 0


def test_maximum_canonical_envelope(client, vectors):
    boundary = vectors["boundary_envelope"]
    assert len(bytes.fromhex(boundary)) == client.profile()["max_envelope"]
    assert client.verify(dict(vectors["cases"][0], envelope=boundary)) == 1
    assert client.verify(vectors["cases"][0]) == 0
