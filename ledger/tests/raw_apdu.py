"""Pinned Speculos TCP framing for deliberate overlapping/lost requests."""
import socket
from contextlib import contextmanager


@contextmanager
def connection(backend):
    with socket.create_connection(("127.0.0.1", backend._apdu_port), timeout=10) as stream:
        yield stream


def send(stream, command):
    stream.sendall(len(command).to_bytes(4, "big") + command)


def receive(stream):
    def exact(length):
        data = b""
        while len(data) < length:
            chunk = stream.recv(length - len(data))
            assert chunk, "Emulator transport closed"
            data += chunk
        return data
    length = int.from_bytes(exact(4), "big")
    assert length <= 260
    return exact(length + 2)
