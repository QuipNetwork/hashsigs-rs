"""Durable public APDU evidence and a deadline for the pinned blocking HID read."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace


class EventLog:
    def __init__(self, path):
        # Create before device discovery/open, and never overwrite old evidence.
        self.file = Path(path).open("x", buffering=1)
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.sequence = 0

    def emit(self, event, **fields):
        with self.lock:
            self.sequence += 1
            record = {"sequence": self.sequence, "event": event,
                      "utc": datetime.now(timezone.utc).isoformat(),
                      "elapsed_seconds": time.monotonic() - self.started, **fields}
            self.file.write(json.dumps(record) + "\n")
            self.file.flush()
            os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


@contextmanager
def deadline(log, seconds, operation):
    """A native read may ignore its timeout; exit the whole runner on expiry.

    Keep an outer process timeout too, in case a native call retains the GIL.
    The already-fsynced send event survives even if this callback cannot run.
    """
    completed = threading.Event()

    def expired():
        if not completed.is_set():
            try:
                log.emit("timeout", operation=operation, limit_seconds=seconds)
            finally:
                os._exit(124)

    timer = threading.Timer(max(0, seconds), expired)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        completed.set()
        timer.cancel()


class RecordedBackend:
    def __init__(self, log):
        from ledgerwallet.client import LedgerClient
        from ledgerwallet.transport.hid import HidDevice
        self.log = log
        self.pending = []
        self.counter = 0
        self.device = None
        log.emit("connect_begin")
        with deadline(log, 10, "connect"):
            devices = HidDevice.enumerate_devices()
            if len(devices) != 1:
                raise ValueError(f"Expose exactly one Ledger HID device; found {len(devices)}")
            log.emit("device_selected", transport=devices[0].get_name())
            self.device = LedgerClient(device=devices[0])
        log.emit("connected")

    @staticmethod
    def limit(apdu):
        if apdu[:2] == b"\xe4\xf4":
            return 1800  # Dedicated full-budget (4096 stateful leaves) benchmark.
        if apdu[:2] in (b"\xe2\xf4", b"\xe2\xf5"):
            return 120
        if apdu[:2] in (b"\xe0\xd8", b"\xe2\xf3", b"\xe2\x30", b"\xe4\xf3"):
            return 300  # Explicit human approval; not a public-read deadline.
        return 10

    def write(self, apdu):
        apdu = bytes(apdu)
        # Only the deliberately sampled busy-probe flow may overlap requests.
        if self.pending and not (len(self.pending) == 1
                and self.pending[0]["apdu"][:2] == b"\xe2\xf5"
                and apdu == bytes.fromhex("e206000000")):
            raise ValueError("Another request is outstanding")
        if len(apdu) < 5 or len(apdu) != 5 + apdu[4]:
            raise ValueError("Malformed short APDU")
        self.counter += 1
        request = {"id": self.counter, "apdu": apdu,
                   "expires": time.monotonic() + self.limit(apdu)}
        self.pending.append(request)
        self.log.emit("apdu_send", request_id=request["id"],
                      apdu=apdu[:5].hex() if apdu[:2] in (b"\xe2\xf4", b"\xe4\xf4") else apdu.hex(),
                      data_redacted=apdu[:2] in (b"\xe2\xf4", b"\xe4\xf4"),
                      deadline_seconds=self.limit(apdu))
        with deadline(self.log, 10, f"write:{request['id']}"):
            self.device.device.write(apdu)

    def read(self):
        if not self.pending:
            raise ValueError("No request is outstanding")
        seconds = min(item["expires"] for item in self.pending) - time.monotonic()
        with deadline(self.log, seconds, "read"):
            reply = bytes(self.device.device.read())
        # A sampled GET_INFO gets its busy reply before the keygen completion.
        index = -1 if len(self.pending) == 2 and reply == b"\x69\x86" else 0
        request = self.pending.pop(index)
        redacted = request["apdu"][:2] in (b"\xe2\xf3", b"\xe4\xf3") and reply[-2:] == b"\x90\x00"
        self.log.emit("apdu_receive", request_id=request["id"],
                      response=reply[-2:].hex() if redacted else reply.hex(),
                      data_redacted=redacted, response_bytes=len(reply))
        return reply

    def exchange(self, cla=0xe2, ins=0, p1=0, p2=0, data=b"", expected=0x9000):
        if self.pending:
            raise ValueError("Another request is outstanding")
        if len(data) > 255:
            raise ValueError("APDU too large")
        self.write(bytes([cla, ins, p1, p2, len(data)]) + data)
        reply = self.read()
        if len(reply) < 2:
            raise ValueError("Truncated response")
        status = int.from_bytes(reply[-2:], "big")
        if status != expected:
            raise ValueError(f"INS {ins:02x}: expected {expected:04x}, got {status:04x}")
        return SimpleNamespace(data=reply[:-2], status=status)

    def close(self):
        self.log.emit("close_begin", outstanding=[item["id"] for item in self.pending])
        if self.device is not None:
            with deadline(self.log, 10, "close"):
                self.device.close()
        self.log.emit("closed")
