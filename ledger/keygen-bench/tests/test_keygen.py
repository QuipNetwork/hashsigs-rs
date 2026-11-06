"""Full-budget emulator computation, approval, and isolated installation."""
import json
from pathlib import Path
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
from check import CLA, CAPACITY, LEAVES, PROFILE, check_public, check_resources, metrics, read_public  # noqa: E402

APP = ROOT / "target/apex_p/release/hashsigs-ledger-keygen-bench"


def status(backend, expected, **kwargs):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(cla=CLA, **kwargs)
    assert error.value.status == expected


def test_full_keygen_and_approval():
    device = Devices.get_by_name("apex_p")
    with SpeculosBackend(APP, device) as backend:
        navigator = TouchNavigator(backend, device)
        assert backend.exchange(cla=CLA, ins=6).data == PROFILE + CAPACITY.to_bytes(4, "big") + LEAVES.to_bytes(4, "big")
        assert backend.exchange(cla=CLA, ins=4).data == b"hashsigs-ledger-keygen-bench"
        status(backend, 0x6986, ins=0xf4, data=bytes(16))
        status(backend, 0x6a80, ins=0xf3, data=b"x")
        status(backend, 0x6d00, ins=0x30)
        status(backend, 0x6d00, ins=0x40)
        with pytest.raises(ExceptionRAPDU) as error:
            with backend.exchange_async(cla=CLA, ins=0xf3):
                backend.wait_for_text_on_screen("Benchmark full key?")
                navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT], screen_change_before_first_instruction=False)
        assert error.value.status == 0x6985
        # Ragger 1.47.3 can raise the async rejection inside navigation before
        # its normal resume_ticker call. Restore real-time ticks before hashing.
        while backend._ticker_paused_count:
            backend.resume_ticker()
        status(backend, 0x6986, ins=0xf4, data=bytes(16))

        def arm():
            with backend.exchange_async(cla=CLA, ins=0xf3):
                backend.wait_for_text_on_screen("Benchmark full key?")
                navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
            return backend.last_async_response.data

        token = arm()
        status(backend, 0x6986, ins=0xf4, data=bytes([token[0] ^ 1]) + token[1:])
        status(backend, 0x6986, ins=0xf4, data=token)
        token = arm()
        backend.exchange(cla=CLA, ins=3)
        status(backend, 0x6986, ins=0xf4, data=token)
        token = arm()
        start = time.monotonic()
        response = backend.exchange_raw(bytes([CLA, 0xf4, 0, 0, 16]) + token, tick_timeout=18000)
        raw = response.data + response.status.to_bytes(2, "big")
        seconds = time.monotonic() - start
        assert len(raw) == 62 and raw[-2:] == b"\x90\x00"
        assert int.from_bytes(raw[32:36], "big") == LEAVES
        assert int.from_bytes(raw[36:40], "big") == LEAVES // 4
        memory = metrics(raw[40:60])
        check_resources(memory)
        public = read_public(backend.exchange)
        check_public(public, raw[:32])
        with pytest.raises(ValueError, match="capacity"):
            altered = bytearray(public)
            altered[256:260] = (4).to_bytes(4, "big")
            check_public(bytes(altered), raw[:32])
        status(backend, 0x6986, ins=0xf4, data=token)
        status(backend, 0x6986, ins=0xf3)
        print(json.dumps({"emulator_seconds": seconds, "capacity": CAPACITY, "leaves": LEAVES,
                          "metrics": memory, "public_key": public.hex()}), flush=True)


def test_isolated_install_and_no_wallet_storage():
    with APP.open("rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        assert not any(any(word in s.name for word in ("WALLET_NVM", "wallet_nvm_write", "wallet_app_key"))
                       for s in symbols.iter_symbols())
        params = symbols.get_symbol_by_name("install_parameters")[0]
        section = elf.get_section(params["st_shndx"])
        offset = params["st_value"] - section["sh_addr"]
        raw = section.data()[offset:offset+params["st_size"]]
        tags = {}
        while raw:
            tag, length = raw[:2]
            assert length < 128 and tag not in tags
            tags[tag], raw = raw[2:2+length], raw[2+length:]
        assert tags[1] == b"SHRINCS Keygen"
        label = b"quip.network/SHRINCS/KEYGEN-BENCH/v1"
        assert tags[4] == bytes([8, 0x80 | (len(label)+1), 0]) + label + b"\0"
    script, = APP.parent.glob("*.apdu")
    name = b"SHRINCS Keygen"
    assert bytes.fromhex(script.read_text().splitlines()[0]) == bytes([
        0xe0, 0, 0, 0, len(name)+2, 0x0c, len(name)]) + name
