"""The control app has discovery and SDK UI only, under its own install name."""
from pathlib import Path

from elftools.elf.elffile import ELFFile
from ledgered.devices import Devices
import pytest
from ragger.backend.speculos import SpeculosBackend
from ragger.error import ExceptionRAPDU

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "target/apex_p/release/hashsigs-ledger-launch-check"


def test_discovery_and_no_wallet_api():
    with SpeculosBackend(APP, Devices.get_by_name("apex_p")) as backend:
        assert backend.exchange(cla=0xe3, ins=3).data == bytes([0, 1, 0])
        assert backend.exchange(cla=0xe3, ins=4).data == b"hashsigs-ledger-launch-check"
        for instruction in (0x30, 0x32, 0x40, 0xf1, 0xf4):
            with pytest.raises(ExceptionRAPDU) as error:
                backend.exchange(cla=0xe3, ins=instruction)
            assert error.value.status == 0x6d00
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(cla=0xe2, ins=3)
        assert error.value.status == 0x6e00


def test_install_and_code_isolation():
    with APP.open("rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        assert not any(any(word in sym.name for word in
                           ("WALLET_NVM", "wallet_app_key", "hardware_probe", "hashsigs_rs"))
                       for sym in symbols.iter_symbols())
        params = symbols.get_symbol_by_name("install_parameters")[0]
        section = elf.get_section(params["st_shndx"])
        offset = params["st_value"] - section["sh_addr"]
        raw = section.data()[offset:offset + params["st_size"]]
        tags = {}
        while raw:
            tag, length = raw[:2]
            assert length < 128 and tag not in tags
            tags[tag], raw = raw[2:2 + length], raw[2 + length:]
        label = b"quip.network/SHRINCS/LAUNCH-CHECK/v1"
        assert tags[1] == b"SHRINCS Launch"
        assert tags[4] == bytes([8, 0x80 | (len(label) + 1), 0]) + label + b"\0"
        assert elf.get_section_by_name("ledger.app_flags").data().strip(b"\0\n") == b"0x200"
    script, = APP.parent.glob("*.apdu")
    name = b"SHRINCS Launch"
    assert bytes.fromhex(script.read_text().splitlines()[0]) == bytes([
        0xe0, 0, 0, 0, len(name) + 2, 0x0c, len(name)]) + name
