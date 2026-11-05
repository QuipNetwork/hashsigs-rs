"""Fresh Speculos processes with the diagnostic app's saved NVM, not RAM mocks."""
from contextlib import contextmanager
from pathlib import Path
import shutil
import sys

from elftools.elf.elffile import ELFFile
from ledgered.devices import Devices
import pytest
from ragger.backend.speculos import SpeculosBackend
from ragger.error import ExceptionRAPDU

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from check import fixtures, exchange, run_case, compare_restart, check_state  # noqa: E402

APP = ROOT / "target/apex_p/release/hashsigs-ledger-nvm-diag"


@pytest.fixture
def persistent(tmp_path, monkeypatch):
    app = tmp_path / "diag.elf"
    shutil.copyfile(APP, app)
    monkeypatch.chdir(tmp_path)
    with app.open("rb") as source:
        elf = ELFFile(source)
        rodata, nvm = (elf.get_section_by_name(name) for name in (".rodata", ".nvm_data"))
        offset = nvm["sh_addr"] - rodata["sh_addr"]
        initial = bytearray(offset + nvm["sh_size"])
        initial[:rodata["sh_size"]], initial[offset:] = rodata.data(), nvm.data()
        symbols = elf.get_section_by_name(".symtab")
        storage = [s for s in symbols.iter_symbols() if "DIAG_NVM" in s.name]
        assert len(storage) == 1 and storage[0]["st_size"] == 2048
        marker = storage[0]["st_value"] - rodata["sh_addr"] + 512
    saved = tmp_path / "main_nvram.bin"
    saved.write_bytes(initial)
    boot = 0

    @contextmanager
    def start():
        nonlocal boot
        boot += 1
        # PUBLIC emulator seed, irrelevant to the fixture MAC/key material.
        # Explicit distinct RNG streams avoid time-seeded nonce collisions in
        # rapid process restarts. Hardware uses the real device RNG.
        with SpeculosBackend(app, Devices.get_by_name("apex_p"),
                             args=["--seed", "hex:" + "42" * 64,
                                   "--deterministic-rng", str(boot),
                                   "--save-nvram", "--load-nvram"]) as backend:
            yield backend
    return start, saved, marker


@pytest.mark.parametrize("source,target", [(0, 1), (1, 2), (4, 5)])
@pytest.mark.parametrize("cut", range(10), ids=lambda n: f"checkpoint-{n}")
def test_every_checkpoint_recovers_in_new_process(persistent, source, target, cut):
    start, saved, _ = persistent
    with start() as backend:
        report = run_case(backend, fixtures(ROOT / "fixtures.bin"), source, target, cut)
    before = saved.read_bytes()
    with start() as backend:
        after = exchange(backend)
        compare_restart(report["after"], after)
    assert saved.read_bytes() == before, "Read-only recovery changed NVM"


def test_malformed_requests_and_wrong_transition_do_not_write(persistent):
    start, _, _ = persistent
    with start() as backend:
        initial = exchange(backend, 0x10, 1)
        for ins, p1, p2, data, status in [
            (0x11, 1, 0, b"", 0x6986), (0x11, 5, 0, b"", 0x6986),
            (0x11, 2, 10, b"", 0x6a86), (0x10, 2, 0, b"", 0x6a86),
            (0x11, 2, 0, b"bad", 0x6a80), (0x30, 0, 0, b"", 0x6d00),
        ]:
            with pytest.raises(ExceptionRAPDU) as error:
                backend.exchange(cla=0xe1, ins=ins, p1=p1, p2=p2, data=data)
            assert error.value.status == status
            assert exchange(backend) == initial


@pytest.mark.parametrize("offset", [0, 511, 512 + 160, 512 + 500])
def test_saved_record_corruption_locks(persistent, offset):
    start, saved, marker = persistent
    with start() as backend:
        run_case(backend, fixtures(ROOT / "fixtures.bin"), 1, 2, 0)
    damaged = bytearray(saved.read_bytes())
    damaged[marker + offset] ^= 1
    saved.write_bytes(damaged)
    with start() as backend:
        status = exchange(backend)
        check_state(status, {"guards": 3, "state_bytes": (b"\x03" + bytes(109)).hex()})
    assert saved.read_bytes() == damaged


def test_binary_permissions_and_isolation():
    with APP.open("rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        names = [s.name for s in symbols.iter_symbols()]
        assert not any("WALLET_NVM" in n or "wallet_app_key" in n or "derive_bip32" in n for n in names)
        storage = [s for s in symbols.iter_symbols() if "DIAG_NVM" in s.name]
        assert len(storage) == 1 and storage[0]["st_size"] == 2048
        assert storage[0]["st_value"] % 512 == 0
        symbol = symbols.get_symbol_by_name("install_parameters")[0]
        section = elf.get_section(symbol["st_shndx"])
        offset = symbol["st_value"] - section["sh_addr"]
        data = section.data()[offset:offset + symbol["st_size"]]
        tags = {}
        while data:
            tag, length = data[:2]
            assert length < 128 and tag not in tags
            tags[tag], data = data[2:2 + length], data[2 + length:]
        assert tags[1] == b"SHRINCS NVM Diag"
        label = b"\0quip.network/SHRINCS/NVM-DIAG/v1"
        assert tags[4] == bytes([8, 0x80 | len(label)]) + label + b"\0"
        assert elf.get_section_by_name("ledger.app_flags").data().strip(b"\0\n") == b"0x200"
    # Check the install script's delete-by-name command cannot target the wallet.
    apdus = list(APP.parent.glob("*.apdu"))
    assert len(apdus) == 1
    first = bytes.fromhex(apdus[0].read_text().splitlines()[0])
    name = b"SHRINCS NVM Diag"
    assert first == bytes([0xe0, 0, 0, 0, len(name) + 2, 0x0c, len(name)]) + name
    wallet = ROOT.parent / "app/target/apex_p/release/hashsigs-ledger"
    with wallet.open("rb") as source:
        elf = ELFFile(source)
        assert b"NVM-DIAG" not in elf.get_section_by_name(".rodata").data()
        assert not any("diagnostics" in s.name or "DIAG_NVM" in s.name
                       for s in elf.get_section_by_name(".symtab").iter_symbols())
