"""Real process restarts with saved public-seed emulator NVM (see adapter)."""
from contextlib import contextmanager
from pathlib import Path
import shutil

import pytest
from elftools.elf.elffile import ELFFile
from ragger.backend.speculos import SpeculosBackend
from ragger.navigator import TouchNavigator, NavInsID
from raw_apdu import connection, send

from app_client import AppClient, CLA
from test_shrincs import assert_status
from test_wallet import PROFILE, PUBLIC_SEED, approve_creation, expected_public

pytestmark = pytest.mark.emulator_only


@pytest.fixture
def persistent(tmp_path, device, monkeypatch):
    app = tmp_path / "wallet.elf"
    shutil.copyfile(Path(__file__).parents[1] / "app/target/apex_p/release/hashsigs-ledger", app)
    # The pinned launcher names its file main_nvram.bin in its working directory.
    monkeypatch.chdir(tmp_path)
    with app.open("rb") as source:
        elf = ELFFile(source)
        rodata = elf.get_section_by_name(".rodata")
        nvm = elf.get_section_by_name(".nvm_data")
        offset = nvm["sh_addr"] - rodata["sh_addr"]
        initial = bytearray(offset + nvm["sh_size"])
        initial[:rodata["sh_size"]] = rodata.data()
        initial[offset:] = nvm.data()
        symbols = elf.get_section_by_name(".symtab")
        storage = [s for s in symbols.iter_symbols() if "WALLET_NVM" in s.name]
        assert len(storage) == 1 and storage[0]["st_size"] == 1024
        marker_offset = storage[0]["st_value"] - rodata["sh_addr"]

    @contextmanager
    def start(seed=PUBLIC_SEED):
        # The C loader zeros its declared NVM region before loading. Rust has
        # initialized data/PIC tables there, so seed the first image from ELF.
        if not (tmp_path / "main_nvram.bin").exists():
            (tmp_path / "main_nvram.bin").write_bytes(initial)
        args = ["--seed", "hex:" + seed.hex(), "--save-nvram", "--load-nvram"]
        with SpeculosBackend(app, device, args=args) as backend:
            yield AppClient(backend), backend, TouchNavigator(backend, device)
    return start, tmp_path, marker_offset


def test_restart_wrong_seed_and_torn_marker(persistent):
    start, directory, marker = persistent
    with start() as (client, backend, navigator):
        assert client.state()["state"] == 0
        nonce = client.info()["boot_nonce"]
        commitment, _ = approve_creation(client, backend, navigator)
        state = client.state()
        public = client.public_key(commitment)
        assert public == expected_public(state["generation"])
    saved = list(directory.glob("*_nvram.bin"))
    assert len(saved) == 1, list(directory.iterdir())
    snapshot = saved[0].read_bytes()
    assert b"SHRINCS2" in snapshot
    with start() as (client, _, _):
        assert client.info()["boot_nonce"] != nonce
        assert client.state() == state
        assert client.public_key(commitment) == public
        assert_status(0x6986, lambda: client.backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (4).to_bytes(4, "big")))
    with start(bytes([42]) * 64) as (client, _, _):
        assert client.state()["state"] == 3
        assert client.state()["commitment"] == bytes(32)
        assert_status(0x6984, lambda: client.public_key(commitment))
        assert_status(0x6984, lambda: client.backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (4).to_bytes(4, "big")))
    # A wrong seed must not alter/erase the stored identity.
    assert saved[0].read_bytes() == snapshot
    with start() as (client, _, _):
        assert client.state() == state
    # Payload corruption and a forged tag are rejected by the real device MAC
    # implementation, not just by the host fault model.
    # Read-only literals also contain the magic and marker arrays. Use the
    # actual storage symbol's ELF address to target the persisted blocks.
    assert snapshot[marker:marker + 512] == bytes([0xa5]) * 512
    record = marker + 512
    assert snapshot[record:record + 8] == b"SHRINCS2"
    for offset in [record + 160, record + 500]:
        damaged = bytearray(snapshot)
        damaged[offset] ^= 1
        saved[0].write_bytes(damaged)
        with start() as (client, _, _):
            assert client.state()["state"] == 3
            assert_status(0x6984, lambda: client.public_key(commitment))
    damaged = bytearray(snapshot)
    damaged[marker + 100] = 0
    saved[0].write_bytes(damaged)
    with start() as (client, _, _):
        assert client.state()["state"] == 3
        assert_status(0x6984, lambda: client.public_key(commitment))
    # Fresh installation (no saved image) gets a new generation and commitment,
    # even with the identical public emulator seed.
    saved[0].unlink()
    with start() as (client, backend, navigator):
        assert client.state()["state"] == 0
        new_commitment, _ = approve_creation(client, backend, navigator)
        assert new_commitment != commitment
        assert client.state()["generation"] != state["generation"]


def test_lost_create_response_recovers_without_replacement(persistent):
    start, _, _ = persistent
    with start() as (_, backend, navigator):
        with connection(backend) as stream:
            send(stream, bytes.fromhex("e030000024") + PROFILE + (4).to_bytes(4, "big"))
            backend.wait_for_text_on_screen("Create SHRINCS key?")
            navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM], screen_change_before_first_instruction=False)
            backend.wait_for_text_on_screen("Key created", timeout=120)
            # Stop the process before dismissing the final screen or receiving
            # CREATE_KEY's success response. The committed key must survive.
    with start() as (client, _, _):
        state = client.state()
        assert state["state"] == 1 and state["next_leaf"] == 1
        assert client.public_key(state["commitment"]) == expected_public(state["generation"])
        assert_status(0x6986, lambda: client.backend.exchange(cla=CLA, ins=0x30, data=PROFILE + (4).to_bytes(4, "big")))
