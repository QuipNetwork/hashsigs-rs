"""Check the permissions and erase-unit placement in the exact built ELF."""
from pathlib import Path
from elftools.elf.elffile import ELFFile


def test_install_permissions_and_storage_alignment():
    app = Path(__file__).parents[1] / "app/target/apex_p/release/hashsigs-ledger"
    with app.open("rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        symbol = symbols.get_symbol_by_name("install_parameters")[0]
        section = elf.get_section(symbol["st_shndx"])
        offset = symbol["st_value"] - section["sh_addr"]
        data = section.data()[offset:offset + symbol["st_size"]]
        tags = {}
        while data:
            tag, length = data[:2]
            assert length < 128  # Current manifest uses only short TLVs.
            assert tag not in tags
            tags[tag], data = data[2:2+length], data[2+length:]
        # Trailing 0 is the SDK's regular-path placeholder. Mask 08 disables
        # every EC curve, and the sole symmetric prefix is 00 || this label.
        assert tags[4] == b"\x08\x98\0quip.network/SHRINCS/v1\0"
        assert elf.get_section_by_name("ledger.app_flags").data().strip(b"\0\n") == b"0x200"
        storage = [s for s in symbols.iter_symbols() if "WALLET_NVM" in s.name]
        assert len(storage) == 1
        assert storage[0]["st_value"] % 512 == 0
        assert storage[0]["st_size"] == 1024
