"""Build-time adapter for pinned Speculos 0.27.0; never modifies the app ELF.

Its C launcher already saves NVM writes; Python only lacks Rust region metadata.
Include the SDK's relocated .rodata as well as .nvm_data because Rust startup
also writes PIC fixups. Keep this test-tool patch explicit and version checked.
"""
from importlib.metadata import version
from pathlib import Path
import speculos.main

assert version("speculos") == "0.27.0"
path = Path(speculos.main.__file__)
source = path.read_text()
old = '''            # This is a Rust app
            if args.load_nvram or args.save_nvram:
                logger.error("NVRAM data save and load functionality is not yet implemented for Rust apps.")
                sys.exit(1)'''
new = '''            # SHRINCS test adapter: Rust SDK PIC fixups and application NVM.
            if args.load_nvram or args.save_nvram:
                rodata = elf.get_section_by_name(".rodata")
                nvm = elf.get_section_by_name(".nvm_data")
                ei.app_nvram_addr = rodata["sh_addr"]
                ei.app_nvram_size = nvm["sh_addr"] + nvm["sh_size"] - ei.app_nvram_addr'''
assert source.count(old) == 1, "Pinned Speculos NVRAM branch changed"
path.write_text(source.replace(old, new))
