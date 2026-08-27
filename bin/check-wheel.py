#!/usr/bin/env python3
# Copyright (C) 2026 quip.network
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check a built wheel before it is installed or uploaded.

Usage: check-wheel.py <dist-directory>

Two failures this catches, both of which have shipped:

- A wheel missing profile extensions. maturin builds one cdylib per Cargo
  package, so the other six are staged in by py/hashsigs_build.py. A staging
  bug yields a wheel that imports but cannot load most profiles.
- A wheel PyPI will not accept. maturin's PEP 517 hook defaults to
  `--compatibility off`, which tags the wheel `linux_x86_64`. PyPI rejects a
  bare linux tag with a 400, because the tag makes no promise about the glibc
  the extensions need. This is only visible in the filename, so a check that
  reads the archive alone will pass a wheel that cannot be published.

Both the release job and `make check-python-dists` call this, so the publish
path and the validation path cannot drift apart on what "a good wheel" means.
"""

from __future__ import annotations

import glob
import os
import sys
import zipfile

EXPECTED_EXTENSIONS = 7


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(f"usage: {os.path.basename(argv[0])} <dist-directory>\n")
        return 2
    dist = argv[1]

    wheels = sorted(glob.glob(os.path.join(dist, "*.whl")))
    if len(wheels) != 1:
        sys.stderr.write(f"expected exactly one wheel in {dist}, found {wheels}\n")
        return 1
    wheel = wheels[0]
    name = os.path.basename(wheel)

    extensions = [n for n in zipfile.ZipFile(wheel).namelist() if n.endswith(".so")]
    if len(extensions) != EXPECTED_EXTENSIONS:
        sys.stderr.write(
            f"{name} carries {len(extensions)} extensions, "
            f"expected {EXPECTED_EXTENSIONS}: {extensions}\n"
        )
        return 1

    # Wheel filename: name-version(-build)?-python-abi-platform.whl
    platform_tag = name[: -len(".whl")].split("-")[-1]
    if platform_tag.startswith("linux_"):
        sys.stderr.write(
            f"{name} carries the bare platform tag {platform_tag!r}, which PyPI "
            f"rejects with a 400.\nThe wheel must be tagged manylinux or "
            f"musllinux. See _with_pypi_compatibility in py/hashsigs_build.py.\n"
        )
        return 1

    print(f"{name}: {len(extensions)} extensions, platform tag {platform_tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
