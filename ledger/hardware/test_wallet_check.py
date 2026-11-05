"""Host checks for the physical lifecycle reporter; no USB access."""
from copy import deepcopy
import subprocess

import pytest

from wallet_check import check_public, compare


def test_public_commitment_and_canonical_encoding():
    public = bytes.fromhex(subprocess.check_output([
        "/repo/ledger/host/target/release/hashsigs-ledger-vectors",
        "--keygen-public", "01" * 32,
    ], text=True).strip())
    commitment = public[320:352]
    check_public(public, commitment)
    # Offset, capacity, padding, claimed commitment, and both stateless fields.
    for offset in [31, 259, 260, 320, 384, 448]:
        bad = bytearray(public)
        bad[offset] ^= 1
        with pytest.raises(ValueError):
            check_public(bytes(bad), commitment)
    with pytest.raises(ValueError):
        check_public(public, bytes(32))


def test_reload_comparison_requires_identity_counters_and_new_boot():
    baseline = {"name": "hashsigs-ledger", "version": [0, 2, 0],
                "state": {"commitment": "aa", "generation": "bb", "next_leaf": 1},
                "public_key": "cc", "info": {"boot_nonce": "11", "capabilities": 3}}
    current = deepcopy(baseline)
    compare(baseline, current, False)
    with pytest.raises(ValueError, match="Boot nonce"):
        compare(baseline, current, True)
    current["info"]["boot_nonce"] = "22"
    compare(baseline, current, True)
    for field, key, value in [("state", "commitment", "dd"), ("state", "generation", "dd"),
                              ("state", "next_leaf", 2), ("info", "capabilities", 7)]:
        bad = deepcopy(current)
        bad[field][key] = value
        with pytest.raises(ValueError):
            compare(baseline, bad, True)
    current["public_key"] = "dd"
    with pytest.raises(ValueError):
        compare(baseline, current, True)
