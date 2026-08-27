# Copyright (C) 2026 quip.network
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-profile packaging tests: every profile module loads its own extension.

This is the suite the one-extension-per-profile layout needs. All six modules
expose identical names over identical byte layouts, so nothing about a module's
shape says which profile it is. A build loop that copied the wrong shared
library into a profile's slot would produce a package that imports cleanly,
type checks, and signs and verifies correctly against itself.

Cost: the 128s profiles are identity checked only. Their keygen costs tens of
seconds and signing about as much again, which does not belong in a suite that
gates every publish. Their crypto is covered natively by ``cargo test`` under
each ``profile-*`` feature, and the Rust ``wasm::tests`` module drives the
shared generic core at more than one profile.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import pathlib

import pytest

import hashsigs
from hashsigs.profiles import DEFAULT_MODULE, PROFILES

# `__path__` rather than `__file__`: a package always has the former, and it
# is not Optional the way `__file__` is.
MANIFEST = json.loads(
    (pathlib.Path(hashsigs.__path__[0]) / "profiles" / "profiles.json").read_text()
)

# Signing is only exercised on profiles cheap enough to sign in a test run.
FAST_MODULES = ("p256s", "p256s_sha2")


def hash32(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def load(module: str):
    return importlib.import_module(f"hashsigs.profiles.{module}")


def test_manifest_and_package_agree_on_the_profile_set():
    assert tuple(p["module"] for p in MANIFEST["profiles"]) == PROFILES
    default = [p for p in MANIFEST["profiles"] if p["module"] == DEFAULT_MODULE]
    assert len(default) == 1, f"{DEFAULT_MODULE} is not one of the built profiles"
    assert default[0]["key"] == MANIFEST["default"]


@pytest.mark.parametrize("entry", MANIFEST["profiles"], ids=lambda e: e["key"])
def test_module_reports_its_own_profile(entry):
    """The extension's own name must match the profile its module claims.

    The name is compiled in from ``<P as Profile>::PROFILE_NAME``, so this is
    the assertion that catches a wrong shared library in a profile's slot, or a
    stale name table in bin/packages.sh. Nothing else would.
    """
    module = load(entry["module"])
    assert module.PROFILE == entry["key"]
    assert module.PROFILE_NAME == entry["name"]
    assert module.profile_name == entry["name"], (
        f"module {entry['module']} loaded an extension reporting "
        f"{module.profile_name!r}, expected {entry['name']!r}"
    )


def test_no_two_profiles_report_the_same_name():
    """Six slots holding six copies of one extension would otherwise slip through.

    Every per-module check above would still pass if the name table were
    equally wrong, so distinctness is a second, independent way to catch it.
    """
    names = [load(m).profile_name for m in PROFILES]
    assert len(set(names)) == len(names), f"duplicate profile names: {names}"


def test_every_profile_reports_the_same_crate_version():
    """A stale extension left behind by a partial rebuild shows up here."""
    versions = {load(m).version for m in PROFILES}
    assert versions == {hashsigs.__version__}


def test_a_signature_does_not_verify_under_another_profile():
    """The 256s twins share every parameter and differ only in the hash suite.

    That makes them the pair that catches a module serving its twin's
    extension: no size, width, or layout check would see the difference.
    """
    keccak = load("p256s")
    sha2 = load("p256s_sha2")

    seed = bytes(32)
    message = hash32("cross-profile-rejection")
    keys = keccak.shrincs.keygen(seed, 4)
    signature = keccak.shrincs.sign(message, keys)

    assert keccak.shrincs.verify(signature, message, keys.public_key_commitment)
    assert not sha2.shrincs.verify(signature, message, keys.public_key_commitment), (
        "the sha2 twin accepted a keccak signature: the two modules are "
        "serving the same extension"
    )


def test_importing_a_key_under_the_wrong_profile_is_rejected():
    """Persisted key bytes carry no profile tag, so the roots have to catch it.

    Feeding a 256s-keccak secret to its sha2 twin must fail the root check
    rather than yield a usable-looking key that signs unverifiably.
    """
    keccak = load("p256s")
    sha2 = load("p256s_sha2")

    keys = keccak.shrincs.keygen(bytes(32), 4)
    secret = hashsigs.shrincs_keys_to_secret_bytes(keys)

    assert keccak.shrincs.import_signing_key(secret).public_key_commitment == (
        keys.public_key_commitment
    )
    with pytest.raises(hashsigs.HashSigsError) as excinfo:
        sha2.shrincs.import_signing_key(secret)
    assert excinfo.value.code == "ERR_IMPORT_INVALID"


@pytest.mark.parametrize("module", FAST_MODULES)
def test_round_trip_through_each_fast_profile(module):
    profile = load(module)
    seed = bytes([0x33]) * 32
    message = hash32(f"round-trip-{module}")

    keys = profile.shrincs.keygen(seed, 4)
    signature = profile.shrincs.sign(message, keys)
    assert profile.shrincs.verify(signature, message, keys.public_key_commitment)

    tampered = bytearray(signature)
    tampered[0] ^= 1
    assert not profile.shrincs.verify(
        bytes(tampered), message, keys.public_key_commitment
    )
    assert not profile.shrincs.verify(signature, hash32("other"), keys.public_key_commitment)


def test_the_package_root_is_the_default_profile():
    default = load(DEFAULT_MODULE)
    assert hashsigs.profile_name == default.profile_name
    assert hashsigs.PROFILE == default.PROFILE
