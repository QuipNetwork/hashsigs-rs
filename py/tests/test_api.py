# Copyright (C) 2026 quip.network
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The signing surface, against the installed wheel.

Everything here runs on the default profile. The point is the Python layer:
the key objects, the decompose/recompose round trip, the leaf accounting, and
the error codes. The cryptography itself is pinned by the Rust suite and the
golden vectors; these tests check that the bindings hand it the right bytes and
hand back the right objects.
"""

from __future__ import annotations

import hashlib

import pytest

import hashsigs
from hashsigs import HashSigsError, shrincs, shrincs_keys_to_secret_bytes, sphincs_plus_c

SEED = bytes([0xAB]) * 32
MESSAGE = hashlib.sha256(b"hashsigs-python-api").digest()


def test_shrincs_keygen_shapes():
    keys = shrincs.keygen(SEED, 4)

    assert len(keys.public_key_commitment) == 32
    assert len(keys.public_key) == 164
    assert len(shrincs_keys_to_secret_bytes(keys)) == 264
    for leaf in (
        keys.stateful.secret.sk_seed,
        keys.stateful.secret.prf_seed,
        keys.stateful.public_key.pk_seed,
        keys.stateful.public_key.root,
        keys.stateless.secret.sk_seed,
        keys.stateless.secret.prf_seed,
        keys.stateless.public_key.pk_seed,
        keys.stateless.public_key.root,
    ):
        assert len(leaf) == 32

    assert keys.stateful.public_key.max_signatures == 4
    assert keys.stateful.next_leaf_index == 1
    assert keys.stateful.remaining == 4


def test_keygen_is_deterministic_for_the_same_seed():
    assert shrincs_keys_to_secret_bytes(shrincs.keygen(SEED, 4)) == (
        shrincs_keys_to_secret_bytes(shrincs.keygen(SEED, 4))
    )


def test_sign_verify_round_trip_and_rejections():
    keys = shrincs.keygen(SEED, 4)
    signature = shrincs.sign(MESSAGE, keys)

    assert shrincs.verify(signature, MESSAGE, keys.public_key_commitment)
    assert not shrincs.verify(signature, bytes(32), keys.public_key_commitment)

    tampered = bytearray(signature)
    tampered[0] ^= 1
    assert not shrincs.verify(bytes(tampered), MESSAGE, keys.public_key_commitment)

    # The envelope carries the full public key, so verify must check that key
    # hashes to the pinned commitment rather than trusting whatever it carries.
    wrong = bytearray(keys.public_key_commitment)
    wrong[0] ^= 1
    assert not shrincs.verify(signature, MESSAGE, bytes(wrong))


def test_each_sign_consumes_one_leaf_and_the_signatures_differ():
    keys = shrincs.keygen(SEED, 4)

    first = shrincs.sign(MESSAGE, keys)
    assert keys.stateful.next_leaf_index == 2
    assert keys.stateful.remaining == 3

    second = shrincs.sign(MESSAGE, keys)
    assert keys.stateful.next_leaf_index == 3
    assert first != second, "two leaves must produce distinct signatures"
    assert shrincs.verify(first, MESSAGE, keys.public_key_commitment)
    assert shrincs.verify(second, MESSAGE, keys.public_key_commitment)


def test_stateful_signing_raises_once_the_budget_is_spent():
    keys = shrincs.keygen(SEED, 1)
    shrincs.sign(MESSAGE, keys)
    assert keys.stateful.remaining == 0

    with pytest.raises(HashSigsError) as excinfo:
        shrincs.sign(MESSAGE, keys)
    assert excinfo.value.code == "ERR_STATEFUL_LEAVES_EXHAUSTED"

    # Stateless still works on an exhausted key: that is the recovery path.
    signature = shrincs.sign_stateless(MESSAGE, keys)
    assert shrincs.verify_stateless(signature, MESSAGE, keys.stateless.public_key)


def test_persistence_round_trip_preserves_the_leaf_counter():
    """The reason to persist: an older snapshot would reuse a spent leaf."""
    keys = shrincs.keygen(SEED, 4)
    shrincs.sign(MESSAGE, keys)

    restored = shrincs.import_signing_key(shrincs_keys_to_secret_bytes(keys))
    assert restored.stateful.next_leaf_index == 2
    assert restored.stateful.remaining == 3
    assert restored.public_key_commitment == keys.public_key_commitment

    # Signing on continues from the restored counter rather than replaying.
    signature = shrincs.sign(MESSAGE, restored)
    assert restored.stateful.next_leaf_index == 3
    assert shrincs.verify(signature, MESSAGE, restored.public_key_commitment)


def test_import_rejects_a_tampered_secret_and_a_short_one():
    keys = shrincs.keygen(SEED, 4)
    secret = bytearray(shrincs_keys_to_secret_bytes(keys))
    secret[0] ^= 1  # corrupts statefulSkSeed, invalidating statefulRoot

    with pytest.raises(HashSigsError) as excinfo:
        shrincs.import_signing_key(bytes(secret))
    assert excinfo.value.code == "ERR_IMPORT_INVALID"

    with pytest.raises(HashSigsError) as excinfo:
        shrincs.import_signing_key(bytes(secret)[:263])
    assert excinfo.value.code == "ERR_BAD_LENGTH"


def test_stateless_signing_consumes_no_leaf():
    keys = shrincs.keygen(SEED, 4)
    before = shrincs_keys_to_secret_bytes(keys)

    signature = shrincs.sign_stateless(MESSAGE, keys)

    assert shrincs_keys_to_secret_bytes(keys) == before
    assert shrincs.verify_stateless(signature, MESSAGE, keys.stateless.public_key)
    assert not shrincs.verify_stateless(signature, bytes(32), keys.stateless.public_key)
    # A stateless SHRINCS signature IS a SPHINCS+C signature.
    assert sphincs_plus_c.verify(signature, MESSAGE, keys.stateless.public_key)


def test_reset_changes_the_commitment_and_keeps_the_stateless_half():
    keys = shrincs.keygen(SEED, 4)
    original = keys.public_key_commitment
    stateless_before = keys.stateless

    shrincs.reset(keys, bytes([0x99]) * 32)

    assert keys.public_key_commitment != original
    assert keys.stateless == stateless_before, "reset must not touch the stateless half"
    assert keys.stateful.next_leaf_index == 1
    assert keys.stateful.public_key.max_signatures == 4
    assert shrincs.compute_public_key_commitment(keys) == keys.public_key_commitment

    signature = shrincs.sign(MESSAGE, keys)
    assert shrincs.verify(signature, MESSAGE, keys.public_key_commitment)


def test_recover_public_key_commitment():
    keys = shrincs.keygen(SEED, 4)
    signature = shrincs.sign(MESSAGE, keys)

    assert shrincs.recover_public_key_commitment(signature) == keys.public_key_commitment

    with pytest.raises(HashSigsError) as excinfo:
        shrincs.recover_public_key_commitment(bytes(4))
    assert excinfo.value.code == "ERR_ENVELOPE_MALFORMED"


def test_keygen_rejects_an_out_of_range_budget():
    for bad in (0, hashsigs.max_stateful_signatures + 1):
        with pytest.raises(HashSigsError) as excinfo:
            shrincs.keygen(SEED, bad)
        assert excinfo.value.code == "ERR_INVALID_INPUT"

    # The boundary itself is accepted.
    assert shrincs.keygen(SEED, hashsigs.max_stateful_signatures) is not None


def test_sphincs_plus_c_round_trip():
    keys = sphincs_plus_c.keygen(SEED)
    signature = sphincs_plus_c.sign(MESSAGE, keys)

    assert sphincs_plus_c.verify(signature, MESSAGE, keys.public_key)
    assert not sphincs_plus_c.verify(signature, bytes(32), keys.public_key)

    tampered = bytearray(signature)
    tampered[0] ^= 1
    assert not sphincs_plus_c.verify(bytes(tampered), MESSAGE, keys.public_key)


def test_a_wrong_length_message_is_rejected_when_signing():
    keys = shrincs.keygen(SEED, 4)
    with pytest.raises(HashSigsError) as excinfo:
        shrincs.sign(b"not thirty two bytes", keys)
    assert excinfo.value.code == "ERR_BAD_LENGTH"
    # The message must never be echoed back: it reaches logs.
    assert "not thirty two bytes" not in str(excinfo.value)
