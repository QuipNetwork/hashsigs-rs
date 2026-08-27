# Copyright (C) 2026 quip.network
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The profile-independent half of the ``hashsigs`` package.

Every profile extension exports the same functions over the same flat byte
layouts, so the key objects, the decompose/recompose wiring, and the namespace
classes are written once here and bound to an extension by :func:`bind`. The
per-profile modules under ``hashsigs.profiles`` hold nothing but that binding.

This mirrors ``ts/src/api.ts`` on the npm side deliberately: both languages
build their key objects from the same flat layouts produced by the same Rust
code, so the two cannot drift in how they read a secret key.

Keys are decomposed objects, never a single opaque blob. Every leaf is a
32-byte seed or root, named for what it is. The flat layouts are an internal
serialization detail, and the helpers in this module are the only code that
knows their offsets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ._errors import HashSigsError

__all__ = [
    "HashSigsError",
    "SphincsPlusCKeys",
    "SphincsPlusCPublicKey",
    "SphincsPlusCSecret",
    "ShrincsKeys",
    "ShrincsStateful",
    "StatefulPublicKey",
    "bind",
    "shrincs_keys_to_secret_bytes",
]

# `Keys::to_bytes` on the Rust side: stateful(136) || stateless(128).
_STATEFUL_SECRET_LEN = 136
_SEED_LEN = 32

# The extensions reject a max_signatures outside 1..=4096, and each profile
# module re-exports its extension's own MAX_STATEFUL_SIGNATURES. This is only
# the default a caller gets by omitting the argument.
DEFAULT_MAX_STATEFUL_SIGNATURES = 1024


@dataclass(frozen=True)
class SphincsPlusCSecret:
    """The 32-byte seeds every WOTS-C and FORS-C secret in the tree derives from."""

    sk_seed: bytes
    prf_seed: bytes


@dataclass(frozen=True)
class SphincsPlusCPublicKey:
    """The 32-byte public roots a stateless verify pins."""

    pk_seed: bytes
    root: bytes


@dataclass(frozen=True)
class SphincsPlusCKeys:
    """A SPHINCS+C keypair. Also the stateless half of a :class:`ShrincsKeys`."""

    secret: SphincsPlusCSecret
    public_key: SphincsPlusCPublicKey


@dataclass(frozen=True)
class StatefulPublicKey:
    """The stateful half's public roots, plus the leaf budget fixed at keygen."""

    pk_seed: bytes
    root: bytes
    max_signatures: int


@dataclass
class ShrincsStateful:
    """The stateful (UXMSS) half of a hybrid key.

    Not frozen: :meth:`Shrincs.sign` advances ``next_leaf_index``. Every other
    key object in this module is immutable.
    """

    secret: SphincsPlusCSecret
    public_key: StatefulPublicKey
    #: The next unused leaf, 1-based. Advances by one on every stateful sign.
    next_leaf_index: int

    @property
    def remaining(self) -> int:
        """Leaves left to spend before stateful signing raises."""
        return self.public_key.max_signatures - (self.next_leaf_index - 1)


@dataclass
class ShrincsKeys:
    """A SHRINCS hybrid keypair.

    ``stateful`` advances as you sign and ``stateless`` never changes. Persist
    the key after every stateful sign (see
    :func:`shrincs_keys_to_secret_bytes`); signing twice from the same saved
    state reuses a one-time leaf.
    """

    stateless: SphincsPlusCKeys
    stateful: ShrincsStateful
    #: The 32-byte value a stateful verify checks against. Changes on reset.
    public_key_commitment: bytes
    #: The full 164-byte public bundle a verifier is resupplied with.
    public_key: bytes = field(repr=False, default=b"")


class _Extension(Protocol):
    """The surface every profile extension provides.

    One macro in ``py/common/src/lib.rs`` emits all six, so they cannot differ.
    Declaring the shape here lets a type checker verify this module against the
    compiled modules, which carry no type information of their own.
    """

    MAX_STATEFUL_SIGNATURES: int

    def profile_name(self) -> str: ...
    def version(self) -> str: ...
    def sphincs_plus_c_keygen(self, seed: bytes) -> bytes: ...
    def sphincs_plus_c_sign(self, message: bytes, secret_key: bytes) -> bytes: ...
    def sphincs_plus_c_verify(
        self, signature: bytes, message: bytes, public_key: bytes
    ) -> bool: ...
    def shrincs_keygen(
        self, seed: bytes, max_signatures: int
    ) -> tuple[bytes, bytes, bytes]: ...
    def shrincs_import_signing_key(
        self, secret_key: bytes
    ) -> tuple[bytes, bytes, bytes]: ...
    def shrincs_sign(
        self, message: bytes, secret_key: bytes
    ) -> tuple[bytes, bytes]: ...
    def shrincs_sign_stateless(self, message: bytes, secret_key: bytes) -> bytes: ...
    def shrincs_verify(
        self, signature: bytes, message: bytes, public_key_commitment: bytes
    ) -> bool: ...
    def shrincs_verify_stateless(
        self, signature: bytes, message: bytes, stateless_public_key: bytes
    ) -> bool: ...
    def shrincs_reset(self, secret_key: bytes, new_seed: bytes) -> bytes: ...
    def shrincs_compute_public_key_commitment(self, secret_key: bytes) -> bytes: ...
    def shrincs_recover_public_key_commitment(self, signature: bytes) -> bytes: ...


def _sphincs_keys_from_secret_bytes(secret: bytes) -> SphincsPlusCKeys:
    """Split the 128-byte flat secret: skSeed || prfSeed || pkSeed || root."""
    return SphincsPlusCKeys(
        secret=SphincsPlusCSecret(sk_seed=secret[0:32], prf_seed=secret[32:64]),
        public_key=SphincsPlusCPublicKey(pk_seed=secret[64:96], root=secret[96:128]),
    )


def _sphincs_keys_to_secret_bytes(keys: SphincsPlusCKeys) -> bytes:
    """Rebuild the 128-byte flat secret. The public key is its trailing half."""
    return b"".join(
        (
            keys.secret.sk_seed,
            keys.secret.prf_seed,
            keys.public_key.pk_seed,
            keys.public_key.root,
        )
    )


def _public_key_to_bytes(public_key: SphincsPlusCPublicKey) -> bytes:
    """Flatten to the 64-byte ``pkSeed || root`` the verify calls take."""
    return public_key.pk_seed + public_key.root


def _shrincs_keys_from_bytes(
    secret: bytes, public_key: bytes, commitment: bytes
) -> ShrincsKeys:
    """Split the 264-byte flat secret into a :class:`ShrincsKeys`.

    Layout: statefulSkSeed(32) || statefulPrfSeed(32) || statefulPkSeed(32) ||
    statefulRoot(32) || maxSignatures(u32 BE) || nextLeafIndex(u32 BE) ||
    stateless(128).
    """
    max_signatures = int.from_bytes(secret[128:132], "big")
    next_leaf_index = int.from_bytes(secret[132:136], "big")
    return ShrincsKeys(
        stateless=_sphincs_keys_from_secret_bytes(secret[_STATEFUL_SECRET_LEN:]),
        stateful=ShrincsStateful(
            secret=SphincsPlusCSecret(sk_seed=secret[0:32], prf_seed=secret[32:64]),
            public_key=StatefulPublicKey(
                pk_seed=secret[64:96],
                root=secret[96:128],
                max_signatures=max_signatures,
            ),
            next_leaf_index=next_leaf_index,
        ),
        public_key_commitment=commitment,
        public_key=public_key,
    )


def shrincs_keys_to_secret_bytes(keys: ShrincsKeys) -> bytes:
    """Serialize to the 264-byte secret, for persistence between runs.

    Feed it back through ``shrincs_import_signing_key`` on the SAME profile.
    The bytes carry no profile tag, so importing under a different profile
    fails the root check rather than silently producing a wrong key.
    """
    return b"".join(
        (
            keys.stateful.secret.sk_seed,
            keys.stateful.secret.prf_seed,
            keys.stateful.public_key.pk_seed,
            keys.stateful.public_key.root,
            keys.stateful.public_key.max_signatures.to_bytes(4, "big"),
            keys.stateful.next_leaf_index.to_bytes(4, "big"),
            _sphincs_keys_to_secret_bytes(keys.stateless),
        )
    )


class SphincsPlusC:
    """The stateless scheme on its own, bound to one profile."""

    def __init__(self, ext: _Extension) -> None:
        self._ext = ext

    def keygen(self, seed: bytes) -> SphincsPlusCKeys:
        """Derive a keypair from a REQUIRED 32-byte seed.

        Deterministic: the same seed always yields the same key. There is no
        "generate a seed for me" path, because this package pulls in no random
        number generator. Use :func:`secrets.token_bytes` (32).
        """
        return _sphincs_keys_from_secret_bytes(self._ext.sphincs_plus_c_keygen(seed))

    def sign(self, message: bytes, keys: SphincsPlusCKeys) -> bytes:
        """Sign a 32-byte message. Stateless: ``keys`` is never modified."""
        return self._ext.sphincs_plus_c_sign(
            message, _sphincs_keys_to_secret_bytes(keys)
        )

    def verify(
        self, signature: bytes, message: bytes, public_key: SphincsPlusCPublicKey
    ) -> bool:
        """Verify. Never raises: malformed input is simply ``False``."""
        return self._ext.sphincs_plus_c_verify(
            signature, message, _public_key_to_bytes(public_key)
        )


class Shrincs:
    """The hybrid scheme, bound to one profile."""

    def __init__(self, ext: _Extension) -> None:
        self._ext = ext

    def keygen(
        self, seed: bytes, max_signatures: int = DEFAULT_MAX_STATEFUL_SIGNATURES
    ) -> ShrincsKeys:
        """Derive a hybrid keypair from a REQUIRED 32-byte seed.

        ``max_signatures`` fixes the stateful leaf budget for the life of the
        key and must be in 1..=4096. It cannot be raised later; a fresh chain
        needs :meth:`reset`, which changes the commitment.
        """
        secret, public_key, commitment = self._ext.shrincs_keygen(seed, max_signatures)
        return _shrincs_keys_from_bytes(secret, public_key, commitment)

    def import_signing_key(self, secret_key: bytes) -> ShrincsKeys:
        """Rebuild a key from persisted bytes, revalidating it.

        Recomputes both roots and the commitment from the seeds and rejects any
        mismatch with ``ERR_IMPORT_INVALID``. An exhausted key imports fine:
        stateful signing then raises, and stateless signing still works.
        """
        secret, public_key, commitment = self._ext.shrincs_import_signing_key(secret_key)
        return _shrincs_keys_from_bytes(secret, public_key, commitment)

    def sign(self, message: bytes, keys: ShrincsKeys) -> bytes:
        """Sign a 32-byte message with the next unused stateful leaf.

        Consumes a leaf and advances ``keys.stateful`` in place. Raises
        ``ERR_STATEFUL_LEAVES_EXHAUSTED`` once the budget is spent.

        Persist the key after this returns. Signing again from an older saved
        copy reuses a leaf, which breaks the one-time-signature guarantee the
        stateful path rests on and can leak the leaf's secret material.
        """
        signature, advanced = self._ext.shrincs_sign(
            message, shrincs_keys_to_secret_bytes(keys)
        )
        keys.stateful.next_leaf_index = int.from_bytes(advanced[132:136], "big")
        return signature

    def sign_stateless(self, message: bytes, keys: ShrincsKeys) -> bytes:
        """Sign on the recovery path. Consumes no leaf and never modifies ``keys``.

        Far more expensive than :meth:`sign`, and the signature is far larger.
        Reserved for recovery and rotation.
        """
        return self._ext.shrincs_sign_stateless(
            message, shrincs_keys_to_secret_bytes(keys)
        )

    def verify(
        self, signature: bytes, message: bytes, public_key_commitment: bytes
    ) -> bool:
        """Verify a stateful signature against the 32-byte commitment.

        The signature carries the full public key; this checks that key hashes
        to the commitment before verifying. Never raises.
        """
        return self._ext.shrincs_verify(signature, message, public_key_commitment)

    def verify_stateless(
        self,
        signature: bytes,
        message: bytes,
        stateless_public_key: SphincsPlusCPublicKey,
    ) -> bool:
        """Verify a stateless signature against ``keys.stateless.public_key``.

        A stateless SHRINCS signature is a SPHINCS+C signature, so this is
        :meth:`SphincsPlusC.verify`. Never raises.
        """
        return self._ext.shrincs_verify_stateless(
            signature, message, _public_key_to_bytes(stateless_public_key)
        )

    def reset(self, keys: ShrincsKeys, new_seed: bytes) -> None:
        """Start a fresh stateful chain from ``new_seed``, in place.

        Discards any relationship to prior stateful signatures, so use it after
        suspected leaf reuse. The stateless half and ``max_signatures`` are
        untouched, but ``public_key_commitment`` CHANGES: anything pinning the
        old commitment stops accepting this key.
        """
        updated = self._ext.shrincs_reset(shrincs_keys_to_secret_bytes(keys), new_seed)
        commitment = self._ext.shrincs_compute_public_key_commitment(updated)
        _, public_key, _ = self._ext.shrincs_import_signing_key(updated)
        rebuilt = _shrincs_keys_from_bytes(updated, public_key, commitment)
        keys.stateful = rebuilt.stateful
        keys.public_key_commitment = rebuilt.public_key_commitment
        keys.public_key = rebuilt.public_key

    def compute_public_key_commitment(self, keys: ShrincsKeys) -> bytes:
        """Recompute the commitment ``keys`` currently implies. Never modifies it."""
        return self._ext.shrincs_compute_public_key_commitment(
            shrincs_keys_to_secret_bytes(keys)
        )

    def recover_public_key_commitment(self, signature: bytes) -> bytes:
        """Recover the commitment a stateful signature implies, ecrecover style.

        Decodes the public key the envelope carries and recomputes the
        commitment from it. The envelope's own commitment field is never
        trusted. Raises ``ERR_ENVELOPE_MALFORMED`` on a signature that is not a
        well-formed stateful envelope.
        """
        return self._ext.shrincs_recover_public_key_commitment(signature)


@dataclass(frozen=True)
class Profile:
    """One profile's complete surface, as returned by :func:`bind`."""

    #: The SHRINCS profile name, read out of the extension itself.
    profile_name: str
    #: The ``hashsigs-rs`` version the extension was built from.
    version: str
    #: The largest ``max_signatures`` this profile's keygen accepts.
    max_stateful_signatures: int
    sphincs_plus_c: SphincsPlusC
    shrincs: Shrincs


def bind(ext: _Extension) -> Profile:
    """Assemble the surface on top of one profile's extension module.

    ``profile_name`` comes from the extension rather than from the import path,
    so it reports what the binary actually carries.
    """
    return Profile(
        profile_name=ext.profile_name(),
        version=ext.version(),
        max_stateful_signatures=ext.MAX_STATEFUL_SIGNATURES,
        sphincs_plus_c=SphincsPlusC(ext),
        shrincs=Shrincs(ext),
    )
