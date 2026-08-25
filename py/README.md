# hashsigs

Hash-based signatures for Python: SHRINCS and SPHINCS+C, backed by the audited
[`hashsigs-rs`](https://gitlab.com/quip.network/hashsigs-rs) crate.

SHRINCS is a two-path construction. One committed key carries a cheap bounded
stateful path for normal use, and an expensive unbounded stateless path for
recovery and rotation. Verification is pure hashing and needs no signer state.

## Install

```bash
pip install hashsigs
```

Wheels target CPython 3.9 and later through the stable ABI, so one wheel per
platform serves every supported version.

## Quick start

```python
import hashlib
import secrets

from hashsigs import shrincs, shrincs_keys_to_secret_bytes

# The seed is REQUIRED and must be 32 bytes. This package pulls in no random
# number generator, so you supply the entropy.
keys = shrincs.keygen(secrets.token_bytes(32), max_signatures=1024)

# Sign a 32-byte message. Pre-hash whatever you are actually signing.
message = hashlib.sha256(b"transfer 10 to alice").digest()
signature = shrincs.sign(message, keys)

assert shrincs.verify(signature, message, keys.public_key_commitment)

# Persist after every stateful signature. See "Stateful signing" below.
with open("key.bin", "wb") as handle:
    handle.write(shrincs_keys_to_secret_bytes(keys))
```

A verifier stores only the 32-byte `public_key_commitment`. The signature
carries the full public key, and verification checks that key hashes to the
commitment before trusting it.

## Profiles

This one distribution carries every SHRINCS profile. Each has its own module,
and the package root is the default profile, `256s-keccak`:

```python
# The default profile.
from hashsigs import shrincs

# Any other profile, from its own module.
from hashsigs.profiles import p128s_q18
```

| Module | Profile | Scheme hash |
|---|---|---|
| `hashsigs` (root) | `shrincs-256s-keccak` | keccak-256 |
| `hashsigs.profiles.p256s` | `shrincs-256s-keccak` | keccak-256 |
| `hashsigs.profiles.p256s_sha2` | `shrincs-256s-sha2` | SHA-256 |
| `hashsigs.profiles.p128s_q18` | `shrincs-128s-q18-keccak` | keccak-256 |
| `hashsigs.profiles.p128s_q20` | `shrincs-128s-q20-keccak` | keccak-256 |
| `hashsigs.profiles.p128s_q18_sha2` | `shrincs-128s-q18-sha2` | SHA-256 |
| `hashsigs.profiles.p128s_q20_sha2` | `shrincs-128s-q20-sha2` | SHA-256 |

Every module exposes the same names. They differ only in what they compute, and
**a signature made under one profile does not verify under any other**. Pick one
profile per key and keep it. Persisted key bytes carry no profile tag, so
importing them under the wrong profile raises `ERR_IMPORT_INVALID` rather than
producing a key that signs unverifiably.

Read the loaded profile back from the extension itself, not from the import
path:

```python
from hashsigs.profiles import p128s_q18

assert p128s_q18.profile_name == "shrincs-128s-q18-keccak"
```

Choose on cost. The 128s profiles produce much smaller signatures and verify
faster, at the price of slow signing. Keygen at 128s takes tens of seconds,
against roughly 0.1 seconds at 256s.

The sha2 variants sign about three times faster than their keccak twins. They
cost more gas on-chain, though, because keccak is an EVM opcode while SHA-256
is a precompile. The repository README carries the measured table.

## Stateful signing

`shrincs.sign` consumes one leaf of a fixed budget and advances the key. This is
the part that needs care.

```python
keys = shrincs.keygen(seed, max_signatures=4)
print(keys.stateful.remaining)  # 4

signature = shrincs.sign(message, keys)
print(keys.stateful.remaining)  # 3

# Persist NOW, before the next signature.
with open("key.bin", "wb") as handle:
    handle.write(shrincs_keys_to_secret_bytes(keys))
```

**Save the key after every stateful signature.** Signing twice from the same
saved state reuses a one-time leaf, which breaks the guarantee the stateful path
rests on and can expose that leaf's secret material. Restore with
`shrincs.import_signing_key`, which revalidates the key against its own seeds
and preserves the leaf counter:

```python
with open("key.bin", "rb") as handle:
    keys = shrincs.import_signing_key(handle.read())
print(keys.stateful.remaining)  # 3, not 4
```

`max_signatures` is fixed at keygen and cannot be raised later. Once the budget
is spent, stateful signing raises:

```python
from hashsigs import HashSigsError

try:
    shrincs.sign(message, keys)
except HashSigsError as err:
    if err.code == "ERR_STATEFUL_LEAVES_EXHAUSTED":
        ...  # rotate, or fall back to the stateless path
```

## The stateless path

`shrincs.sign_stateless` consumes no leaf, never modifies the key, and works on
an exhausted key. It is far slower and its signatures are far larger, so it
serves recovery and rotation rather than normal traffic.

```python
signature = shrincs.sign_stateless(message, keys)
assert shrincs.verify_stateless(signature, message, keys.stateless.public_key)
```

`shrincs.reset(keys, new_seed)` starts a fresh stateful chain after suspected
leaf reuse. The stateless half and `max_signatures` survive, but
`public_key_commitment` **changes**, so anything pinning the old commitment
stops accepting the key.

## Errors

Every failure raises `HashSigsError` with a stable `code`. Branch on the code,
never on the message text. Messages never echo the input that caused them,
because that input is routinely secret key material and messages routinely
reach logs.

| Code | Meaning |
|---|---|
| `ERR_BAD_LENGTH` | A fixed-width argument had the wrong length |
| `ERR_INVALID_INPUT` | `max_signatures` outside 1 to 4096 |
| `ERR_KEYGEN_FAILED` | Key derivation failed for these inputs |
| `ERR_IMPORT_INVALID` | Recomputed roots do not match the seeds, or the counter is out of range |
| `ERR_STATEFUL_LEAVES_EXHAUSTED` | Every stateful leaf is spent |
| `ERR_SIGNING_FAILED` | Grinding failed for this key and message |
| `ERR_ENVELOPE_MALFORMED` | The signature is not a well-formed envelope |

Verification never raises. A malformed signature, a wrong-length key, or a
commitment mismatch is simply `False`.

## Building from source

```bash
bash bin/build-python.sh                  # one extension per profile
maturin build --release -m py/Cargo.toml  # assemble the wheel
```

Pass `--release`. maturin defaults to a debug build, which produces a far
larger and far slower extension.

The wheel carries one compiled extension per profile under `hashsigs._ext`, so
importing a profile maps only that profile's code. Each extension links its own
copy of the crate, at about 715 KB each, so the six add roughly 4.3 MB against
715 KB for a single-profile build. The released wheel is about 2.0 MB
compressed. That is the trade this layout makes, and unlike a browser bundle
there is no per-import transfer saving to offset it.

## License

AGPL-3.0-or-later. See [COPYING](../COPYING).
