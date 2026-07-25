# @quip.network/hashsigs-wasm

SHRINCS hash-based signatures for Node.js and the browser, compiled from the
audited [`hashsigs-rs`](https://gitlab.com/quip.network/hashsigs-rs) Rust crate
to WebAssembly. The same signatures verify on-chain against the Solidity and
Solana verifiers.

Two schemes ship in one package:

- **SPHINCS+C** — a standalone stateless signature.
- **SHRINCS** — a hybrid key: a cheap stateful fast path (UXMSS) plus a
  stateless SPHINCS+C recovery path, both bound under one 32-byte public-key
  commitment.

## Install

```bash
npm install @quip.network/hashsigs-wasm
```

## Quick start

`loadHashSigs()` awaits the wasm module once and resolves to
`{ sphincsPlusC, shrincs, shrincsImportSigningKey }`. After that first `await`,
every call is synchronous. Keys are decomposed nested objects (never a flat
`secretKey`/`publicKey` field); every leaf and every argument is a
`Uint8Array`.

### SPHINCS+C (stateless)

```ts
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { sphincsPlusC } = await loadHashSigs();

const seed = crypto.getRandomValues(new Uint8Array(32));
const keys = sphincsPlusC.keygen(seed);
// keys.secret:    { skSeed: Uint8Array(32), prfSeed: Uint8Array(32) }
// keys.publicKey: { pkSeed: Uint8Array(32), root: Uint8Array(32) }

const sig = sphincsPlusC.sign(message32, keys);      // never mutates keys
const ok = sphincsPlusC.verify(sig, message32, keys.publicKey); // boolean
```

### SHRINCS (stateful, with stateless recovery)

```ts
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { shrincs } = await loadHashSigs();

const seed = crypto.getRandomValues(new Uint8Array(32));
const keys = shrincs.keygen(seed, maxSignatures); // maxSignatures defaults to 1024

const sig = shrincs.sign(message32, keys);               // STATEFUL: mutates keys.stateful
const recovery = shrincs.signStateless(message32, keys); // recovery path, no mutation

const ok = shrincs.verify(sig, message32, keys.publicKeyCommitment);
const okRecovery = shrincs.verifyStateless(
  recovery,
  message32,
  keys.stateless.publicKey,
);
```

A stateless SHRINCS signature is a SPHINCS+C signature:
`shrincs.signStateless` produces the same bytes as `sphincsPlusC.sign` under
`keys.stateless`, and `shrincs.verifyStateless(sig, msg, keys.stateless.publicKey)`
is exactly `sphincsPlusC.verify(sig, msg, keys.stateless.publicKey)`.

## Seeds and messages

- `keygen` and `reset` require a caller-supplied 32-byte seed. The library has
  no RNG: pass `crypto.getRandomValues(new Uint8Array(32))` in the browser or
  `crypto.randomBytes(32)`/webcrypto in Node. A weak seed produces a weak key,
  and nothing here checks seed quality.
- Messages are exactly 32 bytes. Pre-hash arbitrary data and pass the digest,
  matching how the on-chain verifier treats its hash argument as the signed
  message. A wrong-length message throws on sign and returns `false` on verify;
  verify never throws.

## Stateful signing and persistence

`shrincs.sign` consumes one one-time UXMSS leaf per call and advances
`keys.stateful` (`nextLeafIndex`, `remaining`) **in place** — the object the
caller holds is mutated, so the next `sign` uses the next leaf. No new key
object is returned.

Serialize `keys` to its 264-byte flat secret with `shrincsKeysToSecretBytes`
and persist it after **every** stateful `sign()` call. Rebuild the keypair on
restart with `shrincsImportSigningKey`:

```ts
import { loadHashSigs, shrincsKeysToSecretBytes } from "@quip.network/hashsigs-wasm";

const { shrincsImportSigningKey } = await loadHashSigs();

const persisted = shrincsKeysToSecretBytes(keys); // 264 bytes, after every sign()
const restored = shrincsImportSigningKey(persisted);
```

`shrincsImportSigningKey` recomputes both roots and the commitment from the
seeds and rejects a mismatch with `ERR_IMPORT_INVALID`. It accepts an
already-exhausted key: stateful signing then throws
`ERR_STATEFUL_LEAVES_EXHAUSTED`, but stateless signing still works.

> **Footgun:** signing from a copy of `keys` taken before an earlier `sign`
> call reuses a leaf, which breaks the one-time-signature security the scheme
> depends on. Persist after every `sign`, and never sign again from an older
> snapshot.

When the stateful budget runs out, call `shrincs.signStateless` for unlimited
recovery-path signing, or `shrincs.reset(keys, newSeed)` to start a fresh
stateful chain. `reset` requires a new 32-byte seed, produces a new
`publicKeyCommitment`, and leaves `keys.stateless` untouched.

## API

`sphincsPlusC`:

| Method | Description |
|---|---|
| `keygen(seed)` | Derive a keypair from a 32-byte seed. |
| `sign(message, keys)` | Sign a 32-byte message. Never mutates `keys`. |
| `verify(signature, message, publicKey)` | Verify against `{ pkSeed, root }`. Returns a boolean. |

`shrincs`:

| Method | Description |
|---|---|
| `keygen(seed, maxSignatures?)` | Derive a hybrid key. `maxSignatures` defaults to 1024. |
| `sign(message, keys)` | Stateful sign; advances `keys.stateful` in place. Throws `ERR_STATEFUL_LEAVES_EXHAUSTED` when spent. |
| `signStateless(message, keys)` | Recovery-path sign. Never mutates `keys`. |
| `verify(signature, message, publicKeyCommitment)` | Verify the stateful commitment path. Returns a boolean. |
| `verifyStateless(signature, message, statelessPublicKey)` | Verify the recovery path (a SPHINCS+C verify). |
| `reset(keys, newSeed)` | Regenerate the stateful chain in place from a new 32-byte seed. |
| `computePublicKeyCommitment(keys)` | The 32-byte commitment `keys` currently implies. |
| `recoverPublicKeyCommitment(signature)` | The commitment a `shrincs.sign()` signature implies, `ecrecover`-style. |

Standalone: `shrincsImportSigningKey(secretKey)` and `shrincsKeysToSecretBytes(keys)`.

## Object shapes

`ts/src/index.ts` is the source of truth for these types.

```ts
interface SphincsPlusCKeys {
  secret: { skSeed: Uint8Array; prfSeed: Uint8Array };
  publicKey: { pkSeed: Uint8Array; root: Uint8Array };
}

interface ShrincsKeys {
  stateless: SphincsPlusCKeys; // never changes after keygen
  stateful: {
    secret: { skSeed: Uint8Array; prfSeed: Uint8Array };
    publicKey: { pkSeed: Uint8Array; root: Uint8Array; maxSignatures: number };
    nextLeafIndex: number; // 1-based; advances by one per sign()
    remaining: number;     // maxSignatures - (nextLeafIndex - 1)
  };
  publicKeyCommitment: Uint8Array; // 32 bytes
}
```

## Error codes

Thrown errors carry a stable `error.code` (typed as `ShrincsErrorCode`):

| Code | Cause |
|---|---|
| `ERR_INVALID_INPUT` | Wrong-length seed/message, or `maxSignatures` out of range. |
| `ERR_STATEFUL_LEAVES_EXHAUSTED` | The stateful budget is spent; use `signStateless` or `reset`. |
| `ERR_IMPORT_INVALID` | Imported secret bytes fail root/commitment recomputation. |

## Security

Seed entropy and one-time-leaf handling are the caller's responsibility. See
[SECURITY.md](https://gitlab.com/quip.network/hashsigs-rs/-/blob/main/SECURITY.md)
for the operational rules around holding and persisting key material.

## License

AGPL-3.0-or-later.
