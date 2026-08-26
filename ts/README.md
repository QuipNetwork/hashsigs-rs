# @quip.network/hashsigs-wasm

SHRINCS hash-based signatures for Node.js and the browser, compiled from the
audited [`hashsigs-rs`](https://gitlab.com/quip.network/hashsigs-rs) Rust crate
to WebAssembly. The same signatures verify on-chain against the Solidity and
Solana verifiers.

Two schemes ship in one package:

- **SPHINCS+C**: a standalone stateless signature.
- **SHRINCS**: a hybrid key. It binds a cheap stateful fast path (UXMSS, an
  unbalanced XMSS-style Merkle tree) and a stateless SPHINCS+C recovery path
  under one 32-byte public-key commitment.

## Install

```bash
npm install @quip.network/hashsigs-wasm
```

## Profiles

This one package carries every SHRINCS profile. Each has its own import path,
and the package root is the default profile, `256s-keccak`:

```ts
// The default profile.
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

// Any other profile, on its own path.
import { loadHashSigs as load128s } from "@quip.network/hashsigs-wasm/128s-q18";
```

| Import path | Profile | Scheme hash |
|---|---|---|
| `@quip.network/hashsigs-wasm` | `shrincs-256s-keccak` | keccak-256 |
| `@quip.network/hashsigs-wasm/256s-keccak` | `shrincs-256s-keccak` | keccak-256 |
| `@quip.network/hashsigs-wasm/256s-sha2` | `shrincs-256s-sha2` | SHA-256 |
| `@quip.network/hashsigs-wasm/128s-q18` | `shrincs-128s-q18-keccak` | keccak-256 |
| `@quip.network/hashsigs-wasm/128s-q20` | `shrincs-128s-q20-keccak` | keccak-256 |
| `@quip.network/hashsigs-wasm/128s-q18-sha2` | `shrincs-128s-q18-sha2` | SHA-256 |
| `@quip.network/hashsigs-wasm/128s-q20-sha2` | `shrincs-128s-q20-sha2` | SHA-256 |

Every path exports the same names with the same shapes. They differ only in
what they compute, and **a signature made under one profile does not verify
under any other**. Pick one profile per key and keep it.

Each path carries its own wasm binary, so a browser bundle contains only the
profile you import, not all six. Read the loaded profile back with
`profileName`, which comes from the binary itself rather than the import path:

```ts
const { shrincs, profileName } = await load128s();
// profileName === "shrincs-128s-q18-keccak"
```

Choose on cost. The 128s profiles produce far smaller signatures and verify
faster, at the price of slow signing. Through wasm, 128s keygen takes roughly
53 seconds and a stateless signature roughly 52 more, against about 0.1 seconds
each at 256s. The sha2 variants sign about three times faster than their keccak
twins natively, yet cost more gas on-chain, where keccak is an opcode and
SHA-256 is a precompile. The root README carries the full measured table.

## Quick start

`loadHashSigs()` awaits the wasm module once and resolves to
`{ sphincsPlusC, shrincs, shrincsImportSigningKey }`. After that first `await`,
every call is synchronous. Each key is a nested object, never a flat
`secretKey`/`publicKey` field. Every leaf and every argument is a
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

A stateless SHRINCS signature is a SPHINCS+C signature.
`shrincs.signStateless` produces the same bytes as `sphincsPlusC.sign` under
`keys.stateless`. `shrincs.verifyStateless(sig, msg, keys.stateless.publicKey)`
is exactly `sphincsPlusC.verify(sig, msg, keys.stateless.publicKey)`.

## Seeds and messages

- `keygen` and `reset` require a caller-supplied 32-byte seed. The library has
  no random number generator: pass `crypto.getRandomValues(new Uint8Array(32))`
  in the browser or `crypto.randomBytes(32)`/webcrypto in Node. A weak seed
  produces a weak key. The library does not check seed quality.
- Messages are exactly 32 bytes. Pre-hash arbitrary data and pass the digest,
  matching how the on-chain verifier treats its hash argument as the signed
  message. A wrong-length message throws on sign and returns `false` on verify.
  Verify never throws.

## Stateful signing and persistence

`shrincs.sign` consumes one one-time UXMSS leaf per call and advances
`keys.stateful` (`nextLeafIndex`, `remaining`) **in place**. The call mutates
the object the caller holds, so the next `sign` uses the next leaf. The call
does not return a new key object.

Serialize `keys` to its 264-byte flat secret with `shrincsKeysToSecretBytes`.
Persist that secret after **every** stateful `sign()` call. Rebuild the
keypair on restart with `shrincsImportSigningKey`:

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
> depends on. Persist after every `sign`. Never sign again from an older
> snapshot.

> **Performance:** every `shrincs.*` operation re-validates the full secret
> key. Each call recomputes the UXMSS root (up to `maxSignatures` hashes) and
> the SPHINCS+C root. This is inherent to the stateless key-in / key-out API:
> each call receives the secret bytes across the wasm boundary and re-checks
> them. Per-call latency scales with `maxSignatures`. Choose `maxSignatures`
> no larger than you need.

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
| `sign(message, keys)` | Stateful sign. Advances `keys.stateful` in place. Throws `ERR_STATEFUL_LEAVES_EXHAUSTED` when no leaves remain. |
| `signStateless(message, keys)` | Recovery-path sign. Never mutates `keys`. |
| `verify(signature, message, publicKeyCommitment)` | Verify the stateful commitment path. Returns a boolean. |
| `verifyStateless(signature, message, statelessPublicKey)` | Verify the recovery path (a SPHINCS+C verify). |
| `reset(keys, newSeed)` | Regenerate the stateful chain in place from a new 32-byte seed. |
| `computePublicKeyCommitment(keys)` | The 32-byte commitment the `keys` state implies. |
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

Thrown errors carry a stable `error.code`, typed as `ShrincsErrorCode`:

| Code | Cause |
|---|---|
| `ERR_BAD_LENGTH` | Wrong-length seed, message, or secret key (the most common caller mistake). |
| `ERR_INVALID_INPUT` | `maxSignatures` out of range (0 or greater than 4096). |
| `ERR_STATEFUL_LEAVES_EXHAUSTED` | No stateful leaves remain. Use `signStateless` or `reset`. |
| `ERR_IMPORT_INVALID` | Imported secret bytes fail root/commitment recomputation. |
| `ERR_KEYGEN_FAILED` | Key derivation failed for the supplied inputs. |
| `ERR_SIGNING_FAILED` | WOTS-C / FORS-C / hypertree grinding failed for the leaf/message. |

## Security

Seed entropy and one-time-leaf handling are the caller's responsibility. See
[SECURITY.md](https://gitlab.com/quip.network/hashsigs-rs/-/blob/main/SECURITY.md)
for the operational rules for holding and persisting key material.

## License

AGPL-3.0-or-later.
