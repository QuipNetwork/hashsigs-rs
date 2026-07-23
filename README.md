# hashsigs-rs

Core Rust hash-signature workspace with:

- `hashsigs-rs`: one crate containing:
  - `wotsplus` primitives
  - `shrincs` signer / verifier primitives
  - `account` policy wrapper
  - `wasm` verifier / signer / account bindings
- `solana/`: Solana program integration

## Building

To build the library:

```bash
cargo build
```

For release build:

```bash
cargo build --release
```

To build the Solana program:

```bash
cd solana
cargo build-sbf
```

## WASM Packaging

The crate exposes SHRINCS verifier, signer, and account bindings under
`src/wasm/` behind the `wasm-bindings` feature. The supported build path is
`bin/build-wasm.sh`, which runs `cargo build` for `wasm32-unknown-unknown` and
then the `wasm-bindgen` CLI (not `wasm-pack`) for the `nodejs` and `web`
targets.

Prerequisites:

```bash
rustup target add wasm32-unknown-unknown
# Must equal the crate's wasm-bindgen dependency (Cargo.toml =0.2.100).
cargo install wasm-bindgen-cli --version 0.2.100
```

Build from the crate root (default output directory is `ts/src`):

```bash
./bin/build-wasm.sh
# or
./bin/build-wasm.sh ts/src
```

That writes:

```text
ts/src/nodejs/   # wasm-bindgen nodejs target (CommonJS)
ts/src/web/      # wasm-bindgen web target (ESM)
```

Optional custom output directory:

```bash
./bin/build-wasm.sh /tmp/hashsigs-wasm
```

The TypeScript package that wraps those bindings lives in `ts/` and is named
`@quip.network/hashsigs-wasm`. After the wasm build:

```bash
cd ts
npm ci
npm run build   # also rebuilds wasm, inlines browser wasm as base64, runs tsc
npm test        # packaging conformance against dist/
```

Published consumers load one async entry point. The package `"browser"` field
swaps the Node loader for the browser loader at bundle time:

```ts
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { shrincs } = await loadHashSigs();
const keys = shrincs.keygen(new Uint8Array(32).fill(0xab), 16);
```

CI builds and tests this package on merge requests and the default branch
(`ts-conformance` job). Version tags matching `vX.Y.Z` (optional pre-release
suffix) run the same build and publish to npm.

Current WASM scope:

- supported:
  - noble-style Uint8Array signer/verifier entry point (`loadHashSigs()`) for
    SPHINCS+C and SHRINCS keygen, sign, and verify
  - SHRINCS verifier, account-wrapper, and canonical message-hash bindings via
    the low-level `loadShrincsWasm()` loader
  - Node and browser packaging under `@quip.network/hashsigs-wasm`
- not implemented:
  - WOTS-specific wasm bindings
  - a separate `wasm-pack` / `pkg/<target>` layout

## SHRINCS Profiles

Rust currently supports the same SHRINCS profile identities as the active
Solidity implementation:

- `shrincs-256s-keccak`
- `shrincs-256s-sha2`
- `shrincs-128s-q18-keccak`
- `shrincs-128s-q20-keccak`

The profile selects the compile-time parameter tuple and profile identity.
The scheme-hash suite follows the selected profile:

- `256s-keccak`, `128s-q18-keccak`, `128s-q20-keccak`: internal scheme hashes use keccak
- `256s-sha2`: internal scheme hashes use SHA-256

`build.rs` is the single owner of Rust-side profile selection and profile
identity generation. It selects exactly one active profile for the build and
emits the corresponding profile cfg plus generated identity constants.

Profile identity follows the Solidity `SHRINCSParams` model:

- `PROFILE_NAME` is the canonical suite-qualified profile string
- `PROFILE_ID` is derived as `keccak256(PROFILE_NAME)`
- Rust generates that identity at build time so the name and ID cannot drift

EVM-domain hashes remain keccak under every profile so Rust stays aligned with
the Solidity verifier on:

- profile identity framing
- hybrid public-key commitments
- canonical action-message hashes

The ignored vector generator writes one golden file per compiled profile:

- `tests/test_vectors/shrincs_sphincs_256s_keccak.json`
- `tests/test_vectors/shrincs_sphincs_256s_sha2.json`
- `tests/test_vectors/shrincs_sphincs_128s_q18_keccak.json`
- `tests/test_vectors/shrincs_sphincs_128s_q20_keccak.json`

### Testing Profiles

Run the default profile (`shrincs-256s-keccak`):

```bash
cargo test
```

Run a specific non-default profile:

```bash
cargo test --no-default-features --features profile-256s-sha2
cargo test --no-default-features --features profile-128s-q18
cargo test --no-default-features --features profile-128s-q20
```

For a fast compile-only check:

```bash
cargo test --no-run
cargo test --no-run --no-default-features --features profile-256s-sha2
cargo test --no-run --no-default-features --features profile-128s-q18
cargo test --no-run --no-default-features --features profile-128s-q20
```

Select at most one explicit profile feature at a time:

- default build selects `shrincs-256s-keccak`
- `profile-256s`
- `profile-256s-sha2`
- `profile-128s-q18`
- `profile-128s-q20`

To regenerate the ignored SHRINCS golden vectors for the active profile:

```bash
cargo test generate_shrincs_sphincs_vectors -- --ignored --nocapture
cargo test --no-default-features --features profile-256s-sha2 generate_shrincs_sphincs_vectors -- --ignored --nocapture
cargo test --no-default-features --features profile-128s-q18 generate_shrincs_sphincs_vectors -- --ignored --nocapture
cargo test --no-default-features --features profile-128s-q20 generate_shrincs_sphincs_vectors -- --ignored --nocapture
```

### Fast Local Loops

During development, prefer a narrow local loop over rerunning the full matrix
after every edit. `bin/test-fast.sh` wraps the common targeted commands:

```bash
./bin/test-fast.sh compile-default
./bin/test-fast.sh signer-stateful
./bin/test-fast.sh signer-exact generated_stateful_signature_verifies
./bin/test-fast.sh wasm-exact wasm_keypair_binding_signs_and_exports_public_key
./bin/test-fast.sh signer-import
./bin/test-fast.sh account-policy
./bin/test-fast.sh account-exact full_rotation_with_replaced_stateless_key_resets_usage
./bin/test-fast.sh vectors-exact solidity_exported_stateful_action_vector_verifies_in_rust
./bin/test-fast.sh wasm-compile
./bin/test-fast.sh sha2-compile
```

Typical usage:

- use `compile-default` when you only need a fast native compile check
- use `signer-stateful`, `signer-import`, `signer-boundary`, `signer-stateless`,
  `signer-import-exact <test-name>`, or `signer-exact <test-name>` while
  editing SHRINCS signer code
- use `account-policy` or `account-rotation` instead of the broader `account`
  target when you only need one account behavior slice, or `account-exact
  <test-name>` for one exact case
- use `vectors-shrincs` when you only care about the SHRINCS Solidity-exported
  vector cross-checks, or `vectors-exact <test-name>` for one exact vector test
- use `wasm` for native wasm-module tests, `wasm-exact <test-name>` for one
  wasm case, and `wasm-compile` for wasm target compile coverage
- use `solidity-exact <test-name>` when you only want one
  `solidity_account_vectors` case
- use `wasm-compile` for wasm target compile coverage without trying to execute
  the `.wasm` artifact locally
- use `wasm-node` only when you want the actual Node-based wasm runtime tests
- run `cargo test` or `./bin/test-shrincs-profiles.sh` only after the narrow
  loop is clean

For an automatic polling loop on file changes:

```bash
./bin/test-watch.sh help
./bin/test-watch.sh signer-stateful
./bin/test-watch.sh signer-exact 1 generated_stateful_signature_verifies
./bin/test-watch.sh account-exact 1 full_rotation_with_replaced_stateless_key_resets_usage
./bin/test-watch.sh wasm-compile 2
```

`test-watch.sh` watches the crate's Rust, test, script, and build files and
reruns the selected `test-fast.sh` area whenever something changes.

## SHRINCS Layout

The SHRINCS Rust code follows the same high-level split as the Solidity
implementation:

- public compatibility entrypoints
  - `src/shrincs/signer.rs`
  - `src/shrincs/verifier.rs`
- public signer/verifier surfaces
  - `src/shrincs/signers/shrincs_signer.rs`
  - `src/shrincs/verifiers/shrincs_verifier.rs`
  - `src/shrincs/verifiers/sphincs_plus_c_verifier.rs`
- pure scheme orchestration
  - `src/shrincs/core/shrincs.rs`
  - `src/shrincs/core/sphincs_plus_c.rs`
- shared components
  - `src/shrincs/components/hash.rs`
  - `src/shrincs/components/public_key.rs`
  - `src/shrincs/components/uxmss.rs`
  - `src/shrincs/components/fors_c.rs`
  - `src/shrincs/components/hypertree.rs`
- signer-only implementation modules
  - `src/shrincs/signers/uxmss.rs`
  - `src/shrincs/signers/fors_c.rs`
  - `src/shrincs/signers/hypertree.rs`
  - `src/shrincs/signers/utils.rs`
  - `src/shrincs/signers/types.rs`

`src/shrincs/components/public_key.rs` is the canonical shared owner for:

- hybrid public-key commitment derivation
- stateful rotation-target commitment derivation
- encoded stateful public-key encoding
- encoded stateful public-key decoding

Both the signer and the hybrid core use that module so commitment assembly,
validation, and rotation decoding stay on one implementation path.

`src/shrincs/core/messages.rs` is the shared owner for canonical SHRINCS
message-hash construction:

- `stateful_action_message_hash(...)`
- `stateless_action_message_hash(...)`
- `stateful_rotation_message_hash(...)`
- `full_rotation_message_hash(...)`

Both public facades delegate to that lower-level module rather than depending
on each other for canonical message construction.

## WASM Testing

Two layers cover the wasm surface:

1. **Rust host tests** (`cargo test --features wasm-bindings`): DTO parsing,
   byte-length validation, and feature-gated conversion logic on the host.
   They don't run the exported bindings inside a wasm runtime.
2. **TS packaging conformance** (`cd ts && npm test`, after `npm run build`):
   loads the built `dist/` package through both Node and browser loaders and
   exercises `loadHashSigs()` (keygen, sign, verify, stateful-leaf advance,
   import) and the low-level `loadShrincsWasm()` account/verifier surface.

For Rust-only wasm target unit tests (optional), install a matching
`wasm-bindgen-test-runner` and run:

```bash
cargo test --features wasm-bindings --target wasm32-unknown-unknown
```

When changing `WasmShrincsKeys`, `WasmSphincsPlusCKeys`, `WasmShrincsAccount`,
or verifier exports in `src/wasm/`, treat the TS conformance suite as the
packaging gate and the Rust suite as the crypto / DTO gate.

## WASM API

`loadHashSigs()` is the noble-style entry point. It awaits the wasm module
once and resolves to `{ sphincsPlusC, shrincs }` — two namespace objects
whose methods take and return `Uint8Array` only; no hex strings appear on
this surface. After the initial `await`, every call is synchronous.

Messages are exactly 32 bytes. Callers pre-hash arbitrary data and pass the
32-byte digest, matching how the on-chain and envelope verifiers treat their
hash argument as the signed message. A wrong-length message throws on sign
and returns `false` on verify; verify never throws.

### SPHINCS+C (stateless, standalone)

```ts
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { sphincsPlusC } = await loadHashSigs();

const keys = sphincsPlusC.keygen(seed); // seed: 32-byte Uint8Array
// keys.secretKey: Uint8Array(128)
// keys.publicKey: Uint8Array(64) = pkSeed ‖ hypertreeRoot

const sig = sphincsPlusC.sign(message32, keys);
const ok = sphincsPlusC.verify(sig, message32, keys.publicKey); // boolean
```

`sign` is stateless: it never mutates `keys.secretKey`. `verify` never
throws — a malformed signature or wrong-length input is simply `false`.

### SHRINCS (hybrid, stateful with stateless recovery)

```ts
import { loadHashSigs } from "@quip.network/hashsigs-wasm";

const { shrincs } = await loadHashSigs();

const keys = shrincs.keygen(seed, maxSignatures); // maxSignatures defaults to 1024
// keys.secretKey: Uint8Array(264)
// keys.publicKey: Uint8Array(164)
// keys.publicKeyCommitment: Uint8Array(32)

const sig = shrincs.sign(message32, keys);               // STATEFUL: advances keys.secretKey in place
const recovery = shrincs.signStateless(message32, keys); // stateless recovery path, no mutation

const ok = shrincs.verify(sig, message32, keys.publicKeyCommitment);
const okRecovery = shrincs.verifyStateless(recovery, message32, keys.publicKeyCommitment);
```

`shrincs.sign` is stateful:

- each call consumes one one-time UXMSS leaf and advances `keys.secretKey`
  (a 264-byte `Uint8Array`) **in place** — the same buffer the caller holds
  gets mutated, so the next `sign` call automatically uses the next leaf. No
  new key object comes back.
- once the stateful budget is spent, it throws an `Error` with
  `error.code === "ERR_STATEFUL_LEAVES_EXHAUSTED"`.

Footgun: cloning `keys.secretKey` and signing from the copy reuses a leaf,
which breaks the one-time-signature security the scheme depends on. Persist
and reuse the same advancing buffer. Never sign again from a snapshot taken
before an earlier `sign` call.

### Persisting and importing a SHRINCS key

`keys.secretKey` is plain bytes. Save and restore it directly: write the
`Uint8Array` to disk or a database after every stateful `sign()` call. To
rebuild a keypair object from a persisted 264-byte `secretKey`, use the
low-level `shrincsImportSigningKey`, reached through `loadShrincsWasm()`:

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const keys = wasm.shrincsImportSigningKey(persistedSecretKey);
```

`shrincsImportSigningKey` recomputes both roots and the commitment from the
seeds and rejects a mismatch with `ERR_IMPORT_INVALID`. It accepts an
already-exhausted key: stateful signing then throws
`ERR_STATEFUL_LEAVES_EXHAUSTED`, but stateless signing still works.

See [SECURITY.md](SECURITY.md) for the operational rules around holding and
persisting this key material.

### Low-level loader (account and verifier-interface surface)

`loadShrincsWasm()` is the loader the account machine and the
envelope/action verifier surface use. It resolves to the generated wasm
module directly, not the `sphincsPlusC`/`shrincs` namespaces described
earlier. Scalar byte fields — keys, commitments, addresses, message digests —
are `Uint8Array`. The structured DTOs below (`ShrincsPublicKey`,
`ActionContext`, `StatefulSignature`, and related shapes) still carry their
fields as `0x`-prefixed hex strings; that part of the surface hasn't changed.
`u64` fields cross the boundary as JavaScript `bigint`. All DTO shapes and
the `WasmShrincsAccount` type are importable (type-only) from the package
entry.

`loadShrincsWasm()` also exposes the free functions `loadHashSigs()` wraps:
`shrincsKeygen`, `shrincsImportSigningKey`, `shrincsSign`,
`shrincsSignStateless`, `shrincsVerify`, `shrincsVerifyStateless`,
`sphincsPlusCKeygen`, `sphincsPlusCSign`, `sphincsPlusCVerify`, and
`version()`.

### Verifier exports

- `shrincsVerifyEnvelope(key, hash, signature)`
- `shrincsVerifyStatelessEnvelope(key, hash, signature)`
- `shrincsVerifyStatefulRaw(...)`
- `shrincsVerifyStatefulAction(...)`
- `shrincsVerifyStatelessRaw(...)`
- `shrincsVerifyStatelessAction(...)`
- `sphincsPlusCVerify(signature, message32, publicKey)` — noble argument order

Malformed hex or wrong-length fields throw an `Error` with a typed
`error.code` (`ERR_HEX_INVALID`, `ERR_BAD_LENGTH`, or `ERR_INVALID_INPUT` for
serde shape errors). Cryptographic verification failure returns `false` and
doesn't throw.

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const ok = wasm.shrincsVerifyStatelessAction(
  publicKey.publicKeyCommitment,
  publicKey,
  {
    domainSeparator: "0x...",
    nonce: "0x...",
    keyVersion: "0x...",
    actionType: "0x...",
    payloadHash: "0x...",
  },
  signature,
);
```

`shrincsVerifyEnvelope` and `shrincsVerifyStatelessEnvelope` verify the
ABI-encoded envelope bytes `shrincs.sign()` / `shrincs.signStateless()`
return, directly against a `publicKeyCommitment`, with no DTO involved:

```ts
import { loadShrincsWasm, loadHashSigs } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const { shrincs } = await loadHashSigs();

const keys = shrincs.keygen(seed, 4);
const envelope = wasm.shrincsSign(message32, keys.secretKey);
const ok = wasm.shrincsVerifyEnvelope(keys.publicKeyCommitment, message32, envelope);
```

### Account exports

- `new WasmShrincsAccount(owner, chainId, contractAddress, publicKeyCommitment)`
  — `owner` and `chainId` are 32-byte `Uint8Array`, `contractAddress` is a
  20-byte `Uint8Array`, `publicKeyCommitment` is a 32-byte `Uint8Array`
- `snapshot()`
- `verifyStatefulAction(...)`
- `verifyStatelessAction(...)`
- `rotateToFreshKey(...)`
- `rotateFullKey(...)`
- `setStatefulPolicyMonotonicIndex(...)`
- `setStatefulPolicyRecoveryRotation(...)`
- `setStatefulPolicyLeafBitmap(...)`
- `enterRecoveryMode(...)`
- `isValidSignature(...)`

Canonical message-hash helpers, all returning `Uint8Array`:

- `shrincsStatefulActionMessageHash(...)`
- `shrincsStatelessActionMessageHash(...)`
- `shrincsStatefulRotationMessageHash(...)`
- `shrincsFullRotationMessageHash(...)`

```ts
import { loadShrincsWasm, loadHashSigs } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const { shrincs } = await loadHashSigs();

const owner = new Uint8Array(32).fill(0x11);
const chainId = new Uint8Array(32).fill(0x22);
const contractAddress = new Uint8Array(20).fill(0x33);

const keys = shrincs.keygen(seed, 8);
const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  keys.publicKeyCommitment,
);

account.setStatefulPolicyRecoveryRotation(owner);
account.enterRecoveryMode(owner);

console.log(account.snapshot());
```

`verifyStatefulAction`, `verifyStatelessAction`, `rotateToFreshKey`, and
`rotateFullKey` take the structured `ShrincsPublicKey` / `StatefulSignature`
/ `StatelessSignature` / rotation-target DTOs (see Object shapes below) —
that part of the surface hasn't moved to bytes. `shrincs.keygen()`'s
`publicKey` is a flat `Uint8Array(164)` bundle
(`statefulPublicKey(68) ‖ publicKeyCommitment(32) ‖ pkSeed(32) ‖
hypertreeRoot(32)`), not the hex DTO these methods expect, so decode it by
hand when you need one:

```ts
const toHex = (bytes: Uint8Array) =>
  "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function publicKeyDto(keys: { publicKey: Uint8Array }) {
  return {
    statefulPublicKey: toHex(keys.publicKey.slice(0, 68)),
    publicKeyCommitment: toHex(keys.publicKey.slice(68, 100)),
    pkSeed: toHex(keys.publicKey.slice(100, 132)),
    hypertreeRoot: toHex(keys.publicKey.slice(132, 164)),
  };
}
```

`shrincs.sign()` / `shrincs.signStateless()` don't produce the structured
`StatefulSignature` / `StatelessSignature` DTO these account methods expect.
They return an ABI-encoded envelope instead (see `shrincsVerifyEnvelope` /
`shrincsVerifyStatelessEnvelope` earlier for verifying those directly against
a `publicKeyCommitment`). Calling `verifyStatefulAction`, `rotateToFreshKey`,
or `rotateFullKey` needs a signature already in the structured DTO shape,
typically produced by the same off-chain tooling that produces the
Solidity-side test vectors this account layer mirrors.

Canonical end-to-end pattern for the DTO-based calls:

- read `domainSeparator`, `nonce`, and `keyVersion` from `account.snapshot()`
- hash with the matching message helper (`shrincsStatefulActionMessageHash`
  and friends, all returning `Uint8Array`)
- sign with a signer that returns the structured `StatefulSignature` /
  `StatelessSignature` DTO
- submit through the matching account verify or rotate method

### Object shapes

Names match the generated Tsify types re-exported from
`@quip.network/hashsigs-wasm` (see `ts/src/index.ts`). Fields are camelCase.
These DTOs belong to the low-level `loadShrincsWasm()` account/verifier
surface. The noble-style `sphincsPlusC`/`shrincs` namespaces never see them.

Public key (`ShrincsPublicKey`):

```ts
type ShrincsPublicKey = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
  pkSeed: string;
  hypertreeRoot: string;
};
```

Action context (`ActionContext`):

```ts
type ActionContext = {
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
  actionType: string;
  payloadHash: string;
};
```

Account snapshot (`ShrincsAccountSnapshot`):

```ts
type ShrincsAccountSnapshot = {
  currentShrincsPublicKey: string;
  owner: string;
  chainId: string;
  contractAddress: string;
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
  statelessSignaturesUsed: bigint; // u64 over the wasm boundary
  statefulPolicy: string;
  nextStatefulLeafIndex: number;
  recoveryMode: boolean;
};
```

Rotation context (`RotationContext`):

```ts
type RotationContext = {
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
};
```

Stateful rotation target (`StatefulRotationTarget`):

```ts
type StatefulRotationTarget = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
};
```

Full rotation target (`RotationTarget`):

```ts
type RotationTarget = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
  pkSeed: string;
  hypertreeRoot: string;
};
```

Stateful signature (`StatefulSignature`):

```ts
type StatefulSignature = {
  randomizer: string;
  counter: number;
  chains: string[];
  authPath: string[];
};
```

Stateless signature (`StatelessSignature`):

```ts
type ForsEntry = {
  secretLeaf: string;
  authPath: string[];
};

type ForsSignature = {
  randomizer: string;
  counter: number;
  entries: ForsEntry[];
};

type WotsCSignature = {
  randomizer: string;
  counter: number;
  chains: string[];
};

type HypertreeLayerSignature = {
  treeIndex: bigint; // u64 over the wasm boundary
  leafIndex: number;
  wotsCPkHash: string;
  wotsCSignature: WotsCSignature;
  authPath: string[];
};

type StatelessSignature = {
  fors: ForsSignature;
  hypertree: HypertreeLayerSignature[];
};
```

## Testing

Run all tests:

```bash
cargo test
```

Rust currently supports the SHRINCS keccak profiles (`256s`, `128s-q18`,
`128s-q20`) and the `256s-sha2` profile. The SHA-256 suite switch applies only
to SHRINCS scheme hashes (FORS-C, hypertree, WOTS-C, UXMSS); EVM-domain hashes
such as canonical action hashes and public-key commitments remain keccak to
match the Solidity design.

Run specific test vectors:

```bash
cargo test test_wotsplus_keccak256_vectors
```

Generate SHRINCS vectors for the Solidity verifier:

```bash
cargo test --test generate_shrincs_vectors -- --ignored --nocapture
```

Or run the generator for a specific profile:

```bash
cargo test --test generate_shrincs_vectors -- --ignored --nocapture
cargo test --features profile-256s-sha2 --test generate_shrincs_vectors -- --ignored --nocapture
cargo test --features profile-128s-q18 --test generate_shrincs_vectors -- --ignored --nocapture
cargo test --features profile-128s-q20 --test generate_shrincs_vectors -- --ignored --nocapture
```

The generator writes the profile-selected SHRINCS vector JSON inside this Rust
repository:

```text
tests/test_vectors/shrincs_sphincs_256s_keccak.json
tests/test_vectors/shrincs_sphincs_128s_q18_keccak.json
tests/test_vectors/shrincs_sphincs_128s_q20_keccak.json
tests/test_vectors/shrincs_sphincs_256s_sha2.json
```

SHRINCS public keys use one stateless `pkSeed` and one `hypertreeRoot`, matching
the SPHINCS+/FIPS-style `PK = (PK.seed, PK.root)` abstraction for the stateless
path, while the full hybrid bundle stays bound together by
`public_key_commitment`.

To use those vectors with the Solidity verifier tests, copy the generated file
for the active profile into the Solidity repository's matching fixture path:

```bash
# example: 256s-keccak
cp tests/test_vectors/shrincs_sphincs_256s_keccak.json \
  /path/to/hashsigs-solidity/test/test_vectors/shrincs_sphincs_256s_keccak.json

# example: 256s-sha2
cp tests/test_vectors/shrincs_sphincs_256s_sha2.json \
  /path/to/hashsigs-solidity/test/test_vectors/shrincs_sphincs_256s_sha2.json

# example: 128s-q18-keccak
cp tests/test_vectors/shrincs_sphincs_128s_q18_keccak.json \
  /path/to/hashsigs-solidity/test/test_vectors/shrincs_sphincs_128s_q18_keccak.json

# example: 128s-q20-keccak
cp tests/test_vectors/shrincs_sphincs_128s_q20_keccak.json \
  /path/to/hashsigs-solidity/test/test_vectors/shrincs_sphincs_128s_q20_keccak.json
```

For a quick local profile-matrix sweep, run:

```bash
./bin/test-shrincs-profiles.sh
```

To cross-check Solidity-exported account vectors against the Rust verifier,
generate the account-vector JSON in `hashsigs-solidity` first, then copy it
into this Rust repository manually. The repos are separate, so this handoff is
intentionally not automated.

```bash
# in hashsigs-solidity
bash dev/export-account-vectors.sh

# copy the generated JSON into hashsigs-rs manually
cp /path/to/hashsigs-solidity/test/test_vectors/shrincs_account_wrapper_vectors.json \
  tests/test_vectors/shrincs_account_wrapper_vectors.json
```

For the `shrincs-256s-sha2` profile:

```bash
# in hashsigs-solidity
FOUNDRY_PROFILE=256s-sha2-export \
  bash dev/export-account-vectors.sh \
  test/test_vectors/shrincs_account_wrapper_vectors_256s_sha2.json

# copy the generated JSON into hashsigs-rs manually
cp /path/to/hashsigs-solidity/test/test_vectors/shrincs_account_wrapper_vectors_256s_sha2.json \
  tests/test_vectors/shrincs_account_wrapper_vectors_256s_sha2.json
```

Today the committed Rust-side account-wrapper cross-check fixtures exist for:

- `shrincs-256s-keccak`
- `shrincs-256s-sha2`

The `128s-q18` and `128s-q20` profile legs still ignore
`tests/solidity_account_vectors.rs` unless matching per-profile Solidity export
files are generated and copied in under profile-specific filenames.

Then run the Rust-side cross-check:

```bash
cargo test --test solidity_account_vectors
cargo test --no-default-features --features profile-256s-sha2 --test solidity_account_vectors
```

Generate the kth stateful gas vector for Solidity gas benchmarks. The
generator requires Foundry's `cast` on `PATH` and writes
`tests/test_vectors/shrincs_stateful_k_gas_vector.json` (gitignored):

```bash
cargo test --test generate_stateful_gas_vector -- --ignored --nocapture
```

Run Solana program tests:

```bash
cd solana
cargo test-sbf
```

For test output and backtrace:

```
RUST_BACKTRACE=1 cargo test-sbf -- --nocapture 2>&1
```

Show compute units only:

```
RUST_BACKTRACE=1 cargo test-sbf -- --nocapture 2>&1 | grep "compute units:"
```

## Development Requirements

- Rust 1.79 or later; the current local test pass was with Rust 1.95.0
- Solana/Agave SBF cargo subcommands, including `cargo build-sbf` and
  `cargo test-sbf`, for Solana program development: https://solana.com/docs/intro/installation

NOTE: if on Mac, do not use brew to install rust and instead use https://www.rust-lang.org/tools/install

## Project Structure

```
.
├── bin/
│   └── build-wasm.sh  # cargo + wasm-bindgen helper (nodejs + web → ts/src)
├── src/
│   ├── wotsplus/  # WOTS+ primitives
│   ├── shrincs/   # SHRINCS types, primitives, orchestration, and public surfaces
│   │   ├── components/  # low-level SHRINCS primitives (Hash / UXMSS / FORS-C / Hypertree)
│   │   ├── core/        # scheme orchestration (hybrid SHRINCS / stateless SPHINCS+C)
│   │   ├── signers/     # canonical SHRINCS signer ownership
│   │   ├── verifiers/   # canonical SHRINCS verifier ownership
│   │   ├── signer.rs    # compatibility signer entrypoint
│   │   ├── verifier.rs  # compatibility verifier entrypoint
│   │   ├── types.rs     # shared SHRINCS structs
│   │   └── profiles.rs  # compile-time profile constants
│   ├── account/   # Rust account-policy wrapper
│   └── wasm/      # Verifier / signer / account wasm-bindgen surface
├── ts/            # @quip.network/hashsigs-wasm (loadShrincsWasm entry)
├── solana/        # Solana program implementation
└── tests/         # Test vectors and unit tests
```

## SHRINCS Architecture

The `shrincs` module is layered to mirror the Solidity architecture:

- `components/` owns low-level primitives
  - `hash.rs`
  - `uxmss.rs`
  - `fors_c.rs`
  - `hypertree.rs`
- `core/` owns scheme composition and hybrid-key validation
  - `shrincs.rs`
  - `sphincs_plus_c.rs`
- `signers/` and `verifiers/` own the canonical public Rust surfaces
- `signer.rs` and `verifier.rs` are compatibility shims that preserve the
  historical public import paths

Public API stability note:

- prefer `hashsigs_rs::shrincs::*`, `hashsigs_rs::shrincs::signer::*`, and
  `hashsigs_rs::shrincs::verifier::*` as the stable public surface
- the deeper `components/`, `core/`, `signers/`, and `verifiers/` modules are
  internal architecture, not the primary external API contract

## Account Layer Notes

The `account` module is an off-chain Rust policy wrapper that tracks nonce,
key-version, stateful-leaf use, and recovery-mode transitions around the core
SHRINCS primitives. It is intentionally close to the Solidity example account
wrapper, but it is not a literal runtime-equivalent copy.

The Rust account wrapper enforces a hardened security policy model:

- switches between stateful leaf-tracking policies (monotonic index and leaf
  bitmap) are frozen after the first successful stateful use in a key epoch;
  switching to `RecoveryRotation` stays available so key rotation is always
  reachable
- `RecoveryRotation` disables the stateful path for the whole recovery-policy epoch
- `rotateToFreshKey(...)` preserves stateless usage accounting because the stateless key is unchanged
- `rotateFullKey(...)` resets stateless usage accounting only when the supplied
  rotation target actually changes the stateless key material

Current intentional differences:

- Owner / caller model:
  Rust stores `owner` as a generic 32-byte value and takes an explicit
  `caller` argument for owner-gated methods. Solidity stores `owner` as an
  `address` and relies on `msg.sender`. The Rust model is therefore an
  integration-supplied authority check, not a chain-enforced caller model.

- Event semantics:
  Solidity emits wrapper events such as policy changes, recovery-mode entry,
  key rotation, and successful signature verification. Rust currently mutates
  wrapper state and returns `bool` / `Result` values, but does not emit
  first-class event records. Treat this as an observability difference rather
  than a cryptographic or policy-enforcement difference.

- Constructor / account identity model:
  Rust account initialization takes `owner`, `chainId`, `contractAddress`, and
  the initial SHRINCS public-key commitment as explicit inputs. Solidity gets
  owner, chain id, and contract identity from the live execution environment.
  The Rust constructor should therefore be understood as an off-chain
  simulation/adaptation surface, not a one-to-one deployment API mirror.

The account module now recomputes its domain separator from stored `chainId`
and `contractAddress`, and `rotateToFreshKey(...)` is narrowed to a dedicated
stateful-only recovery-rotation target. It also enforces hardened
policy/accounting behavior that goes beyond the current Solidity example
wrapper:

- the stateful leaf-tracking model must be chosen before the first successful
  stateful signature in a key epoch; only `RecoveryRotation` may still be
  selected afterwards, so a used key can always rotate out
- selecting `RecoveryRotation` blocks the stateful path immediately; `enterRecoveryMode(...)`
  then permits stateless action verification and stateless recovery rotations
- stateful-only rotation consumes one stateless recovery use and carries that counter forward
- full-key rotation consumes one stateless recovery use under the old key and resets the
  counter only when the newly installed stateless key actually differs

## License

AGPL-3.0, see COPYING
