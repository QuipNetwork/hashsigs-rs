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
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const keypair = wasm.shrincsKeygen("0x" + "ab".repeat(32), 16);
```

CI builds and tests this package on merge requests and the default branch
(`ts-conformance` job). Version tags matching `vX.Y.Z` (optional pre-release
suffix) run the same build and publish to npm.

Current WASM scope:

- supported:
  - SHRINCS verifier bindings
  - SHRINCS key generation, raw signing, and signing-key import/export
  - account-layer wrapper bindings
  - hex / plain-object JS entry points via `loadShrincsWasm()`
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
   hex helpers, and feature-gated conversion logic on the host. They do not
   run the exported bindings inside a wasm runtime.
2. **TS packaging conformance** (`cd ts && npm test`, after `npm run build`):
   loads the built `dist/` package through both Node and browser loaders and
   exercises keygen, sign, verify, import/export, and typed errors.

For Rust-only wasm target unit tests (optional), install a matching
`wasm-bindgen-test-runner` and run:

```bash
cargo test --features wasm-bindings --target wasm32-unknown-unknown
```

When changing `WasmShrincsKeypair`, `WasmShrincsAccount`, or verifier exports
in `src/wasm/`, treat the TS conformance suite as the packaging gate and the
Rust suite as the crypto / DTO gate.

## WASM API

`loadShrincsWasm()` resolves to the generated wasm module. That module exposes
verifier functions, signer/keypair APIs, and account-wrapper APIs. Byte fields
are `0x`-prefixed hex strings; structured values are plain camelCase objects.
`u64` fields cross the boundary as JavaScript `bigint`.
All DTO shapes and the `WasmShrincsKeypair` / `WasmShrincsAccount` handle
types are importable (type-only) from the package entry.

### Verifier exports

- `shrincsVerifyStatefulRaw(...)`
- `shrincsVerifyStatefulAction(...)`
- `shrincsVerifyStatelessRaw(...)`
- `shrincsVerifyStatelessAction(...)`

Malformed hex or wrong-length fields throw an `Error` with a typed
`error.code` (`ERR_HEX_INVALID`, `ERR_BAD_LENGTH`, or `ERR_INVALID_INPUT` for
serde shape errors). Cryptographic verification failure returns `false` and
does not throw.

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

### Signer exports

- `shrincsKeygen(seedHex, maxStatefulSignatures)`
- `shrincsImportSigningKey(exportedKey)`
- `WasmShrincsKeypair.publicKey()`
- `WasmShrincsKeypair.signStatefulRaw(...)` — returns
  `{ signature, nextStatefulLeafIndex }`
- `WasmShrincsKeypair.signStatefulRawAt(messageHex, leaf)`
- `WasmShrincsKeypair.signStatelessRaw(...)`
- `WasmShrincsKeypair.exportSigningKeyUnsafe()`
- `WasmShrincsKeypair.exportSigningKey()` — legacy alias of the `Unsafe` form
- `WasmShrincsKeypair.destroy()`
- getters: `nextStatefulLeafIndex`, `maxStatefulSignatures`,
  `remainingStatefulSignatures`
- `version()`

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
// Seed must be at least 32 bytes of hex.
const keypair = wasm.shrincsKeygen("0x" + "11".repeat(32), 16);

const publicKey = keypair.publicKey();
const { signature: statefulSignature, nextStatefulLeafIndex } =
  keypair.signStatefulRaw("0xdeadbeef");
const statelessSignature = keypair.signStatelessRaw("0xdeadbeef");
const signingKeySnapshot = keypair.exportSigningKeyUnsafe();
// signingKeySnapshot.formatVersion === 1 (required on import)
```

### Keypair lifecycle: `destroy()` and `free()`

`destroy()` is the supported explicit lifecycle method:

- clears in-memory signing and public-key state on the handle (best-effort wipe)
- permanently invalidates the handle
- later method or getter calls throw an `Error` with
  `error.code === "ERR_HANDLE_DESTROYED"`

`free()` is the `wasm-bindgen`-generated finalizer that drops the underlying
wasm object when the JS wrapper is garbage-collected. Prefer `destroy()` when
you still hold a reference and want secrets cleared early. After `destroy()`,
do not call other keypair methods; you may still call `free()` if your
embedding requires an explicit drop, but the handle is already empty.

### WASM Secret Handling

The WASM signer surface is for environments where the surrounding JS context
is trusted.

- `WasmShrincsKeypair` holds live signing-key material in wasm memory while the
  handle exists
- `exportSigningKeyUnsafe()` materializes the full private signing state into JS
- XSS, same-origin script, compromised dependencies, or hostile extensions that
  run in the page can exfiltrate that material

Operational guidance:

- do not use the browser signer in pages that execute untrusted third-party JS
- avoid `exportSigningKeyUnsafe()` except for explicit backup or migration
- call `destroy()` as soon as the keypair is no longer needed
- treat browser memory as a soft boundary, not a hardware-backed secret store

Safe defaults:

- keep the keypair in wasm and use `signStatefulRaw` / `signStatelessRaw` for
  routine operation
- export secret state only at explicit persistence boundaries
- treat `exportSigningKey()` the same as `exportSigningKeyUnsafe()`

`shrincsKeygen(seedHex, maxStatefulSignatures)` rejects seeds shorter than 32
bytes (`ERR_SEED_TOO_SHORT`) and `maxStatefulSignatures` outside `1..=4096`
(`ERR_INVALID_INPUT`). Stateful signing consumes one leaf per signature;
`signStatefulRaw` throws `ERR_STATEFUL_LEAVES_EXHAUSTED` when the budget is
spent. The returned `PublicKey` is assembled from the encoded stateful key,
global `pk_seed`, and `hypertree_root`, then committed with the same
`components/public_key.rs` logic used by verifier-side commitment and rotation
checks.

### Account exports

- `new WasmShrincsAccount(owner, chainId, contractAddress, publicKeyCommitment)`
- `snapshot()`
- `verifyStatefulAction(...)`
- `verifyStatelessAction(...)`
- `rotateToFreshKey(...)`
- `rotateFullKey(...)`
- `setStatefulPolicyMonotonicIndex(...)`
- `setStatefulPolicyRecoveryRotation(...)`
- `setStatefulPolicyLeafBitmap(...)`
- `enterRecoveryMode(...)`

Canonical message helpers:

- `shrincsStatefulActionMessageHash(...)`
- `shrincsStatelessActionMessageHash(...)`
- `shrincsStatefulRotationMessageHash(...)`
- `shrincsFullRotationMessageHash(...)`

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const keypair = wasm.shrincsKeygen("0x" + "12".repeat(32), 8);
const publicKey = keypair.publicKey();

const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

account.setStatefulPolicyRecoveryRotation(owner);
account.enterRecoveryMode(owner);

console.log(account.snapshot());
```

Stateful action verification:

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);
const actionType = "0x" + "44".repeat(32);
const payloadHash = "0x" + "55".repeat(32);

const keypair = wasm.shrincsKeygen("0x" + "00".repeat(32), 8);
const publicKey = keypair.publicKey();
const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

const snapshot = account.snapshot();
const message = wasm.shrincsStatefulActionMessageHash(
  publicKey.publicKeyCommitment,
  {
    domainSeparator: snapshot.domainSeparator,
    nonce: snapshot.nonce,
    keyVersion: snapshot.keyVersion,
    actionType,
    payloadHash,
  },
);
const { signature } = keypair.signStatefulRaw(message);
const ok = account.verifyStatefulAction(
  publicKey,
  actionType,
  payloadHash,
  signature,
);

console.log({ ok, snapshot: account.snapshot() });
```

Stateless action verification:

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);
const actionType = "0x" + "66".repeat(32);
const payloadHash = "0x" + "77".repeat(32);

const keypair = wasm.shrincsKeygen("0x" + "ab".repeat(32), 8);
const publicKey = keypair.publicKey();
const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

const snapshot = account.snapshot();
const message = wasm.shrincsStatelessActionMessageHash(
  publicKey.publicKeyCommitment,
  {
    domainSeparator: snapshot.domainSeparator,
    nonce: snapshot.nonce,
    keyVersion: snapshot.keyVersion,
    actionType,
    payloadHash,
  },
);
const signature = keypair.signStatelessRaw(message);
const ok = account.verifyStatelessAction(
  publicKey,
  actionType,
  payloadHash,
  signature,
);

console.log({ ok, snapshot: account.snapshot() });
```

Stateful-only rotation:

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";
import { concat, getBytes, keccak256, toUtf8Bytes } from "ethers";

function statefulOnlyTargetCommitment(
  nextStatefulPublicKey: string,
  currentPublicKey: { pkSeed: string; hypertreeRoot: string },
) {
  return keccak256(
    concat([
      toUtf8Bytes("shrincs-public-key"),
      getBytes(nextStatefulPublicKey),
      getBytes(currentPublicKey.pkSeed),
      getBytes(currentPublicKey.hypertreeRoot),
    ]),
  );
}

const wasm = await loadShrincsWasm();
const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const currentKeypair = wasm.shrincsKeygen("0x" + "11".repeat(32), 8);
const nextKeypair = wasm.shrincsKeygen("0x" + "22".repeat(32), 16);

const currentPublicKey = currentKeypair.publicKey();
const nextPublicKey = nextKeypair.publicKey();
const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  currentPublicKey.publicKeyCommitment,
);

account.setStatefulPolicyRecoveryRotation(owner);
account.enterRecoveryMode(owner);

const snapshot = account.snapshot();
const nextStatefulTarget = {
  statefulPublicKey: nextPublicKey.statefulPublicKey,
  publicKeyCommitment: statefulOnlyTargetCommitment(
    nextPublicKey.statefulPublicKey,
    currentPublicKey,
  ),
};

const recoveryMessage = wasm.shrincsStatefulRotationMessageHash(
  currentPublicKey.publicKeyCommitment,
  currentPublicKey,
  {
    domainSeparator: snapshot.domainSeparator,
    nonce: snapshot.nonce,
    keyVersion: snapshot.keyVersion,
  },
  nextStatefulTarget,
);
const recoverySignature = currentKeypair.signStatelessRaw(recoveryMessage);
const rotated = account.rotateToFreshKey(
  currentPublicKey,
  recoverySignature,
  nextStatefulTarget,
);

console.log({ rotated, snapshot: account.snapshot() });
```

Full rotation:

```ts
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

const wasm = await loadShrincsWasm();
const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const currentKeypair = wasm.shrincsKeygen("0x" + "aa".repeat(32), 8);
const nextKeypair = wasm.shrincsKeygen("0x" + "bb".repeat(32), 16);

const currentPublicKey = currentKeypair.publicKey();
const nextPublicKey = nextKeypair.publicKey();
const account = new wasm.WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  currentPublicKey.publicKeyCommitment,
);

account.setStatefulPolicyRecoveryRotation(owner);
account.enterRecoveryMode(owner);

const snapshot = account.snapshot();
const nextFullTarget = {
  statefulPublicKey: nextPublicKey.statefulPublicKey,
  publicKeyCommitment: nextPublicKey.publicKeyCommitment,
  pkSeed: nextPublicKey.pkSeed,
  hypertreeRoot: nextPublicKey.hypertreeRoot,
};

const recoveryMessage = wasm.shrincsFullRotationMessageHash(
  currentPublicKey.publicKeyCommitment,
  currentPublicKey,
  {
    domainSeparator: snapshot.domainSeparator,
    nonce: snapshot.nonce,
    keyVersion: snapshot.keyVersion,
  },
  nextFullTarget,
);
const recoverySignature = currentKeypair.signStatelessRaw(recoveryMessage);
const rotated = account.rotateFullKey(
  currentPublicKey,
  recoverySignature,
  nextFullTarget,
);

console.log({ rotated, snapshot: account.snapshot() });
```

Canonical end-to-end pattern:

- read `domainSeparator`, `nonce`, and `keyVersion` from `account.snapshot()`
- hash with the matching message helper
- sign with `signStatefulRaw` or `signStatelessRaw`
- submit through the matching account verify or rotate method

### Object shapes

Names match the generated Tsify types re-exported from
`@quip.network/hashsigs-wasm` (see `ts/src/index.ts`). Fields are camelCase.

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

Signing key snapshot from `exportSigningKeyUnsafe()` /
`exportSigningKey()` (`ShrincsExportedSigningKey`):

```ts
type ShrincsExportedSigningKey = {
  formatVersion: 1; // required; import rejects other versions
  statefulSkSeed: string;
  statefulPrfSeed: string;
  statefulPkSeed: string;
  statefulRoot: string;
  maxStatefulSignatures: number;
  nextStatefulLeafIndex: number;
  statelessSkSeed: string;
  statelessPrfSeed: string;
  pkSeed: string;
  hypertreeRoot: string;
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
