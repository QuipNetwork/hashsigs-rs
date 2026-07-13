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

The repo now includes a WASM surface in `src/wasm/` for SHRINCS verifier,
signer, and account-wrapper bindings. Build it with `wasm-pack` and the
`wasm-bindings` feature.

Install `wasm-pack` once:

```bash
cargo install wasm-pack
```

Use the helper script from the crate root:

```bash
bin/build-wasm.sh bundler
```

The script accepts these targets:

- `bundler`
- `web`
- `nodejs`

Examples:

```bash
bin/build-wasm.sh bundler
bin/build-wasm.sh web
bin/build-wasm.sh nodejs
```

Generated package output goes to:

```text
pkg/<target>/
```

For example:

```text
pkg/bundler/
pkg/web/
pkg/nodejs/
```

Pass a second argument to change the output base directory:

```bash
bash bin/build-wasm.sh bundler /tmp/hashsigs-wasm
```

That writes to:

```text
/tmp/hashsigs-wasm/bundler/
```

The generated package contains the `.wasm` binary, JS wrapper, and `.d.ts`
files emitted by `wasm-pack`.

Target guidance:

- `bundler`
  - use this for Vite, webpack, Rollup, and most TS application builds
- `web`
  - use this for direct browser loading without a bundler
- `nodejs`
  - use this for server-side Node integrations

Current WASM scope:

- supported now:
  - SHRINCS verifier bindings
  - SHRINCS key generation and raw signing bindings
  - account-layer wrapper bindings
  - hex/JSON-friendly JS entry points
- not implemented yet:
  - published npm package flow
  - documented browser/node packaging examples beyond the raw `wasm-pack` targets
  - CI automation for real wasm-target binding test execution
  - WOTS-specific bindings

## WASM Testing

There are two different WASM-related test layers in this repo:

- native host tests
- real wasm-target binding tests

Native host tests are still useful, but they only validate Rust-side helper
logic and feature-gated conversion code. They do not execute the exported
`wasm-bindgen` bindings inside a real wasm runtime.

To run the real binding-runtime tests, install the wasm target first:

```bash
rustup target add wasm32-unknown-unknown
```

The binding tests do not require browser APIs, so run them in Node:

```bash
wasm-pack test --node --features wasm-bindings
```

If you prefer invoking `cargo test` directly, install a matching
`wasm-bindgen-test-runner` with `wasm-bindgen-cli`, or point Cargo at the runner
binary that `wasm-pack` installed in its cache:

```bash
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=/path/to/wasm-bindgen-test-runner \
  cargo test --features wasm-bindings --target wasm32-unknown-unknown
```

Why both layers exist:

- native host tests
  - faster
  - good for DTO parsing and helper logic
  - do not exercise `JsValue` / `wasm-bindgen` runtime behavior
- wasm-target tests via `wasm-bindgen-test`
  - exercise real exported binding behavior on a wasm target
  - validate JS-facing class/method/runtime conversion paths

If you are changing:

- `WasmShrincsKeypair`
- `WasmShrincsAccount`
- verifier exports in `src/wasm/`

you should treat the wasm-target test run as the authoritative binding check.

## WASM API

The generated package exports three categories of APIs:

- verifier functions
- signer/keypair APIs
- account-wrapper APIs

The current JS-facing data model uses:

- hex strings for byte arrays
- plain JS objects for public keys, signatures, contexts, and rotation targets

### Verifier exports

Available verifier exports:

- `shrincs_verify_stateful_raw(...)`
- `shrincs_verify_stateful_action(...)`
- `shrincs_verify_stateless_raw(...)`
- `shrincs_verify_stateless_action(...)`

Minimal TS example:

```ts
import { shrincs_verify_stateless_action } from "./pkg/bundler/hashsigs_rs";

const ok = shrincs_verify_stateless_action(
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

Available signer exports:

- `shrincsKeygen(...)`
- `WasmShrincsKeypair.publicKey()`
- `WasmShrincsKeypair.destroy()`
- `WasmShrincsKeypair.signStatefulRaw(...)`
- `WasmShrincsKeypair.signStatelessRaw(...)`
- `WasmShrincsKeypair.exportSigningKeyUnsafe()`
- `WasmShrincsKeypair.exportSigningKey()`
  - legacy compatibility alias; new code should prefer the explicit `Unsafe`
    form

Minimal TS example:

```ts
import { shrincsKeygen } from "./pkg/bundler/hashsigs_rs";

const keypair = shrincsKeygen("0x00112233445566778899aabbccddeeff", 16);

const publicKey = keypair.publicKey();
const statefulSignature = keypair.signStatefulRaw("0xdeadbeef");
const statelessSignature = keypair.signStatelessRaw("0xdeadbeef");
const signingKeySnapshot = keypair.exportSigningKeyUnsafe();
```

### WASM Secret Handling

The WASM signer surface is suitable only for environments where the surrounding
JS context is trusted.

Important implications:

- `WasmShrincsKeypair` holds live signing-key material in wasm memory for as
  long as the handle exists
- `exportSigningKeyUnsafe()` materializes the full private signing state into JS
- any XSS, malicious same-origin script, compromised dependency, or hostile
  browser extension with access to the page context can exfiltrate that key
  material

Operational guidance:

- do not use the browser signer in pages that execute untrusted third-party JS
- avoid calling `exportSigningKeyUnsafe()` except for explicit backup /
  migration
  flows
- call `destroy()` as soon as the keypair is no longer needed; this performs a
  best-effort early wipe and permanently invalidates the handle
- still assume browser memory is a soft boundary, not a hardware-backed secret
  store

Safe-default guidance:

- keep the keypair live in wasm and use `signStatefulRaw(...)` /
  `signStatelessRaw(...)` for routine operation
- export secret state only at explicit persistence boundaries such as backup,
  migration, or a durable post-signature checkpoint
- treat `exportSigningKey()` exactly like `exportSigningKeyUnsafe()`; it exists
  only as a legacy alias for compatibility

`shrincsKeygen(seedHex, maxStatefulSignatures)` rejects
`maxStatefulSignatures === 0` and values over `4096`. Stateful signing consumes
one stateful leaf per signature, so `signStatefulRaw(...)` can fail once the
key has used its configured stateful signature budget.

`exportSigningKeyUnsafe()` returns secret material. Treat it as private key
data. `exportSigningKey()` is a legacy alias with the same risk.

### Account exports

Available account exports:

- `new WasmShrincsAccount(...)`
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

Minimal TS example:

```ts
import { WasmShrincsAccount, shrincsKeygen } from "./pkg/bundler/hashsigs_rs";

const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const keypair = shrincsKeygen("0x1234", 8);
const publicKey = keypair.publicKey();

const account = new WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

account.setStatefulPolicyRecoveryRotation(owner);
account.enterRecoveryMode(owner);

console.log(account.snapshot());
```

Stateful action verification example:

```ts
import {
  WasmShrincsAccount,
  shrincsStatefulActionMessageHash,
  shrincsKeygen,
} from "./pkg/bundler/hashsigs_rs";

const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);
const actionType = "0x" + "44".repeat(32);
const payloadHash = "0x" + "55".repeat(32);

const keypair = shrincsKeygen("0x0011223344", 8);
const publicKey = keypair.publicKey();
const account = new WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

const snapshot = account.snapshot();
const message = shrincsStatefulActionMessageHash(
  publicKey.publicKeyCommitment,
  {
    domainSeparator: snapshot.domainSeparator,
    nonce: snapshot.nonce,
    keyVersion: snapshot.keyVersion,
    actionType,
    payloadHash,
  },
);
const signature = keypair.signStatefulRaw(message);
const ok = account.verifyStatefulAction(
  publicKey,
  actionType,
  payloadHash,
  signature,
);

console.log({ ok, snapshot: account.snapshot() });
```

Stateless action verification example:

```ts
import {
  WasmShrincsAccount,
  shrincsStatelessActionMessageHash,
  shrincsKeygen,
} from "./pkg/bundler/hashsigs_rs";

const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);
const actionType = "0x" + "66".repeat(32);
const payloadHash = "0x" + "77".repeat(32);

const keypair = shrincsKeygen("0xabcdef", 8);
const publicKey = keypair.publicKey();
const account = new WasmShrincsAccount(
  owner,
  chainId,
  contractAddress,
  publicKey.publicKeyCommitment,
);

const snapshot = account.snapshot();
const message = shrincsStatelessActionMessageHash(
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

Stateful-only rotation example:

```ts
import {
  WasmShrincsAccount,
  shrincsStatefulRotationMessageHash,
  shrincsKeygen,
} from "./pkg/bundler/hashsigs_rs";
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

const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const currentKeypair = shrincsKeygen("0x1111", 8);
const nextKeypair = shrincsKeygen("0x2222", 16);

const currentPublicKey = currentKeypair.publicKey();
const nextPublicKey = nextKeypair.publicKey();
const account = new WasmShrincsAccount(
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

const recoveryMessage = shrincsStatefulRotationMessageHash(
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

Full rotation example:

```ts
import {
  WasmShrincsAccount,
  shrincsFullRotationMessageHash,
  shrincsKeygen,
} from "./pkg/bundler/hashsigs_rs";

const owner = "0x" + "11".repeat(32);
const chainId = "0x" + "22".repeat(32);
const contractAddress = "0x" + "33".repeat(20);

const currentKeypair = shrincsKeygen("0xaaaa", 8);
const nextKeypair = shrincsKeygen("0xbbbb", 16);

const currentPublicKey = currentKeypair.publicKey();
const nextPublicKey = nextKeypair.publicKey();
const account = new WasmShrincsAccount(
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

const recoveryMessage = shrincsFullRotationMessageHash(
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

The examples above are canonical end-to-end flows:

- the account snapshot exposes `domainSeparator`, `nonce`, and `keyVersion`
- derive the message bytes with the exported helper that matches the intended wrapper path
- sign those exact bytes with `signStatefulRaw(...)` or `signStatelessRaw(...)`
- submit the signature through the corresponding account verification or rotation method

### Object shapes

The current JS object shapes follow camelCase field names.

Public key:

```ts
type WasmPublicKey = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
  pkSeed: string;
  hypertreeRoot: string;
};
```

Action context:

```ts
type WasmActionContext = {
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
  actionType: string;
  payloadHash: string;
};
```

Account snapshot:

```ts
type WasmAccountSnapshot = {
  currentShrincsPublicKey: string;
  owner: string;
  chainId: string;
  contractAddress: string;
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
  statelessSignaturesUsed: number;
  statefulPolicy: string;
  nextStatefulLeafIndex: number;
  recoveryMode: boolean;
};
```

Rotation context:

```ts
type WasmRotationContext = {
  domainSeparator: string;
  nonce: string;
  keyVersion: string;
};
```

Stateful rotation target:

```ts
type WasmStatefulRotationTarget = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
};
```

Full rotation target:

```ts
type WasmRotationTarget = {
  statefulPublicKey: string;
  publicKeyCommitment: string;
  pkSeed: string;
  hypertreeRoot: string;
};
```

Stateful signature:

```ts
type WasmStatefulSignature = {
  randomizer: string;
  counter: number;
  chains: string[];
  authPath: string[];
};
```

Stateless signature:

```ts
type WasmForsEntry = {
  secretLeaf: string;
  authPath: string[];
};

type WasmForsSignature = {
  randomizer: string;
  counter: number;
  entries: WasmForsEntry[];
};

type WasmWotsCSignature = {
  randomizer: string;
  counter: number;
  chains: string[];
};

type WasmHypertreeLayerSignature = {
  treeIndex: string;
  leafIndex: number;
  wotsCPkHash: string;
  wotsCSignature: WasmWotsCSignature;
  authPath: string[];
};

type WasmStatelessSignature = {
  fors: WasmForsSignature;
  hypertree: WasmHypertreeLayerSignature[];
};
```

Signing key snapshot returned by `exportSigningKeyUnsafe()`:

```ts
type WasmSigningKey = {
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

Run specific test vectors:

```bash
cargo test test_wotsplus_keccak256_vectors
```

Generate SHRINCS vectors for the Solidity verifier:

```bash
cargo test --test generate_shrincs_vectors -- --ignored --nocapture
```

The generator writes the SHRINCS vector JSON inside this Rust repository:

```text
tests/test_vectors/shrincs_sphincs_256s_keccak.json
```

SHRINCS public keys use one stateless `pkSeed` and one `hypertreeRoot`, matching
the SPHINCS+/FIPS-style `PK = (PK.seed, PK.root)` abstraction for the stateless
path, while the full hybrid bundle stays bound together by
`public_key_commitment`.

To use those vectors with the Solidity verifier tests, copy the generated file
into the Solidity repository's expected fixture path:

```bash
# copy the generated JSON to the Solidity repository's expected fixture path
cp tests/test_vectors/shrincs_sphincs_256s_keccak.json \
  /path/to/hashsigs-solidity/test/test_vectors/shrincs_sphincs_256s_keccak.json
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

Then run the Rust-side cross-check. The tests are `#[ignore]`d because the
fixture is copied in manually, so pass `--ignored` explicitly:

```bash
cargo test --test solidity_account_vectors -- --ignored
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
│   └── build-wasm.sh  # wasm-pack helper for bundler/web/nodejs builds
├── src/
│   ├── wotsplus/  # WOTS+ primitives
│   ├── shrincs/   # SHRINCS signer / verifier primitives
│   ├── account/   # Rust account-policy wrapper
│   └── wasm/      # Verifier / signer / account wasm-bindgen surface
├── solana/        # Solana program implementation
└── tests/         # Test vectors and unit tests
```

## Account Layer Notes

The `account` module is an off-chain Rust policy wrapper that tracks nonce,
key-version, stateful-leaf use, and recovery-mode transitions around the core
SHRINCS primitives. It is intentionally close to the Solidity example account
wrapper, but it is not a literal runtime-equivalent copy.

The Rust account wrapper now follows the same security policy model as the
Solidity example wrapper:

- stateful policy changes are frozen after the first successful stateful use in a key epoch
- `RecoveryRotation` disables the stateful path for the whole recovery-policy epoch
- `rotateToFreshKey(...)` preserves stateless usage accounting because the stateless key is unchanged
- `rotateFullKey(...)` resets stateless usage accounting only when the stateless key changes

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
stateful-only recovery-rotation target. It also mirrors the Solidity account
wrapper's hardened policy/accounting behavior:

- policy changes must be chosen before the first successful stateful signature in a key epoch
- selecting `RecoveryRotation` blocks the stateful path immediately; `enterRecoveryMode(...)`
  then permits stateless action verification and stateless recovery rotations
- stateful-only rotation consumes one stateless recovery use and carries that counter forward
- full-key rotation consumes one stateless recovery use under the old key and then resets the
  counter for the newly installed stateless key

## License

AGPL-3.0, see COPYING
