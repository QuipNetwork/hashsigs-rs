# hashsigs-rs

Core Rust hash-signature workspace with:

- `hashsigs-rs`: one crate containing:
  - `wotsplus` primitives
  - `shrincs` signer / verifier primitives
  - `account` scaffolding
  - `wasm`-oriented exports
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

- Rust 1.70 or later
- Solana CLI tools (for Solana program development): https://solana.com/docs/intro/installation

NOTE: if on Mac, do not use brew to install rust and instead use https://www.rust-lang.org/tools/install

## Project Structure

```
.
├── src/
│   ├── wotsplus/  # WOTS+ primitives
│   ├── shrincs/   # SHRINCS signer / verifier primitives
│   ├── account/   # Future account-policy module
│   └── wasm/      # WASM-oriented re-export module
├── solana/        # Solana program implementation
└── tests/         # Test vectors and unit tests
```

## Account Layer Notes

The `account` module is an off-chain Rust policy wrapper that tracks nonce,
key-version, stateful-leaf use, and recovery-mode transitions around the core
SHRINCS primitives. It is intentionally close to the Solidity example account
wrapper, but it is not a literal runtime-equivalent copy.

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
stateful-only recovery-rotation target.

## License

AGPL-3.0, see COPYING
