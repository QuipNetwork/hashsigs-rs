# hashsigs-rs

A Rust implementation of WOTS+ (Winternitz One-Time Signature) scheme, with Solana program support.

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
├── src/           # Core WOTS+ implementation
├── solana/        # Solana program implementation
└── tests/         # Test vectors and unit tests
```

## License

AGPL-3.0, see COPYING
