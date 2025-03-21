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

Run Solana program tests:

```bash
cd solana
cargo test-sbf
```

For test output and backtrace:

```
RUST_BACKTRACE=1 cargo test-sbf -- --no-capture 2>&1
```

Show compute units only:

```
RUST_BACKTRACE=1 cargo test-sbf -- --no-capture 2>&1 | grep "compute units:"
```

## Development Requirements

- Rust 1.70 or later
- Solana CLI tools (for Solana program development)
  ```bash
  sh -c "$(curl -sSfL https://release.solana.com/v2.2/install)"
  ```

## Project Structure

```
.
├── src/           # Core WOTS+ implementation
├── solana/        # Solana program implementation
└── tests/         # Test vectors and unit tests
```

## License

AGPL-3.0, see COPYING
