# EasyCrypt specification of SHRINCS

This directory holds an EasyCrypt specification of the SHRINCS scheme that
the Rust code of `hashsigs-rs` runs, at the profile `shrincs-256s-keccak`. It also holds
known-answer tests that EasyCrypt replays against the Rust code of this crate.

CI does not run anything in this directory. Run the gates on a machine with
Docker and the Rust toolchain of the crate:

```sh
make -C proofs/easycrypt docker-check
```

The generator runs on the host with `cargo`. EasyCrypt runs in the image
`ghcr.io/easycrypt/ec-test-box` at release `r2026.02`.
