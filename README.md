# hashsigs-rs

Rust SHRINCS helpers for the compact/stateless account model.

The supported account shape follows the JARDIN-style split:

- store the stateless `pkSeed` and `hypertreeRoot` directly
- store compact slots in a mapping keyed by `keccak256(subPkSeed || subPkRoot)`
- use stateless signatures for stateless actions, compact-slot registration, compact-slot revocation, and full stateless key rotation
- use compact FORS-C signatures for normal registered-slot actions

There is no global `publicKeyCommitment` in the account model. `PublicKey` is:

```text
PublicKey = (pkSeed, hypertreeRoot)
```

`RotationTarget` is:

```text
RotationTarget = (pkSeed, hypertreeRoot)
```

## Vectors

Generate the Solidity-compatible stateless and compact vectors with:

```sh
cargo test --test generate_shrincs_vectors -- --ignored --nocapture
```

The generated JSON is written to:

```text
tests/test_vectors/shrincs_sphincs_256s_keccak.json
```

It contains only `stateless` and `compact` top-level vector groups.

## Tests

```sh
cargo test
```

The account tests cover the compact replacement for the old stateful account path:

- stateless storage as direct `pkSeed`/`hypertreeRoot`
- stateless-authorized compact slot registration
- compact action verification through a registered slot
- stateless-authorized compact slot revocation
- full stateless key rotation

## WASM

The previous WASM binding surface exposed the removed stateful account path and
the removed global public-key commitment. It is intentionally not exported in
normal builds while the compact/stateless-only binding surface is rebuilt.
