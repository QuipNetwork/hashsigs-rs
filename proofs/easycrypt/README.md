# EasyCrypt specification of SHRINCS

This directory holds an EasyCrypt specification of the SHRINCS scheme that
the Rust code of `hashsigs-rs` runs, at the profile `shrincs-256s-keccak`. It
also holds known-answer tests that EasyCrypt replays against the Rust code of
this crate. `docs/freeze-note.md` states the target and the limits of the
tests.

CI does not run anything in this directory. Run the gates on a machine with
Docker and the Rust toolchain of the crate:

```sh
make -C proofs/easycrypt docker-check     # every theory and every replay
make -C proofs/easycrypt docker-audit     # vectors, admits, axioms, sign-off
make -C proofs/easycrypt docker-mutants   # each spec mutant fails a replay
```

The generator runs on the host with `cargo`. EasyCrypt runs in the image
`ghcr.io/easycrypt/ec-test-box` at release `r2026.02`.

## Layout

| Path | Content |
| --- | --- |
| `spec/Spec.eca` | The scheme over an abstract Keccak-256, with the profile constants as parameters |
| `spec/Shrincs.ec` | The constants of `shrincs-256s-keccak` |
| `spec/Games.ec` | The security game |
| `spec/GamesSanity.ec` | Lemmas that pin the bookkeeping of the game |
| `kat/` | The generator crate, the committed vectors, and the mutation check |
| `audit/` | The audit gate and its self-test |
| `docs/` | The freeze note and the review packet |

The case catalog lives in the crate, in `src/kat/`, behind the cargo feature
`kat-trace`. It needs the private functions of the crate.
