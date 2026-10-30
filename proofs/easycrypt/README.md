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
| `spec/ByteDomain.ec` | Shared byte, fixed-length byte-string, and unsigned-range predicates, with list closure lemmas |
| `spec/ByteEncoding.ec` | Byte/word shape lemmas for integer encoders, ABI words, and `word32` on byte-valid inputs |
| `spec/IntegerEncoding.ec` | General integer round trips, decoded-value bounds, and unsigned 32-/64-bit specializations |
| `spec/Shrincs.ec` | The constants of `shrincs-256s-keccak` |
| `spec/Games.ec` | The security game |
| `spec/GamesSanity.ec` | Lemmas that pin the bookkeeping of the game |
| `spec/CounterInvariant.ec` | Budget/counter initialization and preservation, unsigned-domain compatibility, and unchanged state on failed signing |
| `kat/` | The generator crate, the committed vectors, and the mutation check |
| `audit/` | The audit gate and its self-test |
| `docs/` | The freeze note and the review packet |

The byte predicates make representation premises explicit. `word32`
still checks length only in the integer-list model; its output is proved
byte-valid when its input is byte-valid. `IntegerEncoding.ec` proves
integer round trips with explicit width/range and byte-validity premises.
Complete codecs, key well-formedness, and a 32-byte output contract for
the abstract Keccak operator remain separate obligations.

The case catalog lives in the crate, in `src/kat/`, behind the cargo feature
`kat-trace`. It needs the private functions of the crate.
