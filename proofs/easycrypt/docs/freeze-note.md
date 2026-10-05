# SHRINCS proof target freeze note

This note fixes the target of the EasyCrypt development in `proofs/easycrypt`.
It records what the specification covers, how the known-answer tests tie it to
the Rust code, and what the tests do not cover.

## The target

The target is the SHRINCS scheme of this crate, `hashsigs-rs`, at the profile
`shrincs-256s-keccak` (`src/profiles/p256s.rs`). The draft BIP of the SHRINCS
repository at commit `a5891ec` is a different scheme. The two schemes share no
bytes.

| Part | Rust source | Specification |
| --- | --- | --- |
| UXMSS over WOTS-C leaves, the stateful path | `src/shrincs/uxmss.rs` | `spec/Spec.eca`, section UXMSS |
| SPHINCS+C with FORS-C and a WOTS-C hypertree, the stateless path | `src/sphincs_plus_c/` | sections FORS-C, The hypertree, SPHINCS+C |
| Commitment, message hashes, keys, signing, verification | `src/shrincs/` | section SHRINCS |
| Solidity ABI encoding and decoding | `src/abi.rs` and the wire types | sections ABI encoding, ABI decoding |

`spec/Shrincs.ec` fixes the profile constants. `spec/Games.ec` defines the
security game. Every hash of this profile is Keccak-256, and the specification
keeps it abstract as `keccak256`.

## Toolchain

- EasyCrypt `r2026.02` with `Alt-Ergo` 2.6.0 and `Z3` 4.13.4, in the image
  `ghcr.io/easycrypt/ec-test-box@sha256:bf1a13e73d7fe18fccdcc91d1532c1a5a17cfc3a6a2a34619248c4f2710d0bb3`.
- The Rust toolchain of the crate, for the generator.

CI does not run anything in this directory. Run the gates with
`make -C proofs/easycrypt docker-check docker-audit docker-mutants`.

## Known-answer tests

The cargo feature `kat-trace` records every Keccak call of the crate while a
case runs. The generator writes each group of cases twice, as JSON in
`kat/vectors/` and as an EasyCrypt file in `build/kat/ec/`. In the EasyCrypt
file, a lookup table of the recorded calls takes the place of `keccak256` in a
clone of the specification. EasyCrypt proves each case by evaluation. A case holds only if the
specification makes the calls that the Rust code made and combines the results
in the same way.

The tree has 14 groups with 265 cases.

| Group | Profile | Cases | What it replays |
| --- | --- | --- | --- |
| `helpers` | 256s | 34 | Byte helpers, `derive32`, and `PROFILE_ID = keccak256(PROFILE_NAME)` |
| `abi` | 256s | 38 | The ABI encoders and the encoding of every wire type |
| `addresses` | 256s | 21 | The address words |
| `wots_c` | 256s | 23 | WOTS-C for the stateful and the stateless binding |
| `uxmss` | 256s | 21 | The stateful tree at a budget of 4 leaves |
| `fors` | 256s | 14 | FORS-C verification of a full-size signature |
| `hypertree` | 256s | 10 | Hypertree and SPHINCS+C verification of a full-size signature |
| `envelopes` | 256s | 20 | The stateful decoders on canonical input and on malformed input |
| `shrincs` | 256s | 24 | Commitment, message hashes, stateful signing, both byte-level verifiers |
| `golden` | 256s | 11 | The committed vector `tests/test_vectors/shrincs_sphincs_256s_keccak.json.gz` |
| `toy_fors` | reduced | 5 | FORS-C signing |
| `toy_sphincs` | reduced | 12 | Hypertree and SPHINCS+C key generation and signing |
| `toy_envelopes` | reduced | 22 | The stateless decoders on canonical input and on malformed input |
| `toy_shrincs` | reduced | 10 | SHRINCS key generation, stateless signing, the action paths |

The reduced profile in `src/kat/toy.rs` has a hypertree of two layers of
height 2, three FORS trees of height 2, and eight WOTS-C chains. It exists because one
replayed hash call costs about 6 to 25 milliseconds. Full-size stateless key
generation needs about 280,000 Keccak calls, and one full-size stateless
signature needs about 3 million.

## What the tests do not cover

- **Full-size stateless signing and key generation.** The reduced profile
  replays both. The full profile replays only verification.
- **The valid path of the byte-level stateless verifier at full size.**
  Decoding a 55-kilobyte envelope by evaluation overflows the stack, and with
  an unlimited stack it ran for more than 10 minutes. The group `shrincs`
  replays the paths that reject early. The parts of the valid path replay on
  their own: the decoders (`toy_envelopes`), `prepare_stateless_delegation`
  (`toy_shrincs`), the message hash (`shrincs`), and SPHINCS+C verification
  (`hypertree`, `golden`).
- **The final tree index check of the hypertree verifier.** For this profile
  and for the reduced one, the FORS digest gives a tree index that the layers
  always shift to zero. The check cannot fail on a signature that reaches it.
  The case with a changed tree index fails at the WOTS-C check of layer 0.
- **The leaf bound of the UXMSS verifier.** A path longer than the budget also
  fails the WOTS-C check, so the cases cannot tell the bound check from the
  later checks.
- **The features `parallel` and `solana`.** These features change how the
  crate computes, not what it computes. The generator builds neither.
- **Key import and reset.** `Keys::import` and `Keys::reset` are not
  specified.

## Conventions of the specification

- Every operator has the name and the parameter order of the Rust function
  that it transcribes, and its comment names that function.
- A decoder follows the offsets as `AbiReader` does and ends with the
  re-encoding check of the crate. That check implies the other checks of
  `AbiReader`.
- A guard before an `oget` is a nested `if`, not a conjunction. Evaluation
  reduces both sides of a conjunction, and `oget None` then gives a term that
  makes a table lookup expand every branch of the table.
- The Rust treehash streams the leaves through a stack. The specification
  builds the tree level by level. Both give the same nodes.

## Gates

Results on 2026-10-05, on a machine with 32 cores:

| Gate | Command | Result |
| --- | --- | --- |
| Proof check | `make docker-check EC_JOBS=16` | 20 of 20 files check, in 4 minutes 37 seconds. The slowest file is `Kat_envelopes.ec`, at 4 minutes 33 seconds. |
| Audit | `make docker-audit` | The vectors match the generator. No admitted proof. 80 axioms, all from the EasyCrypt standard library and on the allowlist. No sign-off yet. |
| Mutation check | `make docker-mutants EC_JOBS=16` | 24 of 24 mutants fail a replay, in about 5 minutes. |
