# SHRINCS definitions review packet

This packet asks a cryptographer outside the proof team to review three files.
Gate G1 of the Track A plan needs the review. The files are:

- `spec/Spec.eca`: the scheme, transcribed from the Rust code of `hashsigs-rs`.
- `spec/Shrincs.ec`: the constants of the profile `shrincs-256s-keccak`.
- `spec/Games.ec`: the security game.

Read `docs/freeze-note.md` first. It states the target, the tests, and the gaps
in the tests.

## What the known-answer tests already show

The 265 known-answer cases show that the operators of `spec/Spec.eca` compute
what the Rust code computes on those inputs. They do not show that the
transcription is right on other inputs, or that the game states the right
security notion. The review covers both.

## Questions for the reviewer

1. **The verifiers.** `shrincs_verify` and `shrincs_verify_stateless` are the
   two byte-level entry points that a contract calls. Do they reject every
   input that the Rust verifiers reject? Pay attention to the decoders and to
   the commitment checks.
2. **The adversary's view.** The adversary gets the 32-byte commitment and the
   public-key bundle. The bundle is public in every deployment, because each
   envelope carries it.
3. **The signing oracle.** One oracle takes a path and a 32-byte hash.
   - The stateful path signs at the leaf counter of the key, then moves the
     counter on. A key whose counter is past its budget signs nothing.
   - The stateless path signs while fewer than `STATELESS_SIGNATURE_LIMIT`
     stateless signatures exist. The profile sets 1,048,576.
     This cap is the query bound of the profile. The library signer and the
     two byte verifiers do not count signatures, so the game bounds the
     adversary and not the code.
4. **Freshness.** A forgery wins on a path for a hash that the oracle did not
   sign on that path. A stateful signature and a stateless signature on the
   same hash are different, because the two message hashes carry different
   operation tags. Is freshness per path the notion that a contract needs?
5. **The typed action paths.** `verify_stateful` and `verify_stateless` with an
   `ActionContext` are in the specification, but not in the game. The game
   covers the raw-hash paths of `VerifierInterface`. Should the game also give
   the adversary the action paths?
6. **Key generation.** The game samples 32 uniform bytes of seed material and
   calls `shrincs_keygen` with a budget that the game takes as input. Every
   other secret derives from the seed through `derive32`. Accepted budgets
   are integers from 1 through 4096. The model rejects negative budgets,
   which are outside the Rust signer's `u32` input domain.
7. **The abstract hash.** The game keeps `keccak256` abstract. The proof
   after WS0 chooses between a random oracle and a list of hash properties. The
   game does not fix that choice.

`spec/GamesSanity.ec` holds six lemmas that pin the bookkeeping of the game:
an exhausted key signs nothing, a signature moves the counter by one, the
oracle never uses a leaf twice, the oracle keeps the stateless budget, the
stateful verifier never accepts the empty envelope, and an adversary that
returns the empty envelope never wins.

`spec/CounterInvariant.ec` strengthens those bookkeeping results. Key
generation establishes `valid_counter_state`: a valid budget and a counter
from 1 through `budget + 1`, with the final value denoting exhaustion.
Oracle initialization and both signing modes preserve its conjunction with
`one_time` and a nonnegative, bounded stateless count. Failed calls change
none of the persistent oracle state. The tightened key-generation guard
agrees with the previous definition on every unsigned 32-bit budget. These
lemmas do not establish key-byte well-formedness or cryptographic security.

## How to record a sign-off

1. Write `docs/review/SIGNOFF.md` with your name, the date, the commit that you
   reviewed, and your findings.
2. Record the hashes of the three reviewed files:

   ```sh
   cd proofs/easycrypt
   sha256sum spec/Spec.eca spec/Shrincs.ec spec/Games.ec > docs/review/SIGNOFF.sha256
   ```

3. Commit both files. From then on, `make docker-audit` fails if one of the
   three files changes, until a new sign-off replaces the hashes.
