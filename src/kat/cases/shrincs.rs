// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Groups `shrincs`, `toy_shrincs`, and `golden`: the commitment, the
//! message hashes, key generation, signing, and the verifiers of the hybrid
//! key. The full profile replays the byte-level verifiers that a contract
//! calls. The reduced profile replays key generation and stateless signing.
//! The group `golden` replays the committed golden vector of the crate.

use super::wire::{public_key, stateful_sig, stateless_sig};
use super::{full_stateless, grind_failed, label_bytes, label_word, Full};
use crate::kat::group::Group;
use crate::kat::toy::{Toy, TOY_CHAINS, TOY_LAYERS};
use crate::kat::value::Value;
use crate::shrincs::dispatch_access as dispatch;
use crate::shrincs::signer::ShrincsSigner;
use crate::shrincs::{encode_stateless_envelope, prepare_stateless_delegation};
use crate::shrincs::{
    sign as shrincs_sign, ActionContext, Commitment, Keys, PublicKey, ShrincsVerifier,
    ShrincsVerifierExt,
};
use crate::sphincs_plus_c::{self, Signature as StatelessSignature};
use crate::verifier::{VerifierInterface, VerifyOutcome};

const MAX: u32 = 4;

pub(crate) fn keys_value(k: &Keys) -> Value {
    let sl = k.stateless();
    let sf = k.stateful();
    Value::Record(vec![
        (
            "ks_sl_sk_seed",
            Value::bytes(sl.secret().as_sk_seed().as_bytes()),
        ),
        (
            "ks_sl_prf_seed",
            Value::bytes(sl.secret().as_prf_seed().as_bytes()),
        ),
        (
            "ks_sl_pk_seed",
            Value::bytes(sl.public_key.pk_seed.as_bytes()),
        ),
        ("ks_sl_root", Value::bytes(sl.public_key.root.as_bytes())),
        (
            "ks_sf_sk_seed",
            Value::bytes(sf.secret().as_sk_seed().as_bytes()),
        ),
        (
            "ks_sf_prf_seed",
            Value::bytes(sf.secret().as_prf_seed().as_bytes()),
        ),
        (
            "ks_sf_pk_seed",
            Value::bytes(sf.public_key().pk_seed.as_bytes()),
        ),
        ("ks_sf_root", Value::bytes(sf.public_key().root.as_bytes())),
        (
            "ks_max_signatures",
            Value::int(sf.public_key().max_signatures),
        ),
        ("ks_next_leaf", Value::int(sf.next_leaf_index())),
    ])
}

fn context_value(c: &ActionContext) -> Value {
    Value::Record(vec![
        ("ac_domain_separator", Value::bytes(&c.domain_separator)),
        ("ac_nonce", Value::bytes(&c.nonce)),
        ("ac_key_version", Value::bytes(&c.key_version)),
        ("ac_action_type", Value::bytes(&c.action_type)),
        ("ac_payload_hash", Value::bytes(&c.payload_hash)),
    ])
}

fn context(label: &str) -> ActionContext {
    ActionContext {
        domain_separator: label_word(&format!("{label}/domain")),
        nonce: [0; 32],
        key_version: label_word(&format!("{label}/version")),
        action_type: label_word(&format!("{label}/type")),
        payload_hash: label_word(&format!("{label}/payload")),
    }
}

fn outcome(o: &VerifyOutcome) -> Value {
    Value::Ctor(
        match o {
            VerifyOutcome::Valid => "Valid",
            VerifyOutcome::Invalid => "Invalid",
            VerifyOutcome::Malformed => "Malformed",
        },
        vec![],
    )
}

fn commitment(pk: &PublicKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.public_key_commitment);
    out
}

fn verify_stateful_bytes(
    g: &mut Group,
    key: &[u8],
    hash: [u8; 32],
    envelope: &[u8],
) -> VerifyOutcome {
    g.call(
        "shrincs_verify",
        vec![
            Value::bytes(key),
            Value::bytes(&hash),
            Value::bytes(envelope),
        ],
        || ShrincsVerifier::new().verify(key, &hash, envelope),
        outcome,
    )
}

fn verify_stateless_bytes(
    g: &mut Group,
    key: &[u8],
    hash: [u8; 32],
    envelope: &[u8],
) -> VerifyOutcome {
    g.call(
        "shrincs_verify_stateless",
        vec![
            Value::bytes(key),
            Value::bytes(&hash),
            Value::bytes(envelope),
        ],
        || ShrincsVerifier::new().verify_stateless_signature(key, &hash, envelope),
        outcome,
    )
}

pub(super) fn group() -> Group {
    let mut g = Group::new::<Full>("shrincs");
    let word = |r: &[u8; 32]| Value::bytes(r);
    let (stateless_key, _, _) = full_stateless();
    let seed = label_bytes("shrincs/seed", 48);
    let sl_args = Value::Tuple(vec![
        Value::bytes(stateless_key.secret().as_sk_seed().as_bytes()),
        Value::bytes(stateless_key.secret().as_prf_seed().as_bytes()),
        Value::bytes(stateless_key.public_key.pk_seed.as_bytes()),
        Value::bytes(stateless_key.public_key.root.as_bytes()),
    ]);
    let (keys, pk) = g.call(
        "build_keys",
        vec![Value::bytes(&seed), Value::int(MAX), sl_args],
        || ShrincsSigner::build_keys::<Full, 64>(&seed, MAX, stateless_key.clone()),
        |(k, p)| Value::Tuple(vec![keys_value(k), public_key(p)]),
    );
    let expected = commitment(&pk);
    g.call(
        "commitment_of",
        vec![
            Value::bytes(&pk.stateful_public_key),
            Value::bytes(&pk.pk_seed),
            Value::bytes(&pk.hypertree_root),
        ],
        || {
            *Commitment::of::<Full>(
                &pk.stateful_public_key,
                stateless_key.public_key.pk_seed.as_bytes(),
                stateless_key.public_key.root.as_bytes(),
            )
            .as_bytes()
        },
        word,
    );
    let hash = label_word("shrincs/hash");
    for (operator, f) in [
        (
            "stateful_raw_message_hash",
            dispatch::stateful_raw_message_hash::<Full> as fn([u8; 32], [u8; 32]) -> [u8; 32],
        ),
        (
            "stateless_raw_message_hash",
            dispatch::stateless_raw_message_hash::<Full>,
        ),
    ] {
        g.call(
            operator,
            vec![Value::bytes(&expected), Value::bytes(&hash)],
            || f(expected, hash),
            word,
        );
    }
    let ctx = context("shrincs/ctx");
    for (operator, f) in [
        (
            "stateful_action_message_hash",
            dispatch::stateful_action_message_hash::<Full>
                as fn([u8; 32], &ActionContext) -> [u8; 32],
        ),
        (
            "stateless_action_message_hash",
            dispatch::stateless_action_message_hash::<Full>,
        ),
    ] {
        g.call(
            operator,
            vec![Value::bytes(&expected), context_value(&ctx)],
            || f(expected, &ctx),
            word,
        );
    }
    let mut zero_domain = ctx;
    zero_domain.domain_separator = [0; 32];
    for c in [ctx, zero_domain] {
        g.call(
            "valid_action_context",
            vec![context_value(&c)],
            || dispatch::valid_action_context(&c),
            |r| Value::Bool(*r),
        );
    }
    let mut other_pk = pk.clone();
    other_pk.stateful_public_key[0] ^= 1;
    for p in [&pk, &other_pk] {
        g.call(
            "matches_expected_public_key_commitment",
            vec![public_key(p), Value::bytes(&expected)],
            || dispatch::matches_expected_public_key_commitment::<Full>(p, expected),
            |r| Value::Bool(*r),
        );
        g.call(
            "valid_public_key",
            vec![public_key(p)],
            || dispatch::valid_public_key::<Full>(p),
            |r| Value::Bool(*r),
        );
    }

    // Stateful signing with the leaf counter, through the envelope.
    let mut signer = keys.clone();
    let mut envelopes = Vec::new();
    for _ in 0..2 {
        let before = signer.clone();
        let envelope = g.call(
            "shrincs_sign",
            vec![keys_value(&before), Value::bytes(&hash)],
            || shrincs_sign::<Full, 64>(&mut signer, &hash).map(|e| (e, signer.clone())),
            |r| {
                Value::opt(
                    r.as_ref()
                        .map(|(e, k)| Value::Tuple(vec![Value::bytes(e), keys_value(k)])),
                )
            },
        );
        envelopes.extend(envelope.map(|(e, _)| e));
    }
    // An exhausted key signs nothing.
    let exhausted = Keys::from_bytes::<Full>(&{
        let mut bytes = keys.to_bytes();
        bytes[132..136].copy_from_slice(&(MAX + 1).to_be_bytes());
        bytes
    })
    .unwrap_or_else(grind_failed);
    let mut exhausted_signer = exhausted.clone();
    g.call(
        "shrincs_sign",
        vec![keys_value(&exhausted), Value::bytes(&hash)],
        || {
            shrincs_sign::<Full, 64>(&mut exhausted_signer, &hash)
                .map(|e| (e, exhausted_signer.clone()))
        },
        |r| {
            Value::opt(
                r.as_ref()
                    .map(|(e, k)| Value::Tuple(vec![Value::bytes(e), keys_value(k)])),
            )
        },
    );

    let envelope = &envelopes[1];
    assert_eq!(
        verify_stateful_bytes(&mut g, &expected, hash, envelope),
        VerifyOutcome::Valid
    );
    verify_stateful_bytes(
        &mut g,
        &expected,
        label_word("shrincs/other-hash"),
        envelope,
    );
    verify_stateful_bytes(&mut g, &expected[..31], hash, envelope);
    let mut flipped = expected;
    flipped[0] ^= 1;
    verify_stateful_bytes(&mut g, &flipped, hash, envelope);
    verify_stateful_bytes(&mut g, &expected, hash, &envelope[..envelope.len() - 1]);

    // Stateless. A full-size stateless envelope has about 55 kilobytes, and
    // the replay of its decoder does not finish in reasonable time. The full
    // profile replays the paths of the stateless verifier that reject early.
    // The group `toy_shrincs` replays its parts on a valid envelope.
    verify_stateless_bytes(&mut g, &expected[..31], hash, envelope);
    // Review Focus 3: a stateful envelope on the stateless path.
    verify_stateless_bytes(&mut g, &expected, hash, envelope);

    // The typed action path, stateful.
    let action_message = dispatch::stateful_action_message_hash::<Full>(expected, &ctx);
    let action_signature =
        ShrincsSigner::sign_stateful_raw_at_leaf::<Full, 64>(&keys, 3, &action_message)
            .unwrap_or_else(grind_failed);
    for c in [ctx, zero_domain] {
        g.call(
            "verify_stateful",
            vec![
                Value::bytes(&expected),
                public_key(&pk),
                context_value(&c),
                stateful_sig(&action_signature),
            ],
            || dispatch::verify_stateful::<Full, 64>(expected, &pk, &c, &action_signature),
            |r| Value::Bool(*r),
        );
    }
    g
}

pub(super) fn toy_group() -> Group {
    let mut g = Group::new::<Toy>("toy_shrincs");
    let seed = label_bytes("toy_shrincs/seed", 48);
    for max in [0u32, 2] {
        g.call(
            "shrincs_keygen",
            vec![Value::bytes(&seed), Value::int(max)],
            || ShrincsSigner::keygen::<Toy, TOY_CHAINS, TOY_LAYERS>(&seed, max),
            |r| {
                Value::opt(
                    r.as_ref()
                        .map(|(k, p)| Value::Tuple(vec![keys_value(k), public_key(p)])),
                )
            },
        );
    }
    let (mut keys, pk) =
        ShrincsSigner::keygen::<Toy, TOY_CHAINS, TOY_LAYERS>(&seed, 2).unwrap_or_else(grind_failed);
    let expected = commitment(&pk);
    let hash = label_word("toy_shrincs/hash");
    g.call(
        "sign_stateless_adapter",
        vec![keys_value(&keys), public_key(&pk), Value::bytes(&hash)],
        || ShrincsSigner::sign_stateless_adapter::<Toy, TOY_LAYERS>(&keys, &pk, hash),
        |r| Value::opt(r.as_ref().map(stateless_sig)),
    );
    let stateless = ShrincsSigner::sign_stateless_adapter::<Toy, TOY_LAYERS>(&keys, &pk, hash)
        .unwrap_or_else(grind_failed);
    let envelope = encode_stateless_envelope(&pk, &stateless);
    let mut flipped = expected;
    flipped[0] ^= 1;
    for commitment in [expected, flipped] {
        g.call(
            "prepare_stateless_delegation",
            vec![Value::bytes(&commitment), Value::bytes(&envelope)],
            || prepare_stateless_delegation::<Toy>(commitment, &envelope),
            |r| {
                Value::opt(
                    r.as_ref()
                        .map(|(k, s)| Value::Tuple(vec![Value::bytes(k), Value::bytes(s)])),
                )
            },
        );
    }
    // Review Focus 3: a stateless envelope does not decode as a stateful one.
    g.call(
        "decode_stateful_envelope",
        vec![Value::bytes(&envelope)],
        || crate::shrincs::decode_stateful_envelope::<Toy>(&envelope),
        |r| {
            Value::opt(
                r.as_ref()
                    .map(|(p, s)| Value::Tuple(vec![public_key(p), stateful_sig(s)])),
            )
        },
    );
    let ctx = context("toy_shrincs/ctx");
    let before = keys.clone();
    let action = g.call(
        "sign_stateful_action",
        vec![keys_value(&before), public_key(&pk), context_value(&ctx)],
        || {
            ShrincsSigner::sign_stateful_action::<Toy, TOY_CHAINS>(&mut keys, &pk, &ctx)
                .map(|s| (s, keys.clone()))
        },
        |r| {
            Value::opt(
                r.as_ref()
                    .map(|(s, k)| Value::Tuple(vec![stateful_sig(s), keys_value(k)])),
            )
        },
    );
    if let Some((action, _)) = action {
        g.call(
            "verify_stateful",
            vec![
                Value::bytes(&expected),
                public_key(&pk),
                context_value(&ctx),
                stateful_sig(&action),
            ],
            || dispatch::verify_stateful::<Toy, TOY_CHAINS>(expected, &pk, &ctx, &action),
            |r| Value::Bool(*r),
        );
    }
    let stateless_ctx_message = dispatch::stateless_action_message_hash::<Toy>(expected, &ctx);
    let stateless_action: StatelessSignature =
        sphincs_plus_c::sign::<Toy, TOY_LAYERS>(keys.stateless(), &stateless_ctx_message)
            .unwrap_or_else(grind_failed);
    for c in [ctx, context("toy_shrincs/other")] {
        g.call(
            "verify_stateless",
            vec![
                Value::bytes(&expected),
                public_key(&pk),
                context_value(&c),
                stateless_sig(&stateless_action),
            ],
            || dispatch::verify_stateless::<Toy, TOY_CHAINS>(expected, &pk, &c, &stateless_action),
            |r| Value::Bool(*r),
        );
    }
    g
}
