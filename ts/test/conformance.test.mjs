// Packaging conformance test: loads the BUILT package (dist/) in Node and
// exercises the real signing surface through both loaders. This is the only
// test of the packaging layer itself (loaders, exports map, ESM/CJS scoping,
// base64-inline path), so it must run after `npm run build` and gate publish.
//
// Profile scope: this file drives the DEFAULT profile (256s-keccak) through
// the full crypto surface. `profiles.test.mjs` covers the other five: it
// checks every subpath resolves and reports its own profile, and runs the
// cross-profile rejection on the 256s pair. The 128s profiles are identity
// checked only, because 128s keygen through wasm costs about 53 seconds and
// signing about 52 more -- their crypto is covered natively by `cargo test`
// under each `profile-*` feature.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  loadShrincsWasm as loadNode,
  loadHashSigs as loadHashSigsNode,
  shrincsKeysToSecretBytes,
  makeHashSigs,
  decodeStatefulEnvelope,
  decodeStatelessSignature,
} from "../dist/index.js";
import { loadShrincsWasm as loadWeb } from "../dist/profiles/256s-keccak/loader.browser.js";
import * as entryNode from "../dist/index.js";
import * as entryWeb from "../dist/profiles/256s-keccak/loader.browser.js";

const SEED = new Uint8Array(32).fill(0xab);
import { createHash } from "node:crypto";
// The noble sign/verify functions take a 32-byte message (the caller
// pre-hashes arbitrary data, matching the on-chain verifier). sha256 stands
// in for whatever digest a real caller computes.
const hash32 = (label) => new Uint8Array(createHash("sha256").update(label).digest());
const MSG = hash32("hashsigs-noble-conformance-message");

// The web loader yields the same module shape as the node loader, so both get
// the same noble-style surface from the package's own `makeHashSigs`. This
// used to be a hand-copied reimplementation of every ser/de helper; binding
// the real one instead means a bug in that wiring fails this suite rather than
// being faithfully reproduced by a second copy of it.
async function loadHashSigsFor(load) {
  const wasm = await load();
  return { wasm, ...makeHashSigs(wasm) };
}

const loaders = [
  ["node", loadNode],
  ["web", loadWeb],
];

test("entry: node exposes the value surface, web the loader plus decoders", () => {
  // WasmShrincsKeys / WasmSphincsPlusCKeys are exported TYPE-ONLY from
  // src/index.ts, and that is load-bearing: the `browser`
  // exports condition maps the package entry to loader.browser.js, so a
  // VALUE export added to index.js would exist in Node and silently be
  // missing in browser bundles. `shrincsKeysToSecretBytes` and the two
  // envelope decoders are pure byte manipulation (no wasm dependency), so
  // they are safe as value exports.
  assert.deepEqual(
    Object.keys(entryNode).sort(),
    [
      "PROFILE",
      "PROFILE_NAME",
      "decodeStatefulEnvelope",
      "decodeStatelessSignature",
      "loadHashSigs",
      "loadShrincsWasm",
      "makeHashSigs",
      "shrincsKeysToSecretBytes",
    ],
  );
  assert.deepEqual(
    Object.keys(entryWeb).sort(),
    ["decodeStatefulEnvelope", "decodeStatelessSignature", "loadShrincsWasm"],
  );
});

for (const [name, load] of loaders) {
  test(`${name}: loader resolves and exposes the noble-style surface`, async () => {
    const w = await load();
    for (const fn of [
      "sphincsPlusCKeygen",
      "sphincsPlusCSign",
      "sphincsPlusCVerify",
      "shrincsKeygen",
      "shrincsSign",
      "shrincsSignAtLeaf",
      "shrincsSignStatefulRawAt",
      "shrincsSignStateless",
      "shrincsVerify",
      "shrincsVerifyStatefulRaw",
      "shrincsVerifyStateless",
      "shrincsImportSigningKey",
      "shrincsReset",
      "shrincsComputePublicKeyCommitment",
      "shrincsRecoverPublicKeyCommitment",
      "version",
      "profileName",
    ]) {
      assert.equal(typeof w[fn], "function", `missing ${fn}`);
    }
    // The old hex-based, live-handle keypair surface is gone.
    assert.equal(w.WasmShrincsKeypair, undefined);
  });
}

// ── noble-style API: sphincsPlusC ───────────────────────────────────────

for (const [name, load] of loaders) {
  test(`${name}: sphincsPlusC keygen -> sign -> verify round-trips`, async () => {
    const { sphincsPlusC } = await loadHashSigsFor(load);
    const keys = sphincsPlusC.keygen(SEED);
    assert.equal(keys.secret.skSeed.length, 32);
    assert.equal(keys.secret.prfSeed.length, 32);
    assert.equal(keys.publicKey.pkSeed.length, 32);
    assert.equal(keys.publicKey.root.length, 32);

    const sig = sphincsPlusC.sign(MSG, keys);
    assert.equal(sphincsPlusC.verify(sig, MSG, keys.publicKey), true);
  });

  test(`${name}: sphincsPlusC verify rejects a tampered signature and a different message`, async () => {
    const { sphincsPlusC } = await loadHashSigsFor(load);
    const keys = sphincsPlusC.keygen(SEED);
    const sig = sphincsPlusC.sign(MSG, keys);

    const tampered = sig.slice();
    tampered[0] ^= 1;
    assert.equal(sphincsPlusC.verify(tampered, MSG, keys.publicKey), false);
    assert.equal(sphincsPlusC.verify(sig, hash32("different"), keys.publicKey), false);
  });

  test(`${name}: sphincsPlusC keygen is deterministic for the same seed`, async () => {
    const { sphincsPlusC } = await loadHashSigsFor(load);
    const a = sphincsPlusC.keygen(SEED);
    const b = sphincsPlusC.keygen(SEED);
    assert.deepEqual(a.secret.skSeed, b.secret.skSeed);
    assert.deepEqual(a.secret.prfSeed, b.secret.prfSeed);
    assert.deepEqual(a.publicKey.pkSeed, b.publicKey.pkSeed);
    assert.deepEqual(a.publicKey.root, b.publicKey.root);
  });

  test(`${name}: sphincsPlusC keygen requires an exactly-32-byte seed`, async () => {
    const { wasm } = await loadHashSigsFor(load);
    assert.throws(
      () => wasm.sphincsPlusCKeygen(new Uint8Array(31)),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
    assert.throws(
      () => wasm.sphincsPlusCKeygen(new Uint8Array(33)),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
  });
}

// ── noble-style API: shrincs ─────────────────────────────────────────────

for (const [name, load] of loaders) {
  test(`${name}: shrincs keygen returns the decomposed key shape`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);

    assert.equal(keys.stateful.secret.skSeed.length, 32);
    assert.equal(keys.stateful.secret.prfSeed.length, 32);
    assert.equal(keys.stateful.publicKey.pkSeed.length, 32);
    assert.equal(keys.stateful.publicKey.root.length, 32);
    assert.equal(keys.stateless.secret.skSeed.length, 32);
    assert.equal(keys.stateless.secret.prfSeed.length, 32);
    assert.equal(keys.stateless.publicKey.pkSeed.length, 32);
    assert.equal(keys.stateless.publicKey.root.length, 32);
    assert.equal(keys.publicKeyCommitment.length, 32);

    assert.equal(typeof keys.stateful.publicKey.maxSignatures, "number");
    assert.equal(typeof keys.stateful.nextLeafIndex, "number");
    assert.equal(keys.stateful.publicKey.maxSignatures, 4);
    assert.equal(keys.stateful.nextLeafIndex, 1);
    assert.equal(keys.stateful.remaining, 4);
  });

  test(`${name}: shrincs stateful sign -> verify round-trips via keys.publicKeyCommitment`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);

    const sig = shrincs.sign(MSG, keys);
    assert.equal(shrincs.verify(sig, MSG, keys.publicKeyCommitment), true);
  });

  test(`${name}: shrincs verify rejects a tampered signature, a different message, and a wrong commitment`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const other = shrincs.keygen(hash32("hashsigs-conformance-other-key"), 4);
    const sig = shrincs.sign(MSG, keys);

    const tampered = sig.slice();
    tampered[0] ^= 1;
    assert.equal(shrincs.verify(tampered, MSG, keys.publicKeyCommitment), false);
    assert.equal(shrincs.verify(sig, hash32("different"), keys.publicKeyCommitment), false);
    assert.equal(shrincs.verify(sig, MSG, other.publicKeyCommitment), false);
  });

  test(`${name}: shrincs.sign advances nextLeafIndex and decrements remaining`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    assert.equal(keys.stateful.nextLeafIndex, 1);
    assert.equal(keys.stateful.remaining, 4);

    const first = shrincs.sign(MSG, keys);
    assert.equal(keys.stateful.nextLeafIndex, 2);
    assert.equal(keys.stateful.remaining, 3);
    assert.equal(shrincs.verify(first, MSG, keys.publicKeyCommitment), true);

    const second = shrincs.sign(MSG, keys);
    assert.equal(keys.stateful.nextLeafIndex, 3);
    assert.equal(keys.stateful.remaining, 2);
    assert.notDeepEqual(first, second, "two leaves must yield distinct signatures");
    assert.equal(shrincs.verify(second, MSG, keys.publicKeyCommitment), true);
  });

  test(`${name}: shrincs stateful signing exhaustion throws ERR_STATEFUL_LEAVES_EXHAUSTED`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 1); // budget of exactly one leaf
    shrincs.sign(MSG, keys); // consumes the only leaf
    assert.equal(keys.stateful.remaining, 0);
    assert.throws(
      () => shrincs.sign(MSG, keys),
      (e) => e instanceof Error && e.code === "ERR_STATEFUL_LEAVES_EXHAUSTED",
    );
  });

  test(`${name}: shrincs.signStateless never mutates keys and verifies via keys.stateless.publicKey`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const nextLeafIndexBefore = keys.stateful.nextLeafIndex;

    const sig = shrincs.signStateless(MSG, keys);
    assert.equal(keys.stateful.nextLeafIndex, nextLeafIndexBefore, "signStateless must not mutate keys.stateful");
    assert.equal(shrincs.verifyStateless(sig, MSG, keys.stateless.publicKey), true);
    assert.equal(
      shrincs.verifyStateless(sig, hash32("different"), keys.stateless.publicKey),
      false,
    );
  });

  test(`${name}: shrincs.signAtLeaf never mutates keys, matches sign at the next leaf, and pins authPath.length === leafIndex`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);

    const atLeaf = shrincs.signAtLeaf(MSG, keys, 1);
    assert.equal(keys.stateful.nextLeafIndex, 1, "signAtLeaf must not advance the counter");
    assert.equal(shrincs.verify(atLeaf, MSG, keys.publicKeyCommitment), true);

    // Byte-identical to what the counter-advancing sign produces at the
    // same leaf, and deterministic on repeat.
    const advancing = shrincs.keygen(SEED, 4);
    assert.deepEqual(atLeaf, shrincs.sign(MSG, advancing));
    assert.deepEqual(atLeaf, shrincs.signAtLeaf(MSG, keys, 1));

    // A different leaf yields a different signature that still verifies,
    // with the leaf index visible as the decoded authPath length.
    const atThree = shrincs.signAtLeaf(MSG, keys, 3);
    assert.notDeepEqual(atLeaf, atThree);
    assert.equal(shrincs.verify(atThree, MSG, keys.publicKeyCommitment), true);
    assert.equal(decodeStatefulEnvelope(atThree).signature.authPath.length, 3);

    for (const leafIndex of [0, 5]) {
      assert.throws(
        () => shrincs.signAtLeaf(MSG, keys, leafIndex),
        (e) => e instanceof Error && e.code === "ERR_INVALID_INPUT",
      );
    }
  });

  test(`${name}: shrincs.signStatefulRawAt signs the message unbound and never mutates keys`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);

    const raw = shrincs.signStatefulRawAt(MSG, keys, 2);
    assert.equal(keys.stateful.nextLeafIndex, 1, "signStatefulRawAt must not advance the counter");
    assert.deepEqual(raw, shrincs.signStatefulRawAt(MSG, keys, 2), "deterministic per leaf");

    // Raw signing skips the shrincsSign/shrincsSignAtLeaf commitment
    // binding, so the adapter-bound verify must NOT accept it — proving the
    // two entry points sign different digests. (The bound-digest equivalence
    // raw(bind(m)) == signAtLeaf(m) is pinned on the Rust side, where the
    // binding construction is reachable.)
    assert.equal(shrincs.verify(raw, MSG, keys.publicKeyCommitment), false);
    assert.equal(shrincs.verifyStatefulRaw(raw, MSG, keys.publicKeyCommitment), true);
    assert.equal(shrincs.verifyStatefulRaw(raw, hash32("different"), keys.publicKeyCommitment), false);
    assert.equal(decodeStatefulEnvelope(raw).signature.authPath.length, 2);

    for (const leafIndex of [0, 5]) {
      assert.throws(
        () => shrincs.signStatefulRawAt(MSG, keys, leafIndex),
        (e) => e instanceof Error && e.code === "ERR_INVALID_INPUT",
      );
    }
  });

  test(`${name}: decodeStatefulEnvelope exposes the PublicKey and Signature fields`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const sig = shrincs.sign(MSG, keys);

    const decoded = decodeStatefulEnvelope(sig);
    assert.deepEqual(decoded.publicKey.publicKeyCommitment, keys.publicKeyCommitment);
    assert.deepEqual(decoded.publicKey.pkSeed, keys.stateless.publicKey.pkSeed);
    assert.deepEqual(decoded.publicKey.hypertreeRoot, keys.stateless.publicKey.root);
    assert.equal(decoded.publicKey.statefulPublicKey.length, 68);
    // statefulPublicKey = pkSeed ‖ root ‖ maxSignatures(u32 BE)
    assert.deepEqual(
      decoded.publicKey.statefulPublicKey.slice(0, 32),
      keys.stateful.publicKey.pkSeed,
    );
    assert.deepEqual(
      decoded.publicKey.statefulPublicKey.slice(32, 64),
      keys.stateful.publicKey.root,
    );
    assert.equal(readU32BE(decoded.publicKey.statefulPublicKey, 64), 4);

    assert.equal(decoded.signature.randomizer.length, 32);
    assert.equal(typeof decoded.signature.counter, "number");
    assert.ok(decoded.signature.chains.length > 0, "chains must not be empty");
    for (const chain of decoded.signature.chains) assert.equal(chain.length, 32);
    assert.equal(decoded.signature.authPath.length, 1, "first leaf -> authPath length 1");

    assert.throws(
      () => decodeStatefulEnvelope(sig.slice(0, sig.length - 32)),
      (e) => e instanceof Error && e.code === "ERR_ENVELOPE_MALFORMED",
    );
  });

  test(`${name}: decodeStatelessSignature exposes the FORS and hypertree fields`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const sig = shrincs.signStateless(MSG, keys);

    const decoded = decodeStatelessSignature(sig);
    assert.equal(decoded.fors.randomizer.length, 32);
    assert.equal(typeof decoded.fors.counter, "number");
    assert.ok(decoded.fors.entries.length > 0, "FORS entries must not be empty");
    for (const entry of decoded.fors.entries) {
      assert.equal(entry.secretLeaf.length, 32);
      assert.ok(entry.authPath.length > 0);
      for (const node of entry.authPath) assert.equal(node.length, 32);
    }
    assert.ok(decoded.hypertree.length > 0, "hypertree layers must not be empty");
    for (const layer of decoded.hypertree) {
      assert.equal(layer.wotsCPkHash.length, 32);
      assert.equal(layer.wotsCSignature.randomizer.length, 32);
      assert.ok(layer.wotsCSignature.chains.length > 0);
      for (const chain of layer.wotsCSignature.chains) assert.equal(chain.length, 32);
      for (const node of layer.authPath) assert.equal(node.length, 32);
    }

    assert.throws(
      () => decodeStatelessSignature(sig.slice(0, 64)),
      (e) => e instanceof Error && e.code === "ERR_ENVELOPE_MALFORMED",
    );
  });

  test(`${name}: shrincs.reset changes the commitment, resets the leaf counter, and leaves keys.stateless unchanged`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    shrincs.sign(MSG, keys); // advance past leaf 1
    const commitmentBefore = keys.publicKeyCommitment.slice();
    const statelessBefore = {
      secret: {
        skSeed: keys.stateless.secret.skSeed.slice(),
        prfSeed: keys.stateless.secret.prfSeed.slice(),
      },
      publicKey: {
        pkSeed: keys.stateless.publicKey.pkSeed.slice(),
        root: keys.stateless.publicKey.root.slice(),
      },
    };

    shrincs.reset(keys, hash32("hashsigs-conformance-reset-seed"));

    assert.notDeepEqual(keys.publicKeyCommitment, commitmentBefore, "reset must change the commitment");
    assert.equal(keys.stateful.nextLeafIndex, 1);
    assert.equal(keys.stateful.remaining, keys.stateful.publicKey.maxSignatures);
    assert.deepEqual(keys.stateless, statelessBefore, "reset must leave keys.stateless untouched");

    const sig = shrincs.sign(MSG, keys);
    assert.equal(shrincs.verify(sig, MSG, keys.publicKeyCommitment), true);
  });

  test(`${name}: shrincs.computePublicKeyCommitment matches keys.publicKeyCommitment`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    assert.deepEqual(shrincs.computePublicKeyCommitment(keys), keys.publicKeyCommitment);
  });

  test(`${name}: shrincs.recoverPublicKeyCommitment(sig) matches keys.publicKeyCommitment`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const sig = shrincs.sign(MSG, keys);
    assert.deepEqual(shrincs.recoverPublicKeyCommitment(sig), keys.publicKeyCommitment);
  });

  test(`${name}: shrincs keygen requires an exactly-32-byte seed and a valid maxSignatures range`, async () => {
    const { wasm } = await loadHashSigsFor(load);
    assert.throws(
      () => wasm.shrincsKeygen(new Uint8Array(31), 4),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
    assert.throws(
      () => wasm.shrincsKeygen(SEED, 0),
      (e) => e instanceof Error && e.code === "ERR_INVALID_INPUT",
    );
    assert.throws(
      () => wasm.shrincsKeygen(SEED, 4097),
      (e) => e instanceof Error && e.code === "ERR_INVALID_INPUT",
    );
  });

  test(`${name}: shrincs.reset requires an exactly-32-byte seed`, async () => {
    const { shrincs, wasm } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const secret = shrincsKeysToSecretBytes(keys);
    assert.throws(
      () => wasm.shrincsReset(secret, new Uint8Array(31)),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
    assert.throws(
      () => wasm.shrincsReset(secret, new Uint8Array(33)),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
  });

  test(`${name}: persistence round trip via shrincsKeysToSecretBytes -> shrincsImportSigningKey`, async () => {
    const { shrincs, shrincsImportSigningKey } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    shrincs.sign(MSG, keys); // advance past leaf 1 so the import exercises a non-fresh counter

    const persisted = shrincsKeysToSecretBytes(keys);
    const imported = shrincsImportSigningKey(persisted);
    assert.deepEqual(imported, keys);
  });

  test(`${name}: shrincsImportSigningKey rejects a tampered secretKey`, async () => {
    const { shrincs, shrincsImportSigningKey } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const tampered = shrincsKeysToSecretBytes(keys);
    tampered[0] ^= 1; // corrupts statefulSkSeed, invalidating the committed statefulRoot
    assert.throws(
      () => shrincsImportSigningKey(tampered),
      (e) => e instanceof Error && e.code === "ERR_IMPORT_INVALID",
    );
  });
}

test("cross-build: node and web agree on noble keys and signatures", async () => {
  const { sphincsPlusC: spcNode, shrincs: shrincsNode } = await loadHashSigsFor(loadNode);
  const { sphincsPlusC: spcWeb, shrincs: shrincsWeb } = await loadHashSigsFor(loadWeb);

  const spcKeysNode = spcNode.keygen(SEED);
  const spcKeysWeb = spcWeb.keygen(SEED);
  assert.deepEqual(spcKeysNode, spcKeysWeb);
  const spcSigNode = spcNode.sign(MSG, spcKeysNode);
  assert.equal(spcWeb.verify(spcSigNode, MSG, spcKeysWeb.publicKey), true);

  const shrincsKeysNode = shrincsNode.keygen(SEED, 4);
  const shrincsKeysWeb = shrincsWeb.keygen(SEED, 4);
  assert.deepEqual(shrincsKeysNode.publicKeyCommitment, shrincsKeysWeb.publicKeyCommitment);
  const shrincsSigNode = shrincsNode.sign(MSG, shrincsKeysNode);
  assert.equal(shrincsWeb.verify(shrincsSigNode, MSG, shrincsKeysWeb.publicKeyCommitment), true);
});

test("determinism: shrincs keygen from the same seed re-derives the identical key", async () => {
  const { shrincs } = await loadHashSigsFor(loadNode);
  const first = shrincs.keygen(SEED, 4);
  const second = shrincs.keygen(SEED, 4);
  assert.deepEqual(first, second);
});

test("version: wasm reports the package version through both loaders", async () => {
  const pkg = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.equal((await loadNode()).version(), pkg.version);
  assert.equal((await loadWeb()).version(), pkg.version);
});

test("loadHashSigs: the exported entry point resolves through the node loader", async () => {
  const { sphincsPlusC, shrincs } = await loadHashSigsNode();
  const spcKeys = sphincsPlusC.keygen(SEED);
  assert.equal(sphincsPlusC.verify(sphincsPlusC.sign(MSG, spcKeys), MSG, spcKeys.publicKey), true);
  const shrincsKeys = shrincs.keygen(SEED, 4);
  assert.equal(
    shrincs.verify(shrincs.sign(MSG, shrincsKeys), MSG, shrincsKeys.publicKeyCommitment),
    true,
  );
});
