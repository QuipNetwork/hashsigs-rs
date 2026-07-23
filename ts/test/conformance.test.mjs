// Packaging conformance test: loads the BUILT package (dist/) in Node and
// exercises the real signing surface through both loaders. This is the only
// test of the packaging layer itself (loaders, exports map, ESM/CJS scoping,
// base64-inline path), so it must run after `npm run build` and gate publish.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadShrincsWasm as loadNode, loadHashSigs as loadHashSigsNode } from "../dist/index.js";
import { loadShrincsWasm as loadWeb } from "../dist/loader.browser.js";
import * as entryNode from "../dist/index.js";
import * as entryWeb from "../dist/loader.browser.js";
// loadHashSigs is assembled in index.ts itself (not re-exported per-loader),
// so the web-loader variant is built by hand below with `makeHashSigs`-shaped
// wiring: `loadHashSigsFor(loadWeb)`.

const SEED = new Uint8Array(32).fill(0xab);
import { createHash } from "node:crypto";
// The noble sign/verify functions take a 32-byte message (the caller
// pre-hashes arbitrary data, matching the on-chain verifier). sha256 stands
// in for whatever digest a real caller computes.
const hash32 = (label) => new Uint8Array(createHash("sha256").update(label).digest());
const MSG = hash32("hashsigs-noble-conformance-message");
const HEX_RE = /^0x[0-9a-f]*$/;

async function loadHashSigsFor(load) {
  const wasm = await load();
  const sphincsPlusC = {
    keygen: (seed) => {
      const keys = wasm.sphincsPlusCKeygen(seed);
      return { secretKey: keys.secretKey, publicKey: keys.publicKey };
    },
    sign: (message, keys) => wasm.sphincsPlusCSign(message, keys.secretKey),
    verify: (signature, message, publicKey) => wasm.sphincsPlusCVerify(signature, message, publicKey),
  };
  const shrincs = {
    keygen: (seed, maxSignatures = 1024) => {
      const keys = wasm.shrincsKeygen(seed, maxSignatures);
      return { secretKey: keys.secretKey, publicKey: keys.publicKey, publicKeyCommitment: keys.publicKeyCommitment };
    },
    sign: (message, keys) => wasm.shrincsSign(message, keys.secretKey),
    signStateless: (message, keys) => wasm.shrincsSignStateless(message, keys.secretKey),
    verify: (signature, message, publicKeyCommitment) => wasm.shrincsVerify(signature, message, publicKeyCommitment),
    verifyStateless: (signature, message, publicKeyCommitment) =>
      wasm.shrincsVerifyStateless(signature, message, publicKeyCommitment),
  };
  const shrincsImportSigningKey = (secretKey) => {
    const keys = wasm.shrincsImportSigningKey(secretKey);
    return { secretKey: keys.secretKey, publicKey: keys.publicKey, publicKeyCommitment: keys.publicKeyCommitment };
  };
  return { wasm, sphincsPlusC, shrincs, shrincsImportSigningKey };
}

const loaders = [
  ["node", loadNode],
  ["web", loadWeb],
];

test("entry: runtime surface is exactly { loadShrincsWasm, loadHashSigs } in BOTH entries", () => {
  // WasmShrincsKeys / WasmSphincsPlusCKeys / WasmShrincsAccount are exported
  // TYPE-ONLY from src/index.ts, and that is load-bearing: the `browser`
  // exports condition maps the package entry to loader.browser.js, so a
  // VALUE export added to index.js would exist in Node and silently be
  // missing in browser bundles.
  assert.deepEqual(Object.keys(entryNode).sort(), ["loadHashSigs", "loadShrincsWasm"]);
  assert.deepEqual(Object.keys(entryWeb).sort(), ["loadShrincsWasm"]);
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
      "shrincsSignStateless",
      "shrincsVerify",
      "shrincsVerifyStateless",
      "shrincsImportSigningKey",
      "version",
    ]) {
      assert.equal(typeof w[fn], "function", `missing ${fn}`);
    }
    assert.equal(typeof w.WasmShrincsAccount, "function");
    // The old hex-based, live-handle surface is gone: no more free-standing
    // keypair class or hex-string keygen.
    assert.equal(w.WasmShrincsKeypair, undefined);
  });
}

// ── noble-style API: sphincsPlusC ───────────────────────────────────────

for (const [name, load] of loaders) {
  test(`${name}: sphincsPlusC keygen -> sign -> verify round-trips`, async () => {
    const { sphincsPlusC } = await loadHashSigsFor(load);
    const keys = sphincsPlusC.keygen(SEED);
    assert.equal(keys.secretKey.length, 128);
    assert.equal(keys.publicKey.length, 64);

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
    assert.deepEqual(a.secretKey, b.secretKey);
    assert.deepEqual(a.publicKey, b.publicKey);
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
  test(`${name}: shrincs keygen -> sign -> verify round-trips`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    assert.equal(keys.secretKey.length, 264);
    assert.equal(keys.publicKey.length, 164);
    assert.equal(keys.publicKeyCommitment.length, 32);

    const sig = shrincs.sign(MSG, keys);
    assert.equal(shrincs.verify(sig, MSG, keys.publicKeyCommitment), true);
  });

  test(`${name}: shrincs verify rejects a tampered signature and a different message`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const sig = shrincs.sign(MSG, keys);

    const tampered = sig.slice();
    tampered[0] ^= 1;
    assert.equal(shrincs.verify(tampered, MSG, keys.publicKeyCommitment), false);
    assert.equal(shrincs.verify(sig, hash32("different"), keys.publicKeyCommitment), false);
  });

  test(`${name}: shrincs.sign advances keys.secretKey in place across two signatures`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const before = keys.secretKey.slice();

    const first = shrincs.sign(MSG, keys);
    assert.notDeepEqual(keys.secretKey, before, "secretKey must mutate in place after sign()");
    assert.equal(shrincs.verify(first, MSG, keys.publicKeyCommitment), true);

    const afterFirst = keys.secretKey.slice();
    const second = shrincs.sign(MSG, keys);
    assert.notDeepEqual(keys.secretKey, afterFirst, "secretKey must advance again on the next sign()");
    assert.notDeepEqual(first, second, "two leaves must yield distinct signatures");
    assert.equal(shrincs.verify(second, MSG, keys.publicKeyCommitment), true);
  });

  test(`${name}: shrincs stateful signing exhaustion throws ERR_STATEFUL_LEAVES_EXHAUSTED`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 1); // budget of exactly one leaf
    shrincs.sign(MSG, keys); // consumes the only leaf
    assert.throws(
      () => shrincs.sign(MSG, keys),
      (e) => e instanceof Error && e.code === "ERR_STATEFUL_LEAVES_EXHAUSTED",
    );
  });

  test(`${name}: shrincs.signStateless never mutates keys.secretKey and verifies`, async () => {
    const { shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const before = keys.secretKey.slice();

    const sig = shrincs.signStateless(MSG, keys);
    assert.deepEqual(keys.secretKey, before, "signStateless must not mutate secretKey");
    assert.equal(shrincs.verifyStateless(sig, MSG, keys.publicKeyCommitment), true);
    assert.equal(
      shrincs.verifyStateless(sig, hash32("different"), keys.publicKeyCommitment),
      false,
    );
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

  test(`${name}: shrincsImportSigningKey round-trips a persisted secretKey`, async () => {
    const { shrincs, shrincsImportSigningKey } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    shrincs.sign(MSG, keys); // advance past leaf 1 so the import exercises a non-fresh counter

    const imported = shrincsImportSigningKey(keys.secretKey);
    assert.deepEqual(imported.secretKey, keys.secretKey);
    assert.deepEqual(imported.publicKeyCommitment, keys.publicKeyCommitment);
  });

  test(`${name}: shrincsImportSigningKey rejects a tampered secretKey`, async () => {
    const { shrincs, shrincsImportSigningKey } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 4);
    const tampered = keys.secretKey.slice();
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
  assert.deepEqual(spcKeysNode.secretKey, spcKeysWeb.secretKey);
  assert.deepEqual(spcKeysNode.publicKey, spcKeysWeb.publicKey);
  const spcSigNode = spcNode.sign(MSG, spcKeysNode);
  assert.equal(spcWeb.verify(spcSigNode, MSG, spcKeysWeb.publicKey), true);

  const shrincsKeysNode = shrincsNode.keygen(SEED, 4);
  const shrincsKeysWeb = shrincsWeb.keygen(SEED, 4);
  assert.deepEqual(shrincsKeysNode.publicKeyCommitment, shrincsKeysWeb.publicKeyCommitment);
  const shrincsSigNode = shrincsNode.sign(MSG, shrincsKeysNode);
  assert.equal(shrincsWeb.verify(shrincsSigNode, MSG, shrincsKeysWeb.publicKeyCommitment), true);
});

// ── WasmShrincsAccount: byte params, policy state, and message-hash methods ──
// Every account param is a `Uint8Array`. Action/rotation methods take the
// signature bytes the noble signer produces; the account's own
// `*MessageHash` methods build the exact message a caller must sign from the
// account's own state, so callers never assemble that context by hand.

for (const [name, load] of loaders) {
  test(`${name}: WasmShrincsAccount takes byte params and tracks policy state`, async () => {
    const { wasm, shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 8);

    const account = new wasm.WasmShrincsAccount(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      new Uint8Array(20).fill(3),
      keys.publicKeyCommitment,
    );
    const snapshot = account.snapshot();
    assert.equal(snapshot.statefulPolicy, "monotonic-index");
    assert.equal(typeof snapshot.statelessSignaturesUsed, "bigint");

    account.setStatefulPolicyRecoveryRotation(new Uint8Array(32).fill(1));
    account.enterRecoveryMode(new Uint8Array(32).fill(1));
    const afterPolicy = account.snapshot();
    assert.equal(afterPolicy.statefulPolicy, "recovery-rotation");
    assert.equal(afterPolicy.recoveryMode, true);
  });

  test(`${name}: account verifyStatefulAction accepts the signature shrincs.sign() returns`, async () => {
    // Proves the bridge: account.statefulActionMessageHash() builds the exact
    // message shrincs.sign() must cover, and its output feeds the account's
    // action verifier directly (no DTO assembly). Default monotonic policy
    // accepts the leaf-1 signature the first shrincs.sign produces.
    const { wasm, shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 8);
    const account = new wasm.WasmShrincsAccount(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      new Uint8Array(20).fill(3),
      keys.publicKeyCommitment,
    );
    const snap = account.snapshot();
    const actionType = new Uint8Array(32).fill(0x44);
    const payloadHash = new Uint8Array(32).fill(0x55);
    const message = account.statefulActionMessageHash(actionType, payloadHash);
    assert.ok(message instanceof Uint8Array);
    assert.equal(message.length, 32);

    const signature = shrincs.sign(message, keys); // stateful, consumes leaf 1
    // Resolves (no throw) and advances the account nonce.
    account.verifyStatefulAction(actionType, payloadHash, signature);
    const after = account.snapshot();
    assert.notEqual(after.nonce, snap.nonce, "a verified action advances the nonce");
  });

  test(`${name}: account verifyStatelessAction accepts the signature shrincs.signStateless() returns`, async () => {
    const { wasm, shrincs } = await loadHashSigsFor(load);
    const keys = shrincs.keygen(SEED, 8);
    const account = new wasm.WasmShrincsAccount(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      new Uint8Array(20).fill(3),
      keys.publicKeyCommitment,
    );
    const actionType = new Uint8Array(32).fill(0x66);
    const payloadHash = new Uint8Array(32).fill(0x77);
    const message = account.statelessActionMessageHash(actionType, payloadHash);
    const signature = shrincs.signStateless(message, keys);

    account.verifyStatelessAction(actionType, payloadHash, signature);
    const after = account.snapshot();
    assert.equal(after.statelessSignaturesUsed, 1n);
  });

  test(`${name}: account rotateFullKey accepts a fullRotationMessageHash signature`, async () => {
    // Proves the rotation bridge end-to-end: sign
    // account.fullRotationMessageHash(nextPublicKey) with the CURRENT key's
    // stateless path, then rotate to that next key.
    const { wasm, shrincs } = await loadHashSigsFor(load);
    const currentKeys = shrincs.keygen(SEED, 8);
    const nextKeys = shrincs.keygen(hash32("hashsigs-rotation-next-key"), 8);
    const account = new wasm.WasmShrincsAccount(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      new Uint8Array(20).fill(3),
      currentKeys.publicKeyCommitment,
    );
    account.setStatefulPolicyRecoveryRotation(new Uint8Array(32).fill(1));
    account.enterRecoveryMode(new Uint8Array(32).fill(1));

    const recoveryMessage = account.fullRotationMessageHash(nextKeys.publicKey);
    const recoverySignature = shrincs.signStateless(recoveryMessage, currentKeys);

    account.rotateFullKey(recoverySignature, nextKeys.publicKey);
    const after = account.snapshot();
    const toHex = (b) => "0x" + Buffer.from(b).toString("hex");
    assert.equal(after.currentShrincsPublicKey, toHex(nextKeys.publicKeyCommitment));
  });
}

test("determinism: shrincs keygen from the same seed re-derives the identical key", async () => {
  const { shrincs } = await loadHashSigsFor(loadNode);
  const first = shrincs.keygen(SEED, 4);
  const second = shrincs.keygen(SEED, 4);
  assert.deepEqual(first.secretKey, second.secretKey);
  assert.deepEqual(first.publicKeyCommitment, second.publicKeyCommitment);
});

test("runtime types match the declarations", async () => {
  const { wasm, shrincs } = await loadHashSigsFor(loadNode);
  const keys = shrincs.keygen(SEED, 4);
  const account = new wasm.WasmShrincsAccount(
    new Uint8Array(32).fill(0x11),
    new Uint8Array(32).fill(0x22),
    new Uint8Array(20).fill(0x33),
    keys.publicKeyCommitment,
  );
  const snap = account.snapshot();
  // The bigint drift guard: u64 fields must cross the boundary as BigInt, not
  // number (the default serializer breaks on values past 2^53).
  assert.equal(typeof snap.statelessSignaturesUsed, "bigint");

  // Hex-DTO fields (still hex on the nested-object surface) are 0x-prefixed
  // lowercase strings.
  assert.match(snap.domainSeparator, HEX_RE);
  assert.match(snap.owner, HEX_RE);
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
