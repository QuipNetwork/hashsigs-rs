// Packaging conformance test: loads the BUILT package (dist/) in Node and
// exercises the real signing surface through both loaders. This is the only
// test of the packaging layer itself (loaders, exports map, ESM/CJS scoping,
// base64-inline path), so it must run after `npm run build` and gate publish.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  loadShrincsWasm as loadNode,
  loadHashSigs as loadHashSigsNode,
  shrincsKeysToSecretBytes,
} from "../dist/index.js";
import { loadShrincsWasm as loadWeb } from "../dist/loader.browser.js";
import * as entryNode from "../dist/index.js";
import * as entryWeb from "../dist/loader.browser.js";
// loadHashSigs is assembled in index.ts itself (not re-exported per-loader),
// so the web-loader variant is built by hand below with the same decompose/
// recompose wiring: `loadHashSigsFor(loadWeb)`.

const SEED = new Uint8Array(32).fill(0xab);
import { createHash } from "node:crypto";
// The noble sign/verify functions take a 32-byte message (the caller
// pre-hashes arbitrary data, matching the on-chain verifier). sha256 stands
// in for whatever digest a real caller computes.
const hash32 = (label) => new Uint8Array(createHash("sha256").update(label).digest());
const MSG = hash32("hashsigs-noble-conformance-message");

// ── decompose/recompose helpers, mirroring ts/src/index.ts ─────────────────
// (duplicated here because `loadHashSigsFor` has to reassemble the noble
// surface by hand for the web loader; see the comment above).

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32BEBytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function readU32BE(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
}

function sphincsPlusCKeysToSecretBytes(keys) {
  return concatBytes(keys.secret.skSeed, keys.secret.prfSeed, keys.publicKey.pkSeed, keys.publicKey.root);
}

function sphincsPlusCKeysFromSecretBytes(secret) {
  return {
    secret: { skSeed: secret.slice(0, 32), prfSeed: secret.slice(32, 64) },
    publicKey: { pkSeed: secret.slice(64, 96), root: secret.slice(96, 128) },
  };
}

function sphincsPlusCPublicKeyToBytes(publicKey) {
  return concatBytes(publicKey.pkSeed, publicKey.root);
}

const STATEFUL_SECRET_LEN = 136;

function shrincsKeysFromSecretBytes(secret, publicKeyCommitment) {
  const maxSignatures = readU32BE(secret, 128);
  const nextLeafIndex = readU32BE(secret, 132);
  return {
    stateless: sphincsPlusCKeysFromSecretBytes(secret.slice(STATEFUL_SECRET_LEN)),
    stateful: {
      secret: { skSeed: secret.slice(0, 32), prfSeed: secret.slice(32, 64) },
      publicKey: { pkSeed: secret.slice(64, 96), root: secret.slice(96, 128), maxSignatures },
      nextLeafIndex,
      remaining: maxSignatures - (nextLeafIndex - 1),
    },
    publicKeyCommitment,
  };
}

async function loadHashSigsFor(load) {
  const wasm = await load();
  const sphincsPlusC = {
    keygen: (seed) => sphincsPlusCKeysFromSecretBytes(wasm.sphincsPlusCKeygen(seed).secretKey),
    sign: (message, keys) => wasm.sphincsPlusCSign(message, sphincsPlusCKeysToSecretBytes(keys)),
    verify: (signature, message, publicKey) =>
      wasm.sphincsPlusCVerify(signature, message, sphincsPlusCPublicKeyToBytes(publicKey)),
  };
  const shrincs = {
    keygen: (seed, maxSignatures = 1024) => {
      const keys = wasm.shrincsKeygen(seed, maxSignatures);
      return shrincsKeysFromSecretBytes(keys.secretKey, keys.publicKeyCommitment);
    },
    sign: (message, keys) => {
      const secret = shrincsKeysToSecretBytes(keys);
      const signature = wasm.shrincsSign(message, secret);
      keys.stateful.nextLeafIndex = readU32BE(secret, 132);
      keys.stateful.remaining = keys.stateful.publicKey.maxSignatures - (keys.stateful.nextLeafIndex - 1);
      return signature;
    },
    signStateless: (message, keys) => wasm.shrincsSignStateless(message, shrincsKeysToSecretBytes(keys)),
    verify: (signature, message, publicKeyCommitment) => wasm.shrincsVerify(signature, message, publicKeyCommitment),
    verifyStateless: (signature, message, statelessPublicKey) =>
      wasm.shrincsVerifyStateless(signature, message, sphincsPlusCPublicKeyToBytes(statelessPublicKey)),
    reset: (keys, newSeed) => {
      const secret = shrincsKeysToSecretBytes(keys);
      wasm.shrincsReset(secret, newSeed);
      const publicKeyCommitment = wasm.shrincsComputePublicKeyCommitment(secret);
      const updated = shrincsKeysFromSecretBytes(secret, publicKeyCommitment);
      keys.stateful = updated.stateful;
      keys.publicKeyCommitment = updated.publicKeyCommitment;
    },
    computePublicKeyCommitment: (keys) => wasm.shrincsComputePublicKeyCommitment(shrincsKeysToSecretBytes(keys)),
    recoverPublicKeyCommitment: (signature) => wasm.shrincsRecoverPublicKeyCommitment(signature),
  };
  const shrincsImportSigningKey = (secretKey) => {
    const keys = wasm.shrincsImportSigningKey(secretKey);
    return shrincsKeysFromSecretBytes(keys.secretKey, keys.publicKeyCommitment);
  };
  return { wasm, sphincsPlusC, shrincs, shrincsImportSigningKey };
}

const loaders = [
  ["node", loadNode],
  ["web", loadWeb],
];

test("entry: runtime surface is exactly { loadHashSigs, loadShrincsWasm, shrincsKeysToSecretBytes } in node, { loadShrincsWasm } in web", () => {
  // WasmShrincsKeys / WasmSphincsPlusCKeys are exported TYPE-ONLY from
  // src/index.ts, and that is load-bearing: the `browser`
  // exports condition maps the package entry to loader.browser.js, so a
  // VALUE export added to index.js would exist in Node and silently be
  // missing in browser bundles. `shrincsKeysToSecretBytes` is pure byte
  // manipulation (no wasm dependency), so it is safe as a value export.
  assert.deepEqual(
    Object.keys(entryNode).sort(),
    ["loadHashSigs", "loadShrincsWasm", "shrincsKeysToSecretBytes"],
  );
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
      "shrincsReset",
      "shrincsComputePublicKeyCommitment",
      "shrincsRecoverPublicKeyCommitment",
      "version",
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
