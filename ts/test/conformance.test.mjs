// Packaging conformance test: loads the BUILT package (dist/) in Node and
// exercises the real signing surface through both loaders. This is the only
// test of the packaging layer itself (loaders, exports map, ESM/CJS scoping,
// base64-inline path), so it must run after `npm run build` and gate publish.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadShrincsWasm as loadNode } from "../dist/index.js";
import { loadShrincsWasm as loadWeb } from "../dist/loader.browser.js";

const SEED = "0x" + "ab".repeat(32);
const MSG = "0x" + "11".repeat(32);
const HEX32 = (byte) => "0x" + byte.repeat(32);
const HEX_RE = /^0x[0-9a-f]*$/;

const loaders = [
  ["node", loadNode],
  ["web", loadWeb],
];

for (const [name, load] of loaders) {
  test(`${name}: loader resolves and exposes the shrincs surface`, async () => {
    const w = await load();
    for (const fn of [
      "shrincsKeygen",
      "shrincsVerifyStatefulRaw",
      "shrincsVerifyStatelessRaw",
      "version",
    ]) {
      assert.equal(typeof w[fn], "function", `missing ${fn}`);
    }
    assert.equal(typeof w.WasmShrincsAccount, "function");
  });

  test(`${name}: keygen → signStatefulRawAt → verify, tamper → false`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    const pk = kp.publicKey();
    const sig = kp.signStatefulRawAt(MSG, 1);
    assert.equal(
      w.shrincsVerifyStatefulRaw(pk.publicKeyCommitment, pk, MSG, sig),
      true,
    );
    const bad = structuredClone(sig);
    bad.randomizer = "0x" + "00".repeat(32);
    assert.equal(
      w.shrincsVerifyStatefulRaw(pk.publicKeyCommitment, pk, MSG, bad),
      false,
    );
  });

  test(`${name}: verify with a second keypair commitment returns false`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    const pk = kp.publicKey();
    const sig = kp.signStatefulRawAt(MSG, 1);
    const otherPk = w.shrincsKeygen("0x" + "cd".repeat(32), 4).publicKey();
    assert.equal(
      w.shrincsVerifyStatefulRaw(otherPk.publicKeyCommitment, pk, MSG, sig),
      false,
    );
  });

  test(`${name}: verify throws typed errors on malformed hex`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    const pk = kp.publicKey();
    const sig = kp.signStatefulRawAt(MSG, 1);
    // Invalid hex digits → ERR_HEX_INVALID (message does not echo the input).
    assert.throws(
      () => w.shrincsVerifyStatefulRaw("0xzz", pk, MSG, sig),
      (e) => e instanceof Error && e.code === "ERR_HEX_INVALID",
    );
    // Odd-length hex body → ERR_BAD_LENGTH.
    assert.throws(
      () => w.shrincsVerifyStatefulRaw("0x" + "ab".repeat(31) + "a", pk, MSG, sig),
      (e) => e instanceof Error && e.code === "ERR_BAD_LENGTH",
    );
  });

  test(`${name}: destroy() invalidates the handle with ERR_HANDLE_DESTROYED`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    kp.destroy();
    assert.throws(
      () => kp.publicKey(),
      (e) => e instanceof Error && e.code === "ERR_HANDLE_DESTROYED",
    );
    assert.throws(
      () => kp.signStatelessRaw(MSG),
      (e) => e instanceof Error && e.code === "ERR_HANDLE_DESTROYED",
    );
  });

  test(`${name}: stateless sign → verify`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    const pk = kp.publicKey();
    const ssig = kp.signStatelessRaw(MSG);
    assert.equal(
      w.shrincsVerifyStatelessRaw(pk.publicKeyCommitment, pk, MSG, ssig),
      true,
    );
  });

  test(`${name}: keygen enforces the 32-byte seed floor`, async () => {
    const w = await load();
    for (const seed of ["0x", "0x" + "ab".repeat(31)]) {
      assert.throws(
        () => w.shrincsKeygen(seed, 4),
        (e) => e instanceof Error && e.code === "ERR_SEED_TOO_SHORT",
        `seed of ${(seed.length - 2) / 2} bytes must be rejected`,
      );
    }
    // Exactly 32 bytes passes (SEED is 32 bytes).
    assert.ok(w.shrincsKeygen(SEED, 4));
  });

  test(`${name}: runtime types match the declarations`, async () => {
    const w = await load();
    const kp = w.shrincsKeygen(SEED, 4);
    const pk = kp.publicKey();
    const sig = kp.signStatefulRawAt(MSG, 1);
    const ssig = kp.signStatelessRaw(MSG);

    // The bigint drift guard: u64 fields must cross the boundary as BigInt,
    // not number (the default serializer breaks on values past 2^53).
    assert.equal(typeof ssig.hypertree[0].treeIndex, "bigint");
    assert.equal(typeof sig.counter, "number");

    const account = new w.WasmShrincsAccount(
      HEX32("11"),
      HEX32("22"),
      "0x" + "33".repeat(20),
      pk.publicKeyCommitment,
    );
    const snap = account.snapshot();
    assert.equal(typeof snap.statelessSignaturesUsed, "bigint");

    // Hex fields are 0x-prefixed lowercase strings.
    for (const [label, value] of [
      ["publicKeyCommitment", pk.publicKeyCommitment],
      ["statefulPublicKey", pk.statefulPublicKey],
      ["pkSeed", pk.pkSeed],
      ["hypertreeRoot", pk.hypertreeRoot],
      ["sig.randomizer", sig.randomizer],
      ["sig.authPath[0]", sig.authPath[0]],
    ]) {
      assert.match(value, HEX_RE, `${label} is not 0x-lowercase hex: ${value}`);
    }
  });
}

test("cross-build: node and web agree on keys and signatures", async () => {
  const wNode = await loadNode();
  const wWeb = await loadWeb();

  const kpNode = wNode.shrincsKeygen(SEED, 4);
  const kpWeb = wWeb.shrincsKeygen(SEED, 4);
  const pkNode = kpNode.publicKey();
  const pkWeb = kpWeb.publicKey();
  assert.deepEqual(pkNode, pkWeb);

  // Signatures are plain DTOs, so each build can verify the other's output.
  const sigNode = kpNode.signStatefulRawAt(MSG, 1);
  assert.equal(
    wWeb.shrincsVerifyStatefulRaw(pkWeb.publicKeyCommitment, pkWeb, MSG, sigNode),
    true,
  );
  const sigWeb = kpWeb.signStatefulRawAt(MSG, 2);
  assert.equal(
    wNode.shrincsVerifyStatefulRaw(pkNode.publicKeyCommitment, pkNode, MSG, sigWeb),
    true,
  );
});

test("determinism: keygen from the same seed re-derives the identical key", async () => {
  // The SDK's restart story is re-derivation from the stored seed, so two
  // keygens from one seed must produce byte-identical signing keys.
  const w = await loadNode();
  const first = w.shrincsKeygen(SEED, 4).exportSigningKey();
  const second = w.shrincsKeygen(SEED, 4).exportSigningKey();
  assert.deepEqual(first, second);
});

test("import: exported key round-trips and resumes at the persisted counter", async () => {
  const w = await loadNode();
  const kp = w.shrincsKeygen(SEED, 4);
  kp.signStatefulRaw(MSG); // burn leaf 1 → counter 2
  const blob = kp.exportSigningKey();
  assert.equal(blob.formatVersion, 1);
  assert.equal(blob.nextStatefulLeafIndex, 2);

  const restored = w.shrincsImportSigningKey(blob);
  assert.deepEqual(restored.publicKey(), kp.publicKey());
  assert.deepEqual(restored.exportSigningKey(), blob);
  const { signature: sig, nextStatefulLeafIndex } = restored.signStatefulRaw(MSG); // must consume leaf 2, not 1
  assert.equal(sig.authPath.length, 2);
  assert.equal(nextStatefulLeafIndex, 3); // returned counter matches getter
  assert.equal(restored.nextStatefulLeafIndex, 3);
  const pk = kp.publicKey();
  assert.equal(w.shrincsVerifyStatefulRaw(pk.publicKeyCommitment, pk, MSG, sig), true);
});

test("import: rejects unknown formatVersion with a typed error", async () => {
  const w = await loadNode();
  const blob = w.shrincsKeygen(SEED, 4).exportSigningKey();
  assert.throws(
    () => w.shrincsImportSigningKey({ ...blob, formatVersion: 2 }),
    (e) => e.code === "ERR_FORMAT_VERSION_UNSUPPORTED",
  );
  // Missing version field entirely → serde rejects (ERR_INVALID_INPUT).
  const { formatVersion, ...unversioned } = blob;
  assert.throws(
    () => w.shrincsImportSigningKey(unversioned),
    (e) => e.code === "ERR_INVALID_INPUT",
  );
});

test("import: rejects corrupted and spliced blobs", async () => {
  const w = await loadNode();
  const blob = w.shrincsKeygen(SEED, 4).exportSigningKey();
  assert.throws(
    () => w.shrincsImportSigningKey({ ...blob, nextStatefulLeafIndex: 0 }),
    (e) => e.code === "ERR_IMPORT_INVALID",
  );
  assert.throws(
    () => w.shrincsImportSigningKey({ ...blob, nextStatefulLeafIndex: 6 }),
    (e) => e.code === "ERR_IMPORT_INVALID",
  );
  assert.throws(
    () => w.shrincsImportSigningKey({ ...blob, statefulRoot: blob.hypertreeRoot }),
    (e) => e.code === "ERR_IMPORT_INVALID",
  );
});

test("import: exhausted key (counter = max + 1) imports; stateless still signs", async () => {
  const w = await loadNode();
  const blob = w.shrincsKeygen(SEED, 4).exportSigningKey();
  const kp = w.shrincsImportSigningKey({ ...blob, nextStatefulLeafIndex: 5 });
  assert.throws(() => kp.signStatefulRaw(MSG), (e) => e.code === "ERR_STATEFUL_LEAVES_EXHAUSTED");
  const pk = kp.publicKey();
  const sig = kp.signStatelessRaw(MSG);
  assert.equal(w.shrincsVerifyStatelessRaw(pk.publicKeyCommitment, pk, MSG, sig), true);
});

test("import: also works through the web loader", async () => {
  const w = await loadWeb();
  const blob = w.shrincsKeygen(SEED, 4).exportSigningKey();
  const { signature: sig } = w
    .shrincsImportSigningKey({ ...blob, nextStatefulLeafIndex: 3 })
    .signStatefulRaw(MSG);
  assert.equal(sig.authPath.length, 3);
});

test("observability: getters track the counter without touching secrets", async () => {
  const w = await loadNode();
  const kp = w.shrincsKeygen(SEED, 4);
  assert.equal(kp.nextStatefulLeafIndex, 1);
  assert.equal(kp.maxStatefulSignatures, 4);
  assert.equal(kp.remainingStatefulSignatures, 4);

  const r1 = kp.signStatefulRaw(MSG);
  assert.equal(r1.nextStatefulLeafIndex, 2);
  assert.equal(kp.nextStatefulLeafIndex, 2);
  assert.equal(kp.remainingStatefulSignatures, 3);
});

test("observability: exhausted key reports zero remaining and pre-checks", async () => {
  const w = await loadNode();
  const blob = w.shrincsKeygen(SEED, 4).exportSigningKey();
  const kp = w.shrincsImportSigningKey({ ...blob, nextStatefulLeafIndex: 5 });
  assert.equal(kp.remainingStatefulSignatures, 0);
  assert.throws(() => kp.signStatefulRaw(MSG), (e) => e.code === "ERR_STATEFUL_LEAVES_EXHAUSTED");
  assert.equal(kp.nextStatefulLeafIndex, 5); // pre-check mutated nothing
});

test("observability: signStatefulRawAt rejects out-of-range leaves with a typed code", async () => {
  const w = await loadNode();
  const kp = w.shrincsKeygen(SEED, 4);
  assert.throws(() => kp.signStatefulRawAt(MSG, 0), (e) => e.code === "ERR_LEAF_OUT_OF_RANGE");
  assert.throws(() => kp.signStatefulRawAt(MSG, 5), (e) => e.code === "ERR_LEAF_OUT_OF_RANGE");
});

test("version: wasm reports the package version through both loaders", async () => {
  const pkg = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.equal((await loadNode()).version(), pkg.version);
  assert.equal((await loadWeb()).version(), pkg.version);
});
