// Doc-conformance test: extracts the runnable ```ts code blocks from the
// root README and the ts package README and executes each against the BUILT
// package (dist/), so the documented examples can never drift from the real
// API. A renamed/removed method or a wrong object shape in the docs makes the
// corresponding block throw here.
//
// Only blocks that call `loadHashSigs(` run; type-only blocks (the `interface`
// object-shape listings) and shell blocks are skipped. Each block runs in
// isolation with the doc placeholders it uses but does not itself declare
// (`message32`, `maxSignatures`, `keys`) injected as bindings.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadHashSigs, shrincsKeysToSecretBytes } from "../dist/index.js";

const README_FILES = [
  ["root README", new URL("../../README.md", import.meta.url)],
  ["ts README", new URL("../README.md", import.meta.url)],
];

const SEED = new Uint8Array(32).fill(0xab);
// A stand-in for the `message32` the docs leave to the caller: a 32-byte hash.
const MESSAGE32 = new Uint8Array(
  (await import("node:crypto")).createHash("sha256").update("readme-example").digest(),
);
const MAX_SIGNATURES = 4;
const CRYPTO = globalThis.crypto ?? (await import("node:crypto")).webcrypto;

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

/** Extract the bodies of all ```ts fenced blocks. */
function tsBlocks(markdown) {
  return [...markdown.matchAll(/```ts\n([\s\S]*?)```/g)].map((m) => m[1]);
}

/** A block is runnable if it actually loads the library. */
function isRunnable(body) {
  return body.includes("loadHashSigs(");
}

function usesIdent(body, ident) {
  return new RegExp(`\\b${ident}\\b`).test(body);
}

function declaresIdent(body, ident) {
  return new RegExp(`\\b(?:const|let|var)\\s+${ident}\\b`).test(body);
}

/**
 * Turn a documented block into a callable: strip the package import (the test
 * supplies those symbols as bindings), inject the placeholders the block uses
 * but does not declare, and return any `ok`/`okRecovery` the example computes
 * so the caller can assert the crypto actually succeeded.
 */
async function runBlock(body) {
  const stripped = body.replace(/^\s*import\b[^\n]*hashsigs-wasm[^\n]*;\s*$/gm, "");

  // Always available (they replace the stripped import + a global).
  const params = { loadHashSigs, shrincsKeysToSecretBytes, crypto: CRYPTO };
  // Injected only when used-but-not-declared, so a block's own `const keys`
  // (etc.) never collides with an injected binding of the same name.
  const placeholders = {
    message32: MESSAGE32,
    maxSignatures: MAX_SIGNATURES,
    keys: (await loadHashSigs()).shrincs.keygen(SEED, MAX_SIGNATURES),
  };
  for (const [name, value] of Object.entries(placeholders)) {
    if (usesIdent(stripped, name) && !declaresIdent(stripped, name)) {
      params[name] = value;
    }
  }

  const source =
    stripped +
    "\n;return {" +
    "  ok: (typeof ok !== 'undefined') ? ok : true," +
    "  okRecovery: (typeof okRecovery !== 'undefined') ? okRecovery : true," +
    "};";

  const fn = new AsyncFunction(...Object.keys(params), source);
  return fn(...Object.values(params));
}

for (const [label, url] of README_FILES) {
  const blocks = tsBlocks(readFileSync(url, "utf8")).filter(isRunnable);

  test(`${label}: has runnable code examples to check`, () => {
    assert.ok(blocks.length > 0, `no runnable \`\`\`ts examples found in ${label}`);
  });

  blocks.forEach((body, index) => {
    const firstLine =
      body.split("\n").find((l) => l.trim() && !l.trim().startsWith("import")) ?? "";
    test(`${label}: example #${index + 1} runs and verifies (${firstLine.trim().slice(0, 60)})`, async () => {
      const result = await runBlock(body);
      assert.equal(result.ok, true, "documented `ok` result must be true");
      assert.equal(result.okRecovery, true, "documented `okRecovery` result must be true");
    });
  });
}
