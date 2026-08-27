// Per-profile packaging test: every published subpath resolves, loads its own
// wasm, and reports its own profile.
//
// This is the test the one-binary-per-profile layout needs. All six modules
// are structurally identical -- one Rust macro emits them all -- so TypeScript
// cannot tell them apart, `check-exports.mjs` only checks the exports map
// spells the right paths, and `conformance.test.mjs` drives a single profile.
// Nothing else would notice one profile's wasm sitting in another profile's
// directory, which is exactly what a build-loop bug produces.
//
// Cost: the 128s profiles are identity checked only. Their keygen through
// wasm costs about 53 seconds and signing about 52 more, which does not belong
// in a suite that gates every publish. Their crypto is covered natively by
// `cargo test` under each `profile-*` feature, and the Rust `wasm::tests`
// module drives the shared generic core at more than one profile.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const manifest = JSON.parse(
  readFileSync(new URL("../src/profiles/profiles.json", import.meta.url), "utf8")
);

// Signing is only exercised on profiles cheap enough to sign in a test run.
const FAST_PROFILES = new Set(["256s-keccak", "256s-sha2"]);

const hash32 = (label) => new Uint8Array(createHash("sha256").update(label).digest());

const loadProfile = (key) => import(`../dist/profiles/${key}/index.js`);

test("every published profile has an entry, and the default is one of them", () => {
  assert.ok(manifest.profiles.length > 0, "manifest lists no profiles");
  assert.ok(
    manifest.profiles.some((p) => p.key === manifest.default),
    `default ${manifest.default} is not in the profile list`
  );
});

for (const { key, name } of manifest.profiles) {
  test(`${key}: subpath loads and the binary reports its own profile`, async () => {
    const mod = await loadProfile(key);
    assert.equal(mod.PROFILE, key);
    assert.equal(mod.PROFILE_NAME, name);

    const hs = await mod.loadHashSigs();
    // The load-bearing assertion: the wasm's own PROFILE_NAME, compiled into
    // the binary from `<P as Profile>::PROFILE_NAME`, must match the profile
    // this subpath claims. A build loop that wrote the wrong binary here, or a
    // packages.sh name table gone stale, fails on this line and nowhere else.
    assert.equal(
      hs.profileName,
      name,
      `subpath "${key}" served a binary reporting "${hs.profileName}", expected "${name}"`
    );
  });

  test(`${key}: the browser loader serves the same profile as the node loader`, async () => {
    const browser = await import(`../dist/profiles/${key}/loader.browser.js`);
    const wasm = await browser.loadShrincsWasm();
    assert.equal(wasm.profileName(), name);
  });
}

test("no two profiles report the same name", async () => {
  // Six directories holding six copies of one binary would pass every
  // per-profile check above if the name table were equally wrong. Distinctness
  // is a second, independent way to catch it.
  const names = [];
  for (const { key } of manifest.profiles) {
    const hs = await (await loadProfile(key)).loadHashSigs();
    names.push(hs.profileName);
  }
  assert.equal(new Set(names).size, names.length, `duplicate profile names: ${names.join(", ")}`);
});

test("a signature from one profile does not verify under another", async () => {
  // The 256s keccak and sha2 twins share every parameter and differ only in
  // the scheme hash suite, so this is the pair that catches a subpath serving
  // its twin's binary -- a size or width check never would.
  const [a, b] = ["256s-keccak", "256s-sha2"];
  assert.ok(FAST_PROFILES.has(a) && FAST_PROFILES.has(b));

  const hsA = await (await loadProfile(a)).loadHashSigs();
  const hsB = await (await loadProfile(b)).loadHashSigs();

  const seed = new Uint8Array(32).fill(0x5a);
  const message = hash32("cross-profile-rejection");

  const keys = hsA.shrincs.keygen(seed, 4);
  const signature = hsA.shrincs.sign(message, keys);

  assert.equal(
    hsA.shrincs.verify(signature, message, keys.publicKeyCommitment),
    true,
    "the signing profile must accept its own signature"
  );
  assert.equal(
    hsB.shrincs.verify(signature, message, keys.publicKeyCommitment),
    false,
    `${b} accepted a ${a} signature: the two subpaths are serving the same binary`
  );
});

for (const key of FAST_PROFILES) {
  test(`${key}: keygen -> sign -> verify round-trips through its own subpath`, async () => {
    const hs = await (await loadProfile(key)).loadHashSigs();
    const seed = new Uint8Array(32).fill(0x33);
    const message = hash32(`round-trip-${key}`);

    const keys = hs.shrincs.keygen(seed, 4);
    const signature = hs.shrincs.sign(message, keys);
    assert.equal(hs.shrincs.verify(signature, message, keys.publicKeyCommitment), true);

    const tampered = signature.slice();
    tampered[0] ^= 1;
    assert.equal(hs.shrincs.verify(tampered, message, keys.publicKeyCommitment), false);
  });
}
