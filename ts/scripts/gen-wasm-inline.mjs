// Base64-encode each profile's web-target wasm into a TS module so that
// profile's browser loader can instantiate it from bytes with no separate
// `.wasm` asset. Must run before tsc.
//
// One inline module per profile is the point of shipping one binary per
// profile: a browser consumer importing "@quip.network/hashsigs-wasm/128s-q18"
// pulls in that profile's base64 string and nothing else. A single combined
// binary would put every profile inside one string literal, which no bundler
// can split.
import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const { profiles } = JSON.parse(
  readFileSync(new URL("src/profiles/profiles.json", root), "utf8")
);

for (const { key: profile } of profiles) {
  const wasmPath = new URL(`src/profiles/${profile}/web/hashsigs_rs_bg.wasm`, root);
  const outPath = new URL(`src/profiles/${profile}/web/inline.ts`, root);

  const b64 = readFileSync(wasmPath).toString("base64");
  // Annotate `: string` so tsc emits `export declare const wasmBase64: string;`
  // rather than inlining the entire base64 literal into the .d.ts.
  writeFileSync(outPath, `export const wasmBase64: string = "${b64}";\n`);

  console.log(`inlined ${profile} (${b64.length} base64 chars)`);
}
