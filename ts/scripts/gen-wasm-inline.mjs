// Base64-encode the web-target wasm into a TS module so the browser loader can
// instantiate it from bytes with no separate `.wasm` asset. Must run before tsc.
import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const wasmPath = new URL("src/web/hashsigs_rs_bg.wasm", root);
const outPath = new URL("src/web/inline.ts", root);

const b64 = readFileSync(wasmPath).toString("base64");
// Annotate `: string` so tsc emits `export declare const wasmBase64: string;`
// rather than inlining the entire ~480kB base64 literal into the .d.ts.
writeFileSync(outPath, `export const wasmBase64: string = "${b64}";\n`);

console.log(`inlined ${wasmPath.pathname} -> ${outPath.pathname} (${b64.length} base64 chars)`);
