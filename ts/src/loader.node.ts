// Node.js loader.
//
// The Node build is wasm-bindgen's `nodejs` target: a CommonJS module that loads
// and instantiates the wasm itself on require (no async init needed). We reach it
// via `createRequire` so browser bundlers never try to resolve the CJS/`require`
// build — the `"browser"` field in package.json points them at loader.browser.js
// instead.
import { createRequire } from "node:module";

type ShrincsWasmModule = typeof import("./nodejs/hashsigs_rs.js");

let cached: ShrincsWasmModule | undefined;

export async function loadShrincsWasm(): Promise<ShrincsWasmModule> {
  if (cached) return cached;
  const require = createRequire(import.meta.url);
  cached = require("./nodejs/hashsigs_rs.js") as ShrincsWasmModule;
  return cached;
}
