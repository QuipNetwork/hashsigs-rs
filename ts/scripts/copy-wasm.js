// tsc only emits the compiled `.ts` files. The wasm-bindgen output (`.js`,
// `_bg.wasm`, `.d.ts`) is not TypeScript, so copy each profile's generated
// nodejs/ and web/ directories into dist/ verbatim after tsc runs.
import { cpSync, readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const { profiles } = JSON.parse(
  readFileSync(new URL("src/profiles/profiles.json", root), "utf8")
);

for (const { key: profile } of profiles) {
  for (const target of ["nodejs", "web"]) {
    cpSync(
      new URL(`src/profiles/${profile}/${target}`, root),
      new URL(`dist/profiles/${profile}/${target}`, root),
      {
        recursive: true,
        // inline.ts is a generated source; tsc already emits inline.js/.d.ts to
        // dist. Don't copy the raw .ts (avoids shipping the base64 a second time).
        filter: (src) => !src.endsWith("inline.ts"),
      }
    );
  }

  // The root package is an ES module ("type": "module"), so Node treats every
  // nested `.js` as ESM by extension. wasm-bindgen's nodejs target is CommonJS
  // (module.exports / require / __dirname), so mark that directory as CommonJS
  // with a scoped package.json. The web target is ESM and inherits correctly.
  writeFileSync(
    new URL(`dist/profiles/${profile}/nodejs/package.json`, root),
    `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`
  );
}

console.log(`copied ${profiles.length} profiles' wasm-bindgen output into dist/profiles/`);
