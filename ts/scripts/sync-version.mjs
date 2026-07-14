// Verify ts/package.json `version` matches the crate version in ../Cargo.toml
// (the same value env!("CARGO_PKG_VERSION") bakes into the wasm). Does NOT
// rewrite package.json — it FAILS the build if they disagree, so a release
// can't ship a mismatched version. Wired into `npm run build` (and `prepack`).
import { readFileSync } from "node:fs";

const cargo = readFileSync(new URL("../../Cargo.toml", import.meta.url), "utf8");
const crateVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!crateVersion) throw new Error("could not read version from Cargo.toml");

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
if (pkg.version !== crateVersion) {
  throw new Error(
    `version mismatch: ts/package.json is "${pkg.version}" but Cargo.toml is "${crateVersion}". ` +
    `Bump both to the same version `
  );
}

console.log(`version check ✓ package.json (${pkg.version}) matches Cargo.toml`);