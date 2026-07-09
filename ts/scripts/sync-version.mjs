// Sync ts/package.json `version` from the crate version in ../Cargo.toml —
// the same value `env!("CARGO_PKG_VERSION")` bakes into the wasm binary.
// Cargo.toml is the single source of truth; never edit package.json's
// version by hand. Wired into `npm run build` (and therefore `prepack`).
import { readFileSync, writeFileSync } from "node:fs";

const cargo = readFileSync(new URL("../../Cargo.toml", import.meta.url), "utf8");
const version = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version) throw new Error("could not read version from Cargo.toml");

const pkgPath = new URL("../package.json", import.meta.url);
const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
if (pkg.version !== version) {
  pkg.version = version;
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`package.json version → ${version}`);
}
