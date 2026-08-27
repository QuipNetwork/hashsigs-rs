// Fail the build when package.json's exports map and the built profile set
// disagree.
//
// The exports map is hand-written (npm reads it verbatim, and generating it
// would churn package.json on every build), while the profile set comes from
// bin/packages.sh. Nothing else connects the two: a profile added to
// packages.sh and built into dist/ but missing from exports is unreachable by
// consumers, and an exports entry with no built profile is a broken import
// path that only fails at install time.
import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const { profiles, default: defaultProfile } = JSON.parse(
  readFileSync(new URL("src/profiles/profiles.json", root), "utf8")
);
const pkg = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));

const fail = (message) => {
  console.error(`FAIL: ${message}`);
  process.exit(1);
};

const subpaths = Object.keys(pkg.exports).filter((key) => key !== ".");
const expected = profiles.map(({ key }) => `./${key}`);

for (const want of expected) {
  if (!subpaths.includes(want)) {
    fail(`package.json exports has no "${want}" entry, but that profile is built and shipped`);
  }
}
for (const got of subpaths) {
  if (!expected.includes(got)) {
    fail(`package.json exports declares "${got}", which is not a built profile`);
  }
}

// Every subpath must point inside its own profile directory. A copy-paste slip
// here would silently serve one profile's wasm under another's import path,
// and no type or test would notice: the six modules are structurally identical.
for (const { key: profile } of profiles) {
  const entry = pkg.exports[`./${profile}`];
  for (const [condition, target] of Object.entries(entry)) {
    if (!target.startsWith(`./dist/profiles/${profile}/`)) {
      fail(
        `exports["./${profile}"].${condition} points at ${target}, which is not inside ` +
          `./dist/profiles/${profile}/ -- that would serve the wrong profile's binary`
      );
    }
  }
}

// The root export is the default profile. It reaches the same files through
// ./dist/index.js, which re-exports that profile.
const rootTypes = pkg.exports["."].types;
if (!rootTypes.startsWith("./dist/index")) {
  fail(`exports["."].types is ${rootTypes}; the root entry must be the generated ./dist/index`);
}
if (!pkg.exports["."].browser.startsWith(`./dist/profiles/${defaultProfile}/`)) {
  fail(
    `exports["."].browser must resolve inside the default profile (${defaultProfile}), ` +
      `got ${pkg.exports["."].browser}`
  );
}

console.log(`exports map matches ${profiles.length} built profiles (default ${defaultProfile})`);
