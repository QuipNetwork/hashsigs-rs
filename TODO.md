# TODO

## `bin/build-wasm.sh` is broken with the current toolchain

`bin/build-wasm.sh` shells out to `wasm-pack build`, which internally runs
`cargo build --out-dir <tmp>`. Cargo 1.93 renamed `--out-dir` to the
nightly-only `--artifact-dir`, so the build aborts:

```
warning: the --out-dir flag has been changed to --artifact-dir
error: the `--artifact-dir` flag is unstable, and only available on the nightly channel
```

Observed with `wasm-pack 0.15.0` + `cargo 1.93.0`. Passing the build to nightly
only changes the error to `--artifact-dir is unstable, pass -Z unstable-options`,
and wasm-pack's `-- <cargo args>` passthrough does not place `-Z` where cargo
accepts it. So `wasm-pack` is currently unusable here.

### Working recipe (manual two-step)

`wasm-pack` just wraps `cargo build` + `wasm-bindgen`. Do those two steps directly:

```sh
# 1. Compile the cdylib to the wasm target (no --out-dir involved)
cargo build --release --target wasm32-unknown-unknown --features wasm-bindings

# 2. Generate the JS/TS bindings. The wasm-bindgen CLI version MUST match the
#    `wasm-bindgen` crate version pinned in Cargo.lock (currently 0.2.100).
#    Install once: cargo install wasm-bindgen-cli --version 0.2.100
wasm-bindgen target/wasm32-unknown-unknown/release/hashsigs_rs.wasm \
  --out-dir pkg/<target> --target <target>     # <target> = nodejs | web | bundler
```

Prerequisites: `rustup target add wasm32-unknown-unknown`, and
`wasm-bindgen-cli` pinned to the crate's `wasm-bindgen` version (a mismatch fails
the schema-version check). `wasm-opt` is optional (binaryen) for size optimization.

### Fix options

- Update `bin/build-wasm.sh` to perform the manual two-step above instead of
  calling `wasm-pack`, or
- Pin a `cargo`/`wasm-pack` combination that is mutually compatible, or
- Wait for a `wasm-pack` release that emits `--artifact-dir -Z unstable-options`
  (or stops using `--out-dir`) and document the required nightly/cargo versions.
