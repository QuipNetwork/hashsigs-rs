# Releasing hashsigs-rs

One `v<X.Y.Z>` git tag publishes every artifact.

| # | Artifact | Registry | Published by |
|---|----------|----------|--------------|
| 1 | `@quip.network/hashsigs-wasm` | npm | `publish-npm`, staged for approval |
| 2 | `hashsigs-rs` | crates.io | `publish-crates`, automatic |
| 3 | `hashsigs` | PyPI | `publish-pypi`, automatic |

That is the whole list today. The PyPI wheel is a stub until the Python
bindings plan lands: it installs and exposes `__version__`, nothing else,
and every stub release is a prerelease so default pip resolution never
picks it. Later plans add the real Python API, the npm profile siblings,
and the C tarballs.

**Know what each registry lets you undo.** npm allows unpublishing a version
within 72 hours. PyPI lets you delete a release, but the filename stays
reserved permanently. Crates.io allows only yanking. It does not allow
replacing or re-uploading a version. `publish-crates` is deliberately
automatic and runs only after `tag-gate` and `release:validate` pass on the
tag; once it runs, that version number is spent. The npm release stays
staged until a maintainer approves it, so npm can go live after crates.io
has already published.

## Prerequisites (one-time)

**No registry tokens are stored anywhere.** `publish-npm` authenticates with
OpenID Connect through `NPM_ID_TOKEN`, and signs a provenance attestation
through `SIGSTORE_ID_TOKEN`. The job pins `tags: [saas-linux-small-amd64]`
because npm accepts an attestation only from a GitLab-hosted runner. Moving
that job to a private runner loses provenance without warning.

**The npm trusted publisher** is already configured for
`@quip.network/hashsigs-wasm`.

**The crates.io trusted publisher** must name this project. On crates.io,
open `hashsigs-rs` > Settings > Trusted Publishing and add a GitLab
publisher: namespace `quip.network`, project `hashsigs-rs`, top-level
pipeline file `.gitlab-ci.yml`, environment `cargo`. The environment name
must match the `environment:` on the `publish-crates` job exactly. GitLab
support is a public beta and works only for projects on gitlab.com.

**The PyPI trusted publisher** is already configured for `hashsigs`
(project `quip.network/hashsigs-rs`, pipeline `.gitlab-ci.yml`, environment
`pypi`). `publish-pypi` builds and uploads through it with maturin.

**The package must already exist on npm.** CI stages releases, it does not
create packages. A brand new package name needs a one-time manual
`npm publish` from a maintainer's machine with 2FA before any tag pipeline can
work. The job checks for this and fails with instructions rather than a
cryptic npm error.

**Protected tags**: the GitLab UI path is Settings > Repository > Protected
tags. Set the pattern to `v*` and restrict creation to maintainers.

## Pre-flight

1. **Watch `release:validate`.** It runs on merge request pipelines, on the
   default branch, and on every tag, using the same build path the publish
   jobs use, and it fails before it touches any registry. A push to a feature
   branch with no open merge request does not run it. Do not merge a release
   branch while it is red on the default branch.
2. **Run the same gate locally** with `make -k check-release`. It needs a Rust
   toolchain, the `wasm32-unknown-unknown` target, the `wasm-bindgen` CLI at
   the version `Cargo.toml` pins, and `node` with `npm`. The npm leg installs
   its own JavaScript dependencies.
3. **Check the version.** Every manifest must carry the version being
   tagged. `make check-versions` proves it.

## Cutting a release

```sh
# 1. Branch.
git checkout -b release/vX.Y.Z main

# 2. Bump the version in Cargo.toml and ts/package.json, then refresh
#    Cargo.lock.
cargo check

# 3. Prove the tree is publishable.
make -k check-release

# 4. Open the merge request, get it reviewed, merge it.

# 5. Tag.
git tag vX.Y.Z && git push origin vX.Y.Z
```

## After the tag, approve the staged release

**The tag pipeline does not make the release live.** `publish-npm` runs
`npm stage publish`, which puts the tarball in a staging area awaiting
maintainer approval. Run `npm stage approve` with 2FA to release it. Until you
do, the version is not installable.

The dist-tag is derived from the version, not always `latest`. A plain
`X.Y.Z` stages on `latest`. A prerelease stages on the alphabetic part of its
prerelease identifier, so `0.2.0-rc.2` goes to `rc` and `0.3.0-beta.1` goes to
`beta`. This is what keeps `npm install @quip.network/hashsigs-wasm` from
picking up a release candidate.

**The crate and the wheel need no approval step.** `publish-crates` and
`publish-pypi` publish as soon as the gates pass on the tag. Confirm the
version appears on crates.io and PyPI. If a crate release must be pulled
back, `cargo yank` is the only tool, and the version number stays spent.
A PyPI release can be deleted, but its filenames stay reserved.

## When a tag is cut against a red tree

Nothing is lost and nothing leaks. The tag pipeline runs `release:validate`
again ahead of every publish job, so it fails at the same step with no
registry touched. Delete the tag, fix the cause, and re-cut.
