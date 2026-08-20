# Copyright (C) 2026 quip.network
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Release checks for hashsigs-rs.
#
# check-release answers one question: is this tree publishable? CI runs it on
# every pipeline through release:validate, before any job touches a registry.
#
# It is an aggregate of prerequisites, NOT a wrapper script, and CI invokes it
# with `make -k`. A script under `set -euo pipefail` would stop at the first
# failure, so a broken crate manifest would hide a broken npm package and the
# next pipeline would find it instead of this one.

.DEFAULT_GOAL := help

.PHONY: help clean check-release check-versions check-packages \
	check-crate-publish check-npm-dists

# Every manifest carries the root Cargo.toml version.
check-versions:
	bash bin/sync-versions.sh check
	bash bin/tests/test-sync-versions.sh

# Every profile has a package in every ecosystem.
check-packages:
	bash bin/tests/test-packages.sh

# `cargo package`, not `cargo publish --dry-run`. Both verify the same way,
# but `package` stays entirely local: it never enters the upload path, so this
# gate cannot fail on registry state, and it leaves the .crate tarball behind
# for CI to publish as the artifact it just validated.
#
# The stale tarball is deleted first. Cargo leaves an existing .crate in place
# when it does not write one, so a leftover from an earlier version silently
# becomes the thing a later smoke test validates.
#
# One crate, named explicitly. `--workspace` is nightly-only for `publish` and,
# for `package`, does NOT skip publish = false crates the way `publish` does --
# it would fail on the first binding crate whose path dependency has no
# version. Naming the one publishable crate sidesteps both.
#
# --locked so packaging resolves the committed Cargo.lock. Without it a drifted
# lock file passes here and fails in the real publish.
#
# This fails on a dirty working tree, by design. A release check that passes
# on uncommitted changes is checking a tree that will never be published.
check-crate-publish:
	find target/package -maxdepth 1 -name '*.crate' -delete 2>/dev/null || true
	cargo package --locked -p hashsigs-rs
	@ls -la target/package/*.crate

# Pack the npm tarball, install it outside the repository, and import it.
check-npm-dists:
	bash bin/npm-dists.sh check

# The full gate. Later plans add check-python-dists and check-c-artifacts.
check-release: check-versions check-packages check-crate-publish check-npm-dists

help:
	@echo "check-release          every publish path, dry-run only (no registry writes)"
	@echo "  check-versions         every manifest carries the root Cargo.toml version"
	@echo "  check-packages         every profile has a package in every ecosystem"
	@echo "  check-crate-publish    cargo package the crate, no upload path"
	@echo "  check-npm-dists        pack the npm tarball and import it outside the repo"

# Only build output. `ts/dist` is the compiled TypeScript, and a packed
# tarball left in ts/ is what the CI publish job would otherwise pick up.
clean:
	rm -rf ts/dist
	rm -f ts/*.tgz
	cargo clean
