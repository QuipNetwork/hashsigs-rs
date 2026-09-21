#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

fail() {
    echo "production-profile policy check failed: $1" >&2
    exit 1
}

for feature in \
    experimental-profile-128s-q18 \
    experimental-profile-128s-q20 \
    experimental-profile-128s-q18-sha2 \
    experimental-profile-128s-q20-sha2
do
    grep -Eq "^${feature}[[:space:]]*=" Cargo.toml || \
        fail "missing Cargo feature ${feature}"
done

if grep -Eq '^profile-128s-q(18|20)(-sha2)?[[:space:]]*=' Cargo.toml; then
    fail "a 128-bit Cargo feature is not marked experimental"
fi

if grep -E '^default[[:space:]]*=' Cargo.toml | grep -q '128s'; then
    fail "a 128-bit profile is selected by default"
fi

if grep -q 'experimental-profile-128s' .gitlab/ci/release.yml; then
    fail "a release job explicitly selects an experimental 128-bit profile"
fi

echo "production-profile policy check passed"
