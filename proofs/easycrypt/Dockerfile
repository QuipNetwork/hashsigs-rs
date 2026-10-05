# SPDX-License-Identifier: AGPL-3.0-or-later
# Toolchain: EasyCrypt release r2026.02 with Alt-Ergo 2.6.0 and Z3 4.13.4.
# The digest is the image that the tag r2026.02 named on 2026-10-05.
FROM ghcr.io/easycrypt/ec-test-box@sha256:bf1a13e73d7fe18fccdcc91d1532c1a5a17cfc3a6a2a34619248c4f2710d0bb3

# The base image sets the user charlie (uid 1001, group root).
WORKDIR /work
COPY --chown=charlie:root . /work

ENTRYPOINT ["opam", "exec", "--"]
CMD ["make", "check"]
