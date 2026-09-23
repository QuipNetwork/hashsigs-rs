# syntax=docker/dockerfile:1
FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:4388cbb83c1a78181b04a3cabd6041b9e6044b47068a3aa63ae8e2a2b31acb66

USER root
ENV RUSTUP_TOOLCHAIN=nightly-2026-04-15 \
    RUSTFLAGS="-Wwarnings -Zunstable-options" \
    BOLOS_SDK=/opt/apex-secure-sdk \
    HEAP_SIZE=20480 \
    PYTHONUNBUFFERED=1
RUN rustup toolchain install nightly-2026-04-15 --profile minimal --component rust-src,rustfmt
# Reuse the Gen5 target specification pinned by the builder image.
RUN cp -a /opt/rustup/toolchains/nightly-2025-12-05-x86_64-unknown-linux-gnu/lib/rustlib/apex_p /opt/rustup/toolchains/nightly-2026-04-15-x86_64-unknown-linux-gnu/lib/rustlib/
RUN cp /opt/rustup/toolchains/nightly-2025-12-05-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/link_wrap.sh /opt/rustup/toolchains/nightly-2026-04-15-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/
RUN python3 -m venv --system-site-packages /opt/hashsigs-ledger-venv
ENV PATH="/opt/hashsigs-ledger-venv/bin:${PATH}"
COPY ledger/requirements.txt /opt/hashsigs-ledger-requirements.txt
RUN python -m pip install --no-cache-dir -r /opt/hashsigs-ledger-requirements.txt
# Import concrete modules: Ragger's public API substitutes missing backends with
# functions that raise only when a test starts. This check needs no USB device.
RUN python -c "from ragger.backend.ledgerwallet import LedgerWalletBackend; from ragger.backend.speculos import SpeculosBackend"

WORKDIR /repo
COPY Cargo.toml build.rs ./
COPY src/ src/
COPY ledger/app/ ledger/app/
WORKDIR /repo/ledger/app
RUN cargo ledger build apex_p -- --locked

WORKDIR /repo/ledger
COPY ledger/host/ host/
RUN cargo run --locked --release --manifest-path host/Cargo.toml > /tmp/ledger-vectors.json
RUN mkdir -p artifacts && cp /tmp/ledger-vectors.json artifacts/vectors.json
COPY ledger/ledger_app.toml ledger/pytest.ini ledger/conftest.py ./
COPY ledger/tests/ tests/
COPY ledger/benchmarks/ benchmarks/
# Ragger discovers ledger_app.toml from this container-local Git root.
RUN git init --quiet /repo/ledger
ENTRYPOINT []
CMD ["python", "-m", "pytest", "--device", "apex_p", "--backend", "speculos", "-v"]
