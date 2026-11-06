DOCKER ?= docker
IMAGE ?= hashsigs-ledger:local
LEDGER_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_DIR := $(abspath $(LEDGER_DIR)/..)
USB_DEVICE ?=
BENCH_SAMPLES ?= 30
BENCH_WARMUP ?= 5
BENCH_RUN := $(shell date -u +%Y%m%dT%H%M%SZ)
BENCH_OUTPUT ?= $(LEDGER_DIR)/artifacts/benchmarks/$(BENCH_RUN)
WALLET_ARGS ?=
WALLET_TIMEOUT ?= 180
RUN = $(DOCKER) run --rm --network none --user "$$(id -u):$$(id -g)"

.PHONY: help check-docker build check test run test-hardware wallet-hardware bench-hardware measure build-nvm-diag test-nvm-diag build-hw-check test-hw-check build-launch-check test-launch-check build-keygen-bench test-keygen-bench
.DEFAULT_GOAL := help

help:
	@echo 'make -C ledger check-docker   Check Docker installation and daemon access'
	@echo 'make -C ledger build          Build the app and export ELF and public test vectors'
	@echo 'make -C ledger check          Check app and host Rust formatting'
	@echo 'make -C ledger test           Run the Gen5 Speculos suite'
	@echo 'make -C ledger measure        Build a separate metrics ELF and measure keygen in Speculos'
	@echo 'make -C ledger test-nvm-diag   Build and test the separate PUBLIC-fixture storage diagnostic app'
	@echo 'make -C ledger test-hw-check   Build and test the separate resource/permission app'
	@echo 'make -C ledger test-launch-check Build and test the SDK-only launch/exit control'
	@echo 'make -C ledger test-keygen-bench Build and test full-budget (4096 signatures) key generation'
	@echo 'make -C ledger run            Open Speculos at http://localhost:5000'
	@echo 'make -C ledger test-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD'
	@echo 'make -C ledger wallet-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD BENCH_OUTPUT=... WALLET_ARGS="snapshot --output /out/state.json"'
	@echo 'make -C ledger bench-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD'

check-docker:
	@sh "$(LEDGER_DIR)/check-docker.sh" $(DOCKER)

build: check-docker
	$(DOCKER) build --file $(LEDGER_DIR)/Dockerfile --tag $(IMAGE) $(REPO_DIR)
	mkdir -p $(LEDGER_DIR)/artifacts
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/app/target/apex_p/release/hashsigs-ledger /out/app.elf && cp /repo/ledger/artifacts/vectors.json /out/vectors.json && cd /out && sha256sum app.elf vectors.json > SHA256SUMS'

check: build
	$(RUN) $(IMAGE) cargo fmt --manifest-path app/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path host/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path common/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path nvm-diag/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path hw-check/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path launch-check/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path keygen-bench/Cargo.toml --check
	$(DOCKER) run --rm --network none $(IMAGE) cargo test --locked --release --manifest-path common/Cargo.toml
	$(RUN) $(IMAGE) python -B -m pytest hardware --confcutdir=hardware -q

test: check
	$(RUN) $(IMAGE) python -m pytest --device apex_p --backend speculos $(PYTEST_ARGS)

build-nvm-diag: build
	mkdir -p $(LEDGER_DIR)/artifacts/nvm-diag
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts/nvm-diag,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/nvm-diag/target/apex_p/release/hashsigs-ledger-nvm-diag /out/app.elf && cp /repo/ledger/nvm-diag/target/apex_p/release/*.apdu /out/ && cp /repo/ledger/nvm-diag/fixtures.bin /out/ && cd /out && sha256sum app.elf fixtures.bin > SHA256SUMS'

test-nvm-diag: build-nvm-diag
	$(RUN) $(IMAGE) python -B -m pytest nvm-diag/tests --confcutdir=nvm-diag -v $(PYTEST_ARGS)

build-hw-check: build
	mkdir -p $(LEDGER_DIR)/artifacts/hw-check
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts/hw-check,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/hw-check/target/apex_p/release/hashsigs-ledger-hw-check /out/app.elf && cp /repo/ledger/hw-check/target/apex_p/release/*.apdu /out/ && cd /out && sha256sum app.elf > SHA256SUMS'

test-hw-check: build-hw-check
	$(RUN) $(IMAGE) python -B -m pytest hw-check/tests --confcutdir=hw-check -v $(PYTEST_ARGS)

build-launch-check: build
	mkdir -p $(LEDGER_DIR)/artifacts/launch-check
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts/launch-check,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/launch-check/target/apex_p/release/hashsigs-ledger-launch-check /out/app.elf && cp /repo/ledger/launch-check/target/apex_p/release/*.apdu /out/ && cd /out && sha256sum app.elf > SHA256SUMS'

test-launch-check: build-launch-check
	$(RUN) $(IMAGE) python -B -m pytest launch-check/tests --confcutdir=launch-check -v $(PYTEST_ARGS)

build-keygen-bench: build
	mkdir -p $(LEDGER_DIR)/artifacts/keygen-bench
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts/keygen-bench,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/keygen-bench/target/apex_p/release/hashsigs-ledger-keygen-bench /out/app.elf && cp /repo/ledger/keygen-bench/target/apex_p/release/*.apdu /out/ && cd /out && sha256sum app.elf > SHA256SUMS'

test-keygen-bench: build-keygen-bench
	$(RUN) $(IMAGE) python -B -m pytest keygen-bench/tests --confcutdir=keygen-bench -v -s --timeout=1800 $(PYTEST_ARGS)

run: build
	$(DOCKER) run --rm -it --user "$$(id -u):$$(id -g)" --publish 127.0.0.1:5000:5000 $(IMAGE) \
		python -m speculos --model apex_p --display headless --api-port 5000 /repo/ledger/app/target/apex_p/release/hashsigs-ledger

# The operator installs and opens the app first. No seed setup or app installation
# happens here. Only this explicit target exposes the selected USB device.
# A native HID read may ignore Python's signal timeout; a thread watchdog exits
# the runner after the configured test timeout. Stop on the first USB failure.
test-hardware: build
	@test -n "$(USB_DEVICE)" || { echo 'Set USB_DEVICE to the connected Ledger USB device node.'; exit 2; }
	@test -c "$(USB_DEVICE)" || { echo 'USB_DEVICE must be a character device.'; exit 2; }
	$(RUN) --device "$(USB_DEVICE)" --group-add "$$(stat -c %g "$(USB_DEVICE)")" $(IMAGE) \
		python -m pytest --device apex_p --backend ledgerwallet -m 'not emulator_only' --timeout-method=thread -x $(PYTEST_ARGS)

# Operator-assisted creation/rejection and public-state comparisons. Reports
# never contain secret material. Existing keys are not replaced. A wall-clock
# timeout also bounds native HID reads while waiting for manual approval.
wallet-hardware: build
	@test -n "$(USB_DEVICE)" && test -c "$(USB_DEVICE)" || { echo 'Set USB_DEVICE to the connected Ledger character device.'; exit 2; }
	@test -n "$(WALLET_ARGS)" || { echo 'Set WALLET_ARGS to the action and --output /out/report.json.'; exit 2; }
	mkdir -p "$(BENCH_OUTPUT)"
	$(RUN) --device "$(USB_DEVICE)" --group-add "$$(stat -c %g "$(USB_DEVICE)")" \
		--mount "type=bind,src=$(LEDGER_DIR),dst=/lab,readonly" \
		--mount "type=bind,src=$(BENCH_OUTPUT),dst=/out" $(IMAGE) \
		timeout $(WALLET_TIMEOUT) python -B -u /lab/hardware/wallet_check.py $(WALLET_ARGS)

# Verification timings use the same installed app and public fixtures. The
# benchmark directory is outside pytest's default testpaths, so normal tests
# never run these repeated measurements. Each run keeps separate raw reports.
bench-hardware: build
	@test -n "$(USB_DEVICE)" || { echo 'Set USB_DEVICE to the connected Ledger USB device node.'; exit 2; }
	@test -c "$(USB_DEVICE)" || { echo 'USB_DEVICE must be a character device.'; exit 2; }
	mkdir -p "$(BENCH_OUTPUT)"
	$(RUN) --device "$(USB_DEVICE)" --group-add "$$(stat -c %g "$(USB_DEVICE)")" \
		--mount "type=bind,src=$(BENCH_OUTPUT),dst=/out" \
		--env LEDGER_BENCH_OUTPUT=/out --env LEDGER_BENCH_SAMPLES=$(BENCH_SAMPLES) \
		--env LEDGER_BENCH_WARMUP=$(BENCH_WARMUP) $(IMAGE) \
		python -m pytest benchmarks/test_verify_timing.py --device apex_p --backend ledgerwallet --timeout-method=thread -x -s -v $(PYTEST_ARGS)

# The metrics build is made inside a disposable container. The ordinary app.elf
# and its production APDU surface remain unchanged.
measure: build
	mkdir -p "$(BENCH_OUTPUT)"
	$(DOCKER) run --rm --network none --mount "type=bind,src=$(BENCH_OUTPUT),dst=/out" --env LEDGER_BENCH_OUTPUT=/out $(IMAGE) \
		sh -c 'cd app && cargo ledger build apex_p -- --locked --no-default-features --features memory-metrics && cp target/apex_p/release/hashsigs-ledger /out/app-metrics.elf && cd .. && python -m pytest benchmarks/test_keygen_resources.py --device apex_p --backend speculos -x -s --tb=short'
