DOCKER ?= docker
IMAGE ?= hashsigs-ledger:local
LEDGER_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_DIR := $(abspath $(LEDGER_DIR)/..)
USB_DEVICE ?=
RUN = $(DOCKER) run --rm --network none --user "$$(id -u):$$(id -g)"

.PHONY: help build check test run test-hardware
.DEFAULT_GOAL := help

help:
	@echo 'make -C ledger build          Build the app and export ELF and public test vectors'
	@echo 'make -C ledger check          Check app and host Rust formatting'
	@echo 'make -C ledger test           Run the Gen5 Speculos suite'
	@echo 'make -C ledger run            Open Speculos at http://localhost:5000'
	@echo 'make -C ledger test-hardware USB_DEVICE=/dev/bus/usb/BBB/DDD'

build:
	$(DOCKER) build --file $(LEDGER_DIR)/Dockerfile --tag $(IMAGE) $(REPO_DIR)
	mkdir -p $(LEDGER_DIR)/artifacts
	$(RUN) --mount "type=bind,src=$(LEDGER_DIR)/artifacts,dst=/out" $(IMAGE) \
		sh -c 'cp /repo/ledger/app/target/apex_p/release/hashsigs-ledger /out/app.elf && cp /repo/ledger/artifacts/vectors.json /out/vectors.json && cd /out && sha256sum app.elf vectors.json > SHA256SUMS'

check: build
	$(RUN) $(IMAGE) cargo fmt --manifest-path app/Cargo.toml --check
	$(RUN) $(IMAGE) cargo fmt --manifest-path host/Cargo.toml --check

test: check
	$(RUN) $(IMAGE) python -m pytest --device apex_p --backend speculos $(PYTEST_ARGS)

run: build
	$(DOCKER) run --rm -it --user "$$(id -u):$$(id -g)" --publish 127.0.0.1:5000:5000 $(IMAGE) \
		python -m speculos --model apex_p --display headless --api-port 5000 /repo/ledger/app/target/apex_p/release/hashsigs-ledger

# The operator installs and opens the app first. No seed setup or app installation
# happens here. Only this explicit target exposes the selected USB device.
test-hardware: build
	@test -n "$(USB_DEVICE)" || { echo 'Set USB_DEVICE to the connected Ledger USB device node.'; exit 2; }
	@test -c "$(USB_DEVICE)" || { echo 'USB_DEVICE must be a character device.'; exit 2; }
	$(RUN) --device "$(USB_DEVICE)" --group-add "$$(stat -c %g "$(USB_DEVICE)")" $(IMAGE) \
		python -m pytest --device apex_p --backend ledgerwallet -m 'not emulator_only' $(PYTEST_ARGS)
