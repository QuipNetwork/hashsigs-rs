# -*- Makefile -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Proof check, known-answer tests, and audit gate for the SHRINCS EasyCrypt
# development. The generator runs on the host with cargo. The proof targets
# run in the pinned toolchain image through the docker-* targets.

DOCKER       ?= docker
DOCKER_IMAGE ?= hashsigs-easycrypt:r2026.02
EASYCRYPT    ?= easycrypt
CARGO        ?= cargo
EC_JOBS      ?= 4

KAT_OUT := build/kat
REPORTS := reports
GEN     := $(CARGO) run --quiet --release --manifest-path kat/Cargo.toml -- \
           --golden ../../tests/test_vectors/shrincs_sphincs_256s_keccak.json.gz

.DEFAULT_GOAL := help

help:
	@echo "Host:      kat-gen kat-verify kat-update docker-check docker-audit docker-mutants docker-kat-GROUP"
	@echo "Toolchain: check check-spec compile-kat-GROUP mutants audit"

# ---- On the host -----------------------------------------------------------

kat-gen:
	$(GEN) --out $(KAT_OUT)

kat-gen-%:
	$(GEN) --out $(KAT_OUT) --only $*

# The committed vectors must be the ones that the generator writes.
kat-verify: kat-gen
	diff -r $(KAT_OUT)/vectors kat/vectors

kat-update: kat-gen
	mkdir -p kat/vectors
	rm -f kat/vectors/*.json
	cp $(KAT_OUT)/vectors/*.json kat/vectors/

docker-build:
	$(DOCKER) build --quiet --tag $(DOCKER_IMAGE) . >/dev/null

# Generate and replay one group, for example `make docker-kat-helpers`.
docker-kat-%: kat-gen-%
	$(MAKE) docker-build
	$(DOCKER) run --rm $(DOCKER_IMAGE) make compile-kat-$*

docker-check docker-mutants docker-audit: kat-gen
	$(MAKE) docker-build
	$(DOCKER) run --rm $(DOCKER_IMAGE) make $(@:docker-%=%) EC_JOBS=$(EC_JOBS)

docker-check-spec:
	$(MAKE) docker-build
	$(DOCKER) run --rm $(DOCKER_IMAGE) make check-spec EC_JOBS=$(EC_JOBS)

# ---- In the toolchain ------------------------------------------------------

check:
	mkdir -p $(REPORTS)
	$(EASYCRYPT) runtest -jobs $(EC_JOBS) -report $(REPORTS)/all.log config/tests.config all

check-spec:
	mkdir -p $(REPORTS)
	$(EASYCRYPT) runtest -jobs $(EC_JOBS) -report $(REPORTS)/spec.log config/tests.config spec

# EasyCrypt draws a progress meter with carriage returns. Keep only the
# messages, and keep the exit status of EasyCrypt.
compile-kat-%:
	@out=$$($(EASYCRYPT) compile -no-eco $(KAT_OUT)/ec/Kat_$*.ec 2>&1); rc=$$?; \
	printf '%s\n' "$$out" | tr '\r' '\n' | grep -E 'critical|error|warning' || true; \
	echo "Kat_$*.ec: exit $$rc"; exit $$rc

mutants:
	kat/mutation_check.sh $(EC_JOBS)

audit:
	audit/test_audit.sh
	audit/audit.sh

clean:
	find . -name '*.eco' -delete
	rm -rf -- $(KAT_OUT) $(REPORTS)

.PHONY: help kat-gen kat-verify kat-update docker-build docker-check docker-mutants \
	docker-audit docker-check-spec check check-spec mutants audit clean
