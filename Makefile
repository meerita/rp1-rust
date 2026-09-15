# Human entry point for repository operations.
#
# Each target delegates to the tool that owns the work. Implementation
# does not live in this file.

CARGO ?= cargo
RUNNER_MANIFEST := tools/validation-runner/Cargo.toml
RUNNER := $(CARGO) run --quiet --package validation-runner --

.DEFAULT_GOAL := help
.PHONY: help build smoke test gate gate-resume fuzz bench conformance

# Fail with the install command when a required host tool is absent.
define require_command
@command -v $(1) >/dev/null 2>&1 || { \
	echo "error: $(1) is required and was not found on PATH." >&2; \
	echo "install: $(2)" >&2; \
	exit 1; \
}
endef

# The recorded campaigns run through the repository validation runner.
define require_runner
@test -f $(RUNNER_MANIFEST) || { \
	echo "error: the validation runner is not present at $(RUNNER_MANIFEST)." >&2; \
	echo "recorded validation cannot run without it." >&2; \
	exit 1; \
}
endef

help:
	@echo "RP-1 Rust repository operations."
	@echo
	@echo "  make build         compile the crate"
	@echo "  make smoke         fast local checks, not recorded"
	@echo "  make test          development validation campaign, recorded"
	@echo "  make gate          complete gate campaign, recorded and sealed"
	@echo "  make gate-resume   resume the current gate campaign"
	@echo "  make fuzz          one bounded fuzz segment"
	@echo "  make bench         benchmark campaign"
	@echo "  make conformance   RP-1 conformance campaign"
	@echo
	@echo "Requires the Rust toolchain pinned by rust-toolchain.toml."

build:
	$(call require_command,cargo,https://rustup.rs)
	$(CARGO) build

smoke:
	$(call require_command,cargo,https://rustup.rs)
	$(CARGO) build
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets
	$(CARGO) test

test:
	$(call require_command,cargo,https://rustup.rs)
	$(require_runner)
	$(RUNNER) run --tier dev

gate:
	$(call require_command,cargo,https://rustup.rs)
	$(require_runner)
	$(RUNNER) run --tier gate

gate-resume:
	$(call require_command,cargo,https://rustup.rs)
	$(require_runner)
	$(RUNNER) run --tier gate --resume

fuzz:
	@echo "error: this repository has no fuzz campaign yet." >&2
	@echo "the fuzz targets arrive with the wire codec, which parses" >&2
	@echo "peer-controlled bytes and is the first thing worth fuzzing." >&2
	@exit 1

bench:
	@echo "error: this repository has no benchmark campaign yet." >&2
	@echo "benchmarks arrive with the performance work, once a client" >&2
	@echo "exists to measure." >&2
	@exit 1

conformance:
	@echo "error: this repository has no conformance campaign yet." >&2
	@echo "conformance scenarios arrive with the conformance laboratory," >&2
	@echo "once the client speaks the protocol." >&2
	@exit 1
