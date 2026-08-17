# KrnlSentry build driver.
#
# The build has two stages, and the first one is the unusual part:
#
#   1. `make generate` runs bpf2go, which invokes clang to compile
#      bpf/krnlsentry.bpf.c into a BPF ELF object, then writes a Go source file
#      that embeds that object as a byte slice plus typed accessors for every
#      map and program in it. The Go type for `struct event` is derived from the
#      BTF in the object, so kernel and userspace views of the wire format
#      cannot drift.
#
#   2. `make build` is then an ordinary `go build` — the BPF object rides along
#      inside the binary. The result is a single static file with no runtime
#      dependency on clang, libbpf, or kernel headers. That is the entire
#      argument for libbpf+CO-RE over BCC.
#
# Generated files are not committed (see .gitignore): they contain a compiled
# ELF, so a stale one would be invisible in review and would silently ship
# yesterday's kernel code.

SHELL := /bin/bash

BINARY      := krnlsentry
MODULE      := github.com/praneeth132006/KrnlSentry
CMD_PKG     := ./cmd/krnlsentry
BIN_DIR     := bin
BPF_SRC     := bpf/krnlsentry.bpf.c
BPF_HDRS    := bpf/event.h bpf/vmlinux_min.h
GEN_DIR     := ebpfloader
GEN_STAMP   := $(GEN_DIR)/krnlsentry_arm64_bpfel.go

# Version metadata, stamped into the binary via -ldflags. Falls back gracefully
# outside a git checkout (e.g. a source tarball) so the build never breaks.
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
               -X main.version=$(VERSION) \
               -X main.commit=$(COMMIT) \
               -X main.date=$(DATE)

# clang flags for the BPF target.
#   -O2      is mandatory, not an optimisation choice: the verifier rejects the
#            unoptimised output clang produces at -O0.
#   -g       emits BTF, without which there is no CO-RE and no bpf2go types.
#   -Ibpf    lets the .bpf.c find event.h and vmlinux_min.h.
#   -Werror  because a warning in a verifier-bound program is usually a real bug.
BPF_CFLAGS  := -O2 -g -Wall -Werror -Ibpf

BPF2GO      := go run github.com/cilium/ebpf/cmd/bpf2go
# -target amd64,arm64: emits one Go file per architecture, build-tagged, so the
# same repo produces correct __TARGET_ARCH_* defines on an M-series Mac and on
# an x86_64 server.
BPF2GO_ARGS := -go-package ebpfloader \
               -output-dir $(GEN_DIR) \
               -target amd64,arm64 \
               -type event \
               -cc clang \
               -cflags "$(BPF_CFLAGS)"

DOCKER_IMAGE := krnlsentry-dev

.DEFAULT_GOAL := build

## ── Primary targets ─────────────────────────────────────────────────────────

.PHONY: all
all: generate build test ## Generate, build and test

.PHONY: generate
generate: $(GEN_STAMP) ## Compile the eBPF C and generate Go bindings

$(GEN_STAMP): $(BPF_SRC) $(BPF_HDRS)
	@command -v clang >/dev/null 2>&1 || { \
		echo "error: clang not found. eBPF cannot be compiled without it."; \
		echo "       On macOS/Windows use the Linux dev container: make docker-shell"; \
		exit 1; }
	$(BPF2GO) $(BPF2GO_ARGS) KrnlSentry $(BPF_SRC)

.PHONY: build
build: generate ## Build the krnlsentry binary into ./bin
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION))"

.PHONY: test
test: generate ## Run unit tests
	go test -race -count=1 ./...

.PHONY: cover
cover: generate ## Run tests and write a coverage profile
	go test -covermode=atomic -coverprofile=coverage.txt ./...
	go tool cover -func=coverage.txt | tail -n 1

.PHONY: vet
vet: generate ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format Go sources
	go fmt ./...

.PHONY: lint
lint: generate ## Run golangci-lint if available
	@command -v golangci-lint >/dev/null 2>&1 \
		&& golangci-lint run ./... \
		|| echo "golangci-lint not installed; skipping (see CONTRIBUTING.md)"

.PHONY: run
run: build ## Build and run system-wide (needs root or CAP_BPF+CAP_PERFMON)
	sudo $(BIN_DIR)/$(BINARY)

.PHONY: clean
clean: ## Remove build artefacts and generated bindings
	rm -rf $(BIN_DIR) dist coverage.txt
	rm -f $(GEN_DIR)/krnlsentry_*.go $(GEN_DIR)/krnlsentry_*.o

## ── Docker dev environment ──────────────────────────────────────────────────

.PHONY: docker-build
docker-build: ## Build the Linux dev image
	docker build -t $(DOCKER_IMAGE) .

.PHONY: docker-shell
docker-shell: docker-build ## Interactive shell in the dev container
	docker run --rm -it \
		-v "$(CURDIR)":/src \
		-v krnlsentry-gomod:/root/go/pkg/mod \
		$(DOCKER_IMAGE) /bin/bash

# Compile and test inside the container without an interactive shell. This is
# the target to use on macOS: it is how you verify a change actually builds.
.PHONY: docker-make
docker-make: docker-build ## Run a make target inside the container: make docker-make TARGET=test
	docker run --rm \
		-v "$(CURDIR)":/src \
		-v krnlsentry-gomod:/root/go/pkg/mod \
		$(DOCKER_IMAGE) make $(or $(TARGET),all)

# Live tracing needs far more privilege than building does, and needs to see the
# host's PID namespace to be able to resolve and stat the processes it reports.
# --privileged is a blunt instrument; the README documents the narrower
# --cap-add CAP_BPF --cap-add CAP_PERFMON form for kernels that support it.
.PHONY: docker-run
docker-run: docker-build ## Run the agent inside the container (privileged)
	docker run --rm -it \
		--privileged \
		--pid=host \
		-v "$(CURDIR)":/src \
		-v krnlsentry-gomod:/root/go/pkg/mod \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		$(DOCKER_IMAGE) /bin/bash -c "make build && ./bin/$(BINARY)"

## ── Optional tooling ────────────────────────────────────────────────────────

# Generate a full vmlinux.h from the *running* kernel's BTF. Not needed for a
# normal build — bpf/vmlinux_min.h covers what we use, precisely so that the
# build does not depend on the build host having BTF. Provided for contributors
# who need to reach a kernel struct the minimal header does not declare.
.PHONY: vmlinux
vmlinux: ## Regenerate a full bpf/vmlinux.h from the running kernel's BTF
	@test -r /sys/kernel/btf/vmlinux || { \
		echo "error: /sys/kernel/btf/vmlinux not readable."; \
		echo "       This kernel lacks CONFIG_DEBUG_INFO_BTF=y."; \
		exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "wrote bpf/vmlinux.h ($$(wc -c < bpf/vmlinux.h) bytes)"

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
