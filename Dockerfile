# syntax=docker/dockerfile:1
#
# KrnlSentry development environment.
#
# eBPF is a Linux kernel technology, so none of this project can be compiled or
# run on macOS or Windows. This image is the portable Linux toolchain: clang for
# the BPF target, libbpf headers, bpftool, and Go.
#
# It is deliberately a *dev* image, not a minimal runtime image. The point is to
# give a contributor on any host a shell where `make` works.
#
#   Build:  make docker-build
#   Shell:  make docker-shell
#
# RUNNING (as opposed to building) additionally needs a kernel with BTF and the
# CAP_BPF/CAP_PERFMON capabilities. See README "Running under Docker" for the
# caveats — notably that Docker Desktop's LinuxKit VM on macOS often lacks
# /sys/kernel/btf/vmlinux, which is fine for building but prevents live tracing.

FROM ubuntu:24.04

# Non-interactive apt, and keep the layer cache useful by pinning nothing we
# do not have to.
ENV DEBIAN_FRONTEND=noninteractive

# Toolchain rationale, package by package:
#   clang / llvm      — the only compilers with a BPF backend. GCC's bpf target
#                       does not support CO-RE relocations.
#   libbpf-dev        — bpf_helpers.h / bpf_core_read.h, included by our .bpf.c.
#   libelf-dev, zlib  — libbpf's own link dependencies, needed when cilium/ebpf
#                       builds anything native and by bpftool.
#   linux-tools-*     — provides bpftool, used for `make vmlinux` (optional) and
#                       for inspecting loaded programs while debugging.
#   make, git, ca-certs, curl — build driver and Go module fetching.
#   iproute2, netcat, socat, strace, gdb, sudo, python3 — not build deps: these
#                       are what the scripts in test/ need to safely trigger
#                       each detection inside the container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        gcc \
        libc6-dev \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        linux-tools-common \
        linux-tools-generic \
        pkg-config \
        make \
        git \
        curl \
        ca-certificates \
        iproute2 \
        netcat-openbsd \
        socat \
        strace \
        gdb \
        sudo \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Go from upstream rather than apt: Ubuntu's golang package lags, and a
# pinned version makes CI and local builds agree. TARGETARCH is supplied
# automatically by BuildKit, so this image builds natively on both an Apple
# Silicon Mac (arm64) and an x86_64 CI runner.
ARG GO_VERSION=1.25.13
ARG TARGETARCH
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" \
        -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}" \
    GOPATH="/root/go" \
    CGO_ENABLED=0

# bpftool ships under a versioned path in linux-tools-generic and is not on
# PATH by default. Symlink whichever one landed so `bpftool` just works.
RUN set -eux; \
    bt="$(find /usr/lib/linux-tools* -name bpftool -type f 2>/dev/null | head -n1)"; \
    if [ -n "$bt" ]; then ln -sf "$bt" /usr/local/bin/bpftool; fi

WORKDIR /src

# Warm the module cache as its own layer so that editing source does not force
# a re-download on every rebuild. Tolerates absent go.sum on a first build.
COPY go.mod go.su[m] ./
RUN go mod download || true

CMD ["/bin/bash"]
