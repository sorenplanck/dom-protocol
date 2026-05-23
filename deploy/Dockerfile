# DOM Protocol — multi-stage container build
#
# Stage 1: build release binaries with cargo (uses cached layer for deps).
# Stage 2: minimal runtime image with just the dom-node binary.
#
# Usage:
#   docker build -t dom-node:testnet -f deploy/Dockerfile .
#   docker run -d --name dom-testnet \
#     -p 33370:33370 \
#     -v dom-data:/var/lib/dom-testnet \
#     -e DOM_DATA_DIR=/var/lib/dom-testnet \
#     dom-node:testnet

FROM rust:1.82-slim AS builder

# System deps needed by RandomX, LMDB, and crypto crates.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for better layer caching (deps only rebuild when these change).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Release build of dom-node only — drops fuzz, tests, and dev artifacts.
RUN cargo build --release --bin dom-node

# ---- Runtime stage ----
FROM debian:bookworm-slim

# Runtime deps: just libgcc/libc/libssl that release binary expects.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false -u 10001 dom \
    && mkdir -p /var/lib/dom-testnet /var/lib/dom-mainnet \
    && chown -R dom:dom /var/lib/dom-testnet /var/lib/dom-mainnet

COPY --from=builder /build/target/release/dom-node /usr/local/bin/dom-node

USER dom
WORKDIR /var/lib/dom-testnet

# Default P2P port (testnet). Override with -p for mainnet (33369).
EXPOSE 33370

ENV DOM_DATA_DIR=/var/lib/dom-testnet \
    DOM_P2P_LISTEN_ADDR=0.0.0.0:33370 \
    RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/dom-node"]
