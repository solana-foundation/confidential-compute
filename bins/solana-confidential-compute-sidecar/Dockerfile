# Multi-stage hardened build for Solana Confidential Compute Enclave Sidecar Daemon
# @spec SCC-SIDECAR-006

# ------------------------------------------------------------------------------
# 1. Build Stage
# ------------------------------------------------------------------------------
ARG SOURCE_DATE_EPOCH=0
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS builder

WORKDIR /build

# Immutable Debian repositories fix the complete apt dependency closure, including
# transitive packages. Signatures are still required; only snapshot expiry is ignored.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf '%s\n' \
       'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261001T000000Z bookworm main' \
       'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261001T000000Z bookworm-security main' \
       > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
       pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Use the image's preinstalled compiler, with no rustup download caused by the
# repository's developer components. Fail if the repository pin changes.
ENV RUSTUP_TOOLCHAIN=1.98.1 SOURCE_DATE_EPOCH=0
COPY rust-toolchain.toml ./
RUN test "$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)" = "$RUSTUP_TOOLCHAIN" \
    && rustc --version --verbose && cargo --version

# Copy workspace sources
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY programs ./programs
COPY bins ./bins

# Build optimized release binary
RUN cargo build --locked --release --package solana-confidential-compute-sidecar -j4

# Strip binary to reduce surface and footprint
RUN strip /build/target/release/solana-confidential-compute-sidecar

# ------------------------------------------------------------------------------
# 2. Runtime Stage (Minimal Distroless)
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="solana-confidential-compute-sidecar"
LABEL org.opencontainers.image.description="Solana Confidential Compute Enclave Sidecar Daemon"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy stripped binary from builder
COPY --from=builder /build/target/release/solana-confidential-compute-sidecar /usr/local/bin/solana-confidential-compute-sidecar

# Loopback HTTP API
EXPOSE 8080

# Run as non-root user (distroless default uid 65532)
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/solana-confidential-compute-sidecar"]
CMD ["--bind-addr", "127.0.0.1:8080"]
