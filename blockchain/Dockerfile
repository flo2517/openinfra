# syntax=docker/dockerfile:1
FROM rust:1.97-bookworm@sha256:705e294093973d7c10e83400393dce7b3611f8e03e55a80af7fff6d02ae1affb AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev llvm-dev cmake pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32v1-none && rustup component add rust-src

WORKDIR /src
COPY . .
RUN --mount=type=cache,id=openinfra-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=openinfra-blockchain-target,target=/src/target \
    cargo build --locked --release -p openinfra-node \
    && cp /src/target/release/openinfra-node /tmp/openinfra-node

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /var/lib/openinfra openinfra
COPY --from=builder /tmp/openinfra-node /usr/local/bin/openinfra-node

USER 10001:10001
EXPOSE 9944 30333
ENTRYPOINT ["/usr/local/bin/openinfra-node"]
