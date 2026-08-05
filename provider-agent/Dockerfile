# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.97-bookworm@sha256:705e294093973d7c10e83400393dce7b3611f8e03e55a80af7fff6d02ae1affb AS builder

WORKDIR /src

COPY provider-agent/ ./provider-agent/
COPY protocol/proto/ ./protocol/proto/
WORKDIR /src/provider-agent
RUN cargo build --locked --release --package agent-cli \
    && strip target/release/agent-cli

FROM debian:bookworm-slim@sha256:362e64223cc0da95422b3b13c045186fc0a81250e765d31c025fbddf257f6143

RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /var/lib/openinfra-agent nonroot \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/openinfra-agent

COPY --from=builder /src/provider-agent/target/release/agent-cli /usr/local/bin/openinfra-agent
COPY provider-agent/docker/entrypoint.sh /usr/local/bin/openinfra-agent-entrypoint
COPY provider-agent/docker/healthcheck.sh /usr/local/bin/openinfra-agent-healthcheck

WORKDIR /var/lib/openinfra-agent
USER 65532:65532
EXPOSE 50052
ENTRYPOINT ["/usr/local/bin/openinfra-agent-entrypoint"]
