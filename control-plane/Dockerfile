# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee AS build

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.41
ENV CGO_ENABLED=0
WORKDIR /src

COPY protocol/generated/go/ protocol/generated/go/
COPY control-plane/go.mod control-plane/go.sum control-plane/
WORKDIR /src/control-plane
RUN go mod download

COPY control-plane/ /src/control-plane/
RUN go build -trimpath -ldflags="-s -w" -o /out/control-plane ./cmd/controlplane
# controlplane-admin ships alongside the server because ADR-016 §4 makes
# `grant-role` the only way a user becomes a dashboard operator, and
# ADR-014/#12 make `create-user`/`issue-key`/`revoke-key` the only way a
# non-wallet user gets a credential at all. Without this binary in the
# image, an operator running the packaged deployment cannot perform any
# of those actions without building from source and reaching the
# database out-of-band -- i.e. the shipped artifact would not support
# its own documented operational procedures.
RUN go build -trimpath -ldflags="-s -w" -o /out/controlplane-admin ./cmd/controlplane-admin
# networkvalidator ships alongside the server so the local dev stack's
# networkvalidator/networkvalidator-2/networkvalidator-3 Compose services
# (deployments/docker-compose.yml) can run it via an entrypoint override
# on this same image, the same pattern controlplane-admin already
# establishes for a second binary from this module -- without a separate
# Dockerfile duplicating this build stage's dependency and Go-module
# setup.
RUN go build -trimpath -ldflags="-s -w" -o /out/networkvalidator ./cmd/networkvalidator
RUN GOBIN=/out go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION}

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/control-plane /usr/local/bin/control-plane
COPY --from=build /out/controlplane-admin /usr/local/bin/controlplane-admin
COPY --from=build /out/networkvalidator /usr/local/bin/networkvalidator
COPY --from=build /out/grpc-health-probe /usr/local/bin/grpc-health-probe
USER nonroot:nonroot
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/control-plane"]
