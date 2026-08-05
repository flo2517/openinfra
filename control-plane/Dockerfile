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
RUN GOBIN=/out go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION}

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/control-plane /usr/local/bin/control-plane
COPY --from=build /out/grpc-health-probe /usr/local/bin/grpc-health-probe
USER nonroot:nonroot
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/control-plane"]
