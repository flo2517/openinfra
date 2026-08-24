GO ?= /usr/local/go/bin/go
GOFMT ?= /usr/local/go/bin/gofmt
BUF_VERSION ?= v1.72.0
PROTO_TOOL_BIN := $(CURDIR)/protocol/.tools/bin

.PHONY: help fmt lint test test-agent test-control-plane test-blockchain proto proto-tools dev-up dev-down dev-clean e2e e2e-happy-path e2e-multi-provider e2e-chaos e2e-migrations

help:
	@echo "fmt lint test test-agent test-control-plane test-blockchain proto dev-up dev-down dev-clean e2e e2e-happy-path e2e-multi-provider e2e-chaos e2e-migrations"

fmt:
	cd provider-agent && cargo fmt --all -- --check
	cd control-plane && test -f go.mod && test -z "$$($(GOFMT) -l .)"
	cd blockchain && test -f Cargo.toml && cargo fmt --all -- --check

lint:
	cd provider-agent && cargo clippy --workspace --all-targets -- -D warnings
	cd control-plane && $(GO) vet ./...
	cd blockchain && cargo clippy --workspace --all-targets -- -D warnings
	cd protocol && .tools/bin/buf lint

test: test-agent test-control-plane test-blockchain

test-agent:
	cd provider-agent && cargo test --workspace

test-control-plane:
	# -count=1 disables the test result cache for this package tree: at
	# least one test here (blockchainbridge's spec_version drift check)
	# reads a file outside the Go module (blockchain/runtime/src/lib.rs)
	# that go test's cache has no visibility into, so a stale PASS can be
	# replayed after that file changes with no Go source touched at all --
	# defeating exactly the drift detector it was written to be. The whole
	# suite runs in a couple of seconds, so disabling caching here has no
	# meaningful cost.
	cd control-plane && $(GO) test -count=1 ./...

test-blockchain:
	cd blockchain && cargo test --workspace

proto-tools:
	mkdir -p $(PROTO_TOOL_BIN)
	GOBIN=$(PROTO_TOOL_BIN) $(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

proto: proto-tools
	cd protocol && .tools/bin/buf lint && .tools/bin/buf generate
	cd protocol/generated/go && $(GOFMT) -w . && $(GO) vet ./... && $(GO) test ./...

dev-up:
	test -f .env
	test -x deployments/scripts/generate-dev-certs.sh
	deployments/scripts/generate-dev-certs.sh
	docker compose --env-file .env -f deployments/docker-compose.yml config --quiet
	docker compose --env-file .env -f deployments/docker-compose.yml up -d --build --wait
	test -x deployments/scripts/bootstrap-network-validators.sh
	# Runs after `up --wait` has already succeeded, so a failure here is
	# not "nothing came up" -- postgres/redis/blockchain-node/
	# control-plane/every provider-agent are already healthy and usable.
	# It means a Network Validator didn't finish registering in time,
	# which only matters for round-closing/quorum, not for the rest of
	# the stack. Said explicitly on failure (found in review: a bare
	# `make: *** Error 1` here reads as total failure, prompting an
	# unnecessary `make dev-clean`) -- bootstrap-network-validators.sh is
	# itself idempotent (is_registered short-circuits already-registered
	# validators), so `make dev-up` again retries only what's left.
	GO=$(GO) deployments/scripts/bootstrap-network-validators.sh || { \
		echo "dev-up: the core stack is up and healthy -- this failure is only in Network Validator bootstrap (see the errors above)." >&2; \
		echo "dev-up: rerun \`make dev-up\` to retry just the unregistered validator(s); no need to \`make dev-clean\` first." >&2; \
		exit 1; \
	}

dev-down:
	docker compose --env-file .env -f deployments/docker-compose.yml down

dev-clean:
	docker compose --env-file .env -f deployments/docker-compose.yml down --volumes --remove-orphans

e2e:
	test -x tests/e2e/run.sh
	tests/e2e/run.sh

# Individual suites (tests/e2e/AGENTS.md documents each), for faster local
# iteration than the full `e2e` matrix.
e2e-happy-path:
	tests/e2e/run.sh 00-happy-path

e2e-multi-provider:
	tests/e2e/run.sh 10-multi-provider-concurrency

e2e-chaos:
	tests/e2e/run.sh 20-chaos-injection

e2e-migrations:
	tests/e2e/run.sh 30-migrations-rollback
