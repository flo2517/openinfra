# Deployment Guidelines

This directory owns the reproducible local environment for PostgreSQL, Redis, the Substrate node, Control Plane, Provider Agent, and Network Validator.

- Use pinned images, named volumes, explicit healthchecks, least privilege, and documented startup dependencies.
- Never commit passwords, private keys, certificates, tokens, or populated data volumes. Reference `.env` values and maintain safe examples at the root.
- Scripts must be non-interactive where practical, fail fast, and produce repeatable results.
- `make dev-up` must wait on dependency health rather than timing alone. `make dev-down` must document whether named data survives; destructive cleanup requires a separate explicit command.
- Avoid privileged containers and broad host mounts. Document every exposed port and Docker-socket access.

Current local commands: `make dev-up` generates development-only mTLS certificates and Network Validator signing keys, waits for PostgreSQL, Redis, Control Plane, and the Substrate node, then funds and registers whichever Network Validator instances are running; `make dev-down` preserves named volumes; `make dev-clean` removes them explicitly. All published ports bind to `127.0.0.1`. By default the stack runs one Provider Agent and one Network Validator; `COMPOSE_PROFILES=multi-node make dev-up` adds two more of each (`deployments/provider-agent.md`, `deployments/network-validator.md`).
