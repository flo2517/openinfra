# Deployment Guidelines

This directory owns the reproducible local environment for PostgreSQL, Redis, the Substrate node, Control Plane, and Provider Agent.

- Use pinned images, named volumes, explicit healthchecks, least privilege, and documented startup dependencies.
- Never commit passwords, private keys, certificates, tokens, or populated data volumes. Reference `.env` values and maintain safe examples at the root.
- Scripts must be non-interactive where practical, fail fast, and produce repeatable results.
- `make dev-up` must wait on dependency health rather than timing alone. `make dev-down` must document whether named data survives; destructive cleanup requires a separate explicit command.
- Avoid privileged containers and broad host mounts. Document every exposed port and Docker-socket access.

Current local commands: `make dev-up` generates development-only mTLS certificates and waits for PostgreSQL, Redis, Control Plane, and the manual-seal Substrate node; `make dev-down` preserves named volumes; `make dev-clean` removes them explicitly. All published ports bind to `127.0.0.1`. Manual seal is local-development consensus only.
