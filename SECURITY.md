# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability. Report it privately to the repository maintainers through the hosting platform's private security advisory channel. Include affected revisions, impact, reproduction steps, and any suggested mitigation. Maintainers should acknowledge receipt before discussing disclosure timing.

## Scope

Security-sensitive areas include Provider identity and keys, mTLS, gRPC authorization, Docker isolation, workload input, PostgreSQL/Redis access, Substrate origins and arithmetic, proof validation, dependency supply chain, and logs/telemetry.

## Repository Rules

Never commit private keys, certificates, tokens, passwords, populated `.env` files, or production data. Use `.env.example` for names and safe defaults only. Generated keys must use owner-only permissions and must not be logged. Rotate any credential that enters Git history; deletion from the latest tree is insufficient.

Use established cryptographic libraries and protocols. Do not design custom cryptography or weaken verification for tests. Pin production images and lock dependencies when buildable; review security advisories and generated lockfile changes. Apply least privilege to containers, databases, CI, and blockchain origins.

This prototype has not undergone an external security audit and must not be treated as production-ready.
