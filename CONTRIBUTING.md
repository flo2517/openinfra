# Contributing

## Workflow

Create a short-lived branch from the integration branch, keep commits focused, and open a pull request early for interface or architecture work. Use names such as `feat/provider-join`, `fix/lease-overflow`, or `docs/adr-mtls`.

Write imperative commit subjects, optionally using Conventional Commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `build:`, or `chore:`. Do not mix structural moves with unrelated behavior changes.

## Required Checks

Run the relevant component commands from `make help`, including formatting, linting, unit tests, and integration tests affected by the change. Report exact commands and failures in the pull request; never claim an unexecuted check passed.

Pull requests must describe motivation, behavior, affected components, rollback considerations, linked issues/ADRs, and contract or storage migrations. Require review from each affected component owner. Security-sensitive changes need explicit security review.

## Protocol and Architecture

Before changing Protobuf, identify all consumers, preserve field compatibility, run lint/breaking checks, regenerate Go and Rust, and update contract tests. Never edit generated files manually.

Architecture, stack, database, trust-boundary, or component-responsibility changes require a proposed ADR and explicit acceptance before implementation. Preserve superseded ADRs as historical records.
