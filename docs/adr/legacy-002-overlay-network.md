# ADR 002: WireGuard for Overlay Networking

> Historical proposal. Overlay networking is outside the current MVP and this record is not an accepted stack change.

## Status
Proposed

## Context
Provider nodes are distributed globally across various networks. We need a secure, low-latency way to connect workloads (VMs/Containers) across these nodes as if they were on the same local network.

## Decision
Use **WireGuard** as the primary L3 overlay network protocol.

## Rationale
- **Performance**: Significantly faster than OpenVPN or IPsec due to its implementation in the Linux kernel.
- **Security**: Uses modern cryptography (Curve25519, ChaCha20, Poly1305).
- **Simplicity**: Stateless design reduces overhead and complexity in configuration.
- **Stealth**: Nodes do not respond to unauthorized packets, reducing the attack surface.

## Consequences
- Requires kernel support (standard in modern Linux).
- The Control Plane must manage a distributed key-exchange and endpoint mapping system to update WireGuard peers dynamically.
