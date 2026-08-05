# Local Blockchain Testnet

This isolated Compose project runs two Aura authorities (Alice and Bob) plus a non-authoring observer. GRANDPA voters finalize blocks over the private Docker network. Only JSON-RPC ports `9954`–`9956` are published, all on loopback; peer-to-peer port `30333` remains internal. These ports avoid the main development stack's `9944` endpoint.

The development keyring and the generated Control Plane bridge sudo account are strictly local fixtures. They provide reproducibility, not production governance. Never expose this network or reuse its keys.

From the repository root:

```bash
deployments/scripts/generate-dev-certs.sh
docker compose -f deployments/local/blockchain-testnet/docker-compose.yml up -d --build --wait
deployments/local/blockchain-testnet/test.sh
docker compose -f deployments/local/blockchain-testnet/docker-compose.yml down
```

Named chain volumes survive `down`. Add `--volumes` only for an explicit destructive reset. The test verifies peer connectivity, finalized block progress, and an identical finalized hash on all three nodes.
