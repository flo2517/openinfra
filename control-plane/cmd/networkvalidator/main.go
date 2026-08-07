// Command networkvalidator is a Network Validator's full local process
// (ADR-013, docs/adr/013-network-validator-daemon.md): identity and
// lifecycle (register/status/request-exit/withdraw, slice 1), the
// continuous challenge loop (run, slice 4 / issue #78) that discovers
// assigned providers, calls their Agent's SolveChallenge over mTLS,
// scores the response, and submits evidence/closes rounds on
// pallet-network-validator, and disputing a closed round (dispute, slice
// 5) as a deliberate, attributable human action -- never automated by the
// challenge loop itself. Every extrinsic here is signed directly by this
// binary's own operator-supplied key -- never sudo-wrapped, never routed
// through the Control Plane -- the exact trust boundary ADR-011
// introduced.
//
// resolve_dispute (also slice 5) is deliberately not in this binary: the
// pallet gates it to SuspensionOrigin (EnsureRoot in this runtime), so
// only the Control Plane's own bridge/sudo account can call it -- see
// cmd/controlplane-admin's resolve-dispute instead.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/networkvalidator"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "networkvalidator:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	rpcURL := os.Getenv("SUBSTRATE_RPC_URL")
	if rpcURL == "" {
		return errors.New("SUBSTRATE_RPC_URL is required")
	}
	keyFile := os.Getenv("VALIDATOR_SIGNER_KEY_FILE")
	if keyFile == "" {
		return errors.New("VALIDATOR_SIGNER_KEY_FILE is required (a PKCS#8 PEM Ed25519 key, distinct from any Control Plane bridge or provider key)")
	}
	chain, err := blockchainbridge.NewRPCClient(rpcURL, &http.Client{})
	if err != nil {
		return fmt.Errorf("configure Substrate RPC client: %w", err)
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(chain, keyFile)
	if err != nil {
		return fmt.Errorf("configure validator signer: %w", err)
	}
	ctx := context.Background()

	switch args[0] {
	case "register":
		if len(args) != 2 {
			return errors.New("usage: networkvalidator register <stake>")
		}
		stake, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("parse stake: %w", err)
		}
		if err := registrar.RegisterValidator(ctx, stake); err != nil {
			return fmt.Errorf("register_validator: %w", err)
		}
		fmt.Println("register_validator submitted; run `status` once it finalizes")
		return nil
	case "request-exit":
		if len(args) != 1 {
			return errors.New("usage: networkvalidator request-exit")
		}
		if err := registrar.RequestExit(ctx); err != nil {
			return fmt.Errorf("request_exit: %w", err)
		}
		fmt.Println("request_exit submitted; stake unlocks after the unbonding period")
		return nil
	case "withdraw":
		if len(args) != 1 {
			return errors.New("usage: networkvalidator withdraw")
		}
		if err := registrar.WithdrawUnbonded(ctx); err != nil {
			return fmt.Errorf("withdraw_unbonded: %w", err)
		}
		fmt.Println("withdraw_unbonded submitted")
		return nil
	case "status":
		if len(args) != 1 {
			return errors.New("usage: networkvalidator status")
		}
		return printStatus(ctx, chain, registrar)
	case "run":
		if len(args) != 1 {
			return errors.New("usage: networkvalidator run")
		}
		return runLoop(chain, registrar)
	case "dispute":
		if len(args) != 4 {
			return errors.New("usage: networkvalidator dispute <provider-hex> <round> <dimension>")
		}
		return dispute(ctx, registrar, args[1], args[2], args[3])
	default:
		return usageError()
	}
}

// dispute is ADR-013 slice 5's manual, explicit CLI action (deliberately
// not something the challenge loop triggers automatically -- see
// Registrar.DisputeRound's doc comment). Only the validator side of
// dispute_round's authorization is reachable from this binary: a
// provider has no independent chain-signing path in this MVP.
func dispute(ctx context.Context, registrar *blockchainbridge.Registrar, providerHex, roundArg, dimensionArg string) error {
	provider, err := parseAccountHex(providerHex)
	if err != nil {
		return fmt.Errorf("parse provider: %w", err)
	}
	round, err := strconv.ParseUint(roundArg, 10, 64)
	if err != nil {
		return fmt.Errorf("parse round: %w", err)
	}
	dimension, err := blockchainbridge.ParseScoreDimension(dimensionArg)
	if err != nil {
		return err
	}
	if err := registrar.DisputeRound(ctx, provider, round, dimension); err != nil {
		return fmt.Errorf("dispute_round: %w", err)
	}
	fmt.Printf("dispute_round submitted for provider=%s round=%d dimension=%s; the score rolled back to its pre-round value pending resolve_dispute\n", providerHex, round, dimension)
	return nil
}

func parseAccountHex(value string) ([32]byte, error) {
	var account [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return account, fmt.Errorf("%q is not valid hex: %w", value, err)
	}
	if len(decoded) != 32 {
		return account, fmt.Errorf("%q decodes to %d bytes, want 32", value, len(decoded))
	}
	copy(account[:], decoded)
	return account, nil
}

func printStatus(ctx context.Context, chain *blockchainbridge.RPCClient, registrar *blockchainbridge.Registrar) error {
	account := registrar.Account()
	record, found, err := chain.FinalizedValidatorRecord(ctx, account)
	if err != nil {
		return fmt.Errorf("read validator record: %w", err)
	}
	if !found {
		fmt.Println("not registered -- run `register <stake>`")
		return nil
	}
	fmt.Printf("status: %s\n", record.Status)
	fmt.Printf("stake: %d\n", record.Stake)
	fmt.Printf("registered_at: block %d\n", record.RegisteredAt)
	if record.Status == blockchainbridge.ValidatorExiting {
		fmt.Printf("withdrawable_at: block %d\n", record.AvailableAt)
	}
	if record.Status == blockchainbridge.ValidatorActive {
		fmt.Println("note: run `networkvalidator run` to start challenging assigned providers and submitting evidence")
	}
	return nil
}

// runLoop wires up and starts networkvalidator.Run: everything the
// challenge loop needs beyond the chain client and Registrar already
// constructed by run() above. Configured entirely through environment
// variables, matching this binary's existing SUBSTRATE_RPC_URL/
// VALIDATOR_SIGNER_KEY_FILE convention rather than introducing a flag
// parser for a single new subcommand.
func runLoop(chain *blockchainbridge.RPCClient, registrar *blockchainbridge.Registrar) error {
	dashboardBaseURL := os.Getenv("DASHBOARD_BASE_URL")
	if dashboardBaseURL == "" {
		return errors.New("DASHBOARD_BASE_URL is required for `run` (the Control Plane dashboard's base URL, e.g. http://127.0.0.1:8080 -- serves ADR-013 §2's GET /api/v1/agent-endpoint/{provider_id})")
	}
	resolver, err := networkvalidator.NewEndpointResolver(dashboardBaseURL)
	if err != nil {
		return fmt.Errorf("configure agent-endpoint resolver: %w", err)
	}

	clientCert, err := registrar.ClientIdentity()
	if err != nil {
		return fmt.Errorf("build mTLS client identity: %w", err)
	}

	var agentCAPool *x509.CertPool
	if caFile := os.Getenv("AGENT_SERVER_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read AGENT_SERVER_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("AGENT_SERVER_CA_FILE contains no usable certificate")
		}
		agentCAPool = pool
	} else {
		// See challenge.go's callSolveChallenge doc comment for the full
		// discussion: without a CA to verify an Agent's server
		// certificate against, this validator cannot authenticate which
		// server it is really talking to. This is loud on purpose.
		fmt.Fprintln(os.Stderr, "networkvalidator: WARNING -- AGENT_SERVER_CA_FILE is not set; Agent TLS server certificates will NOT be verified (InsecureSkipVerify). This validator's mTLS client identity is still fully verified by the Agent; what is weakened is only this validator's assurance that it is really talking to the Agent it intends to challenge. Set AGENT_SERVER_CA_FILE to the Control Plane's public CA certificate to close this gap.")
	}

	roundLength := networkvalidator.RoundLength(networkvalidator.DefaultRoundLengthBlocks)
	if raw := os.Getenv("ROUND_LENGTH_BLOCKS"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("parse ROUND_LENGTH_BLOCKS: %w", err)
		}
		roundLength = networkvalidator.RoundLength(parsed)
	}

	pollInterval := networkvalidator.DefaultPollInterval
	if raw := os.Getenv("POLL_INTERVAL_SECONDS"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return fmt.Errorf("parse POLL_INTERVAL_SECONDS: %w", err)
		}
		pollInterval = time.Duration(parsed) * time.Second
	}

	challenger := networkvalidator.NewChallengeClient(networkvalidator.ChallengeClientConfig{
		Resolver:          resolver,
		ClientCertificate: clientCert,
		AgentServerCAPool: agentCAPool,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("networkvalidator: starting challenge loop (account=%x, round_length=%d blocks, poll_interval=%s)\n", registrar.Account(), roundLength, pollInterval)
	fmt.Println("networkvalidator: round derivation (round = finalized_block_number / round_length_blocks) is an off-chain convention this implementation chooses, not enforced by pallet-network-validator -- see internal/networkvalidator/round.go")

	err = networkvalidator.Run(ctx, networkvalidator.LoopConfig{
		Chain:        chain,
		Registrar:    registrar,
		Challenger:   challenger,
		RoundLength:  roundLength,
		PollInterval: pollInterval,
	})
	if errors.Is(err, context.Canceled) {
		fmt.Println("networkvalidator: shutting down")
		return nil
	}
	return err
}

func usageError() error {
	return errors.New("usage: networkvalidator <register <stake> | status | request-exit | withdraw | run | dispute <provider-hex> <round> <dimension>>")
}
