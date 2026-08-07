// Command networkvalidator is the first implementation slice of ADR-013
// (docs/adr/013-network-validator-daemon.md): a Network Validator's
// identity and lifecycle, independently operable and never sharing a key
// with the Control Plane's own bridge account. It registers, checks
// status, and exits/withdraws stake by submitting pallet-network-validator
// extrinsics directly signed by the operator's own key -- never
// sudo-wrapped, never routed through the Control Plane -- the exact trust
// boundary ADR-011 introduced.
//
// This binary does not yet challenge providers or submit evidence: that
// requires agent endpoint discovery, the validator-allowlist push to
// Agents, and the challenge loop itself, tracked as issue #78 (ADR-013
// slices 2-5). `status` says so explicitly rather than implying readiness.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/openinfra/network/internal/blockchainbridge"
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
	default:
		return usageError()
	}
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
	// Honest, not aspirational: this binary cannot yet do the thing a
	// Network Validator ultimately exists for. See the package doc
	// comment and issue #78.
	fmt.Println("note: this binary does not yet challenge providers or submit evidence (see issue #78)")
	return nil
}

func usageError() error {
	return errors.New("usage: networkvalidator <register <stake> | status | request-exit | withdraw>")
}
