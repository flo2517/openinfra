// Command controlplane-admin is operator tooling for issue #12: there is
// deliberately no self-service user registration RPC (that would be a much
// larger surface -- verification, abuse prevention -- out of scope for a
// tenancy MVP), so creating a user and issuing their first API key is a
// local/offline operation against the same Postgres the Control Plane uses.
//
// The raw API key is printed exactly once, to stdout, and never persisted
// anywhere (only its SHA-256 hash lives in Postgres) -- copy it immediately;
// there is no way to recover it later, only to revoke it and issue a new one.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "controlplane-admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		return fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	repository := userauth.NewPostgresRepository(pool)

	switch args[0] {
	case "create-user":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin create-user <display-name>")
		}
		return createUser(ctx, repository, args[1])
	case "issue-key":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin issue-key <user-id>")
		}
		return issueKey(ctx, repository, args[1])
	case "revoke-key":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin revoke-key <key-id>")
		}
		if err := repository.RevokeAPIKey(ctx, args[1]); err != nil {
			return fmt.Errorf("revoke key: %w", err)
		}
		fmt.Println("revoked")
		return nil
	default:
		return usageError()
	}
}

func createUser(ctx context.Context, repository *userauth.PostgresRepository, displayName string) error {
	user, err := repository.CreateUser(ctx, displayName)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	fmt.Println("user_id:", user.UserID)
	return issueKey(ctx, repository, user.UserID)
}

func issueKey(ctx context.Context, repository *userauth.PostgresRepository, userID string) error {
	key, err := repository.CreateAPIKey(ctx, userID)
	if err != nil {
		return fmt.Errorf("create API key: %w", err)
	}
	fmt.Println("key_id:", key.KeyID)
	fmt.Println("api_key:", key.Raw, "  (shown once -- store it now; only its hash is kept)")
	return nil
}

func usageError() error {
	return errors.New("usage: controlplane-admin <create-user <display-name> | issue-key <user-id> | revoke-key <key-id>>")
}
