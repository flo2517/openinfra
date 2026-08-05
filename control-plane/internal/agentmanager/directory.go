package agentmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

const heartbeatKeyPrefix = "openinfra:heartbeat:"

var ErrHeartbeatNotFresh = errors.New("provider heartbeat is not fresh")

type RegisteredProvider struct {
	ProviderID      string
	PublicKey       []byte
	ProtocolVersion string
	AgentVersion    string
	AgentEndpoint   string
}

type ProviderRegistry interface {
	ListActive(context.Context) ([]RegisteredProvider, error)
}

type LivenessStore interface {
	HeartbeatPayload(context.Context, string) ([]byte, error)
}

type Directory struct {
	registry ProviderRegistry
	liveness LivenessStore
}

type SchedulableProvider struct {
	RegisteredProvider
	Capabilities *sharedv1.ResourceCapability
}

func NewDirectory(registry ProviderRegistry, liveness LivenessStore) *Directory {
	return &Directory{registry: registry, liveness: liveness}
}

// ListSchedulable returns only durably registered ACTIVE providers whose
// authenticated Redis heartbeat is still inside its TTL.
func (d *Directory) ListSchedulable(ctx context.Context) ([]*sharedv1.NodeIdentity, error) {
	detailed, err := d.ListSchedulableProviders(ctx)
	if err != nil {
		return nil, err
	}
	available := make([]*sharedv1.NodeIdentity, 0, len(detailed))
	for _, provider := range detailed {
		available = append(available, &sharedv1.NodeIdentity{NodeId: provider.ProviderID, ProtocolVersion: provider.ProtocolVersion, AgentVersion: provider.AgentVersion, Capabilities: provider.Capabilities, Status: sharedv1.NodeStatus_NODE_STATUS_ACTIVE})
	}
	return available, nil
}

func (d *Directory) ListSchedulableProviders(ctx context.Context) ([]SchedulableProvider, error) {
	providers, err := d.registry.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list registered providers: %w", err)
	}
	available := make([]SchedulableProvider, 0, len(providers))
	for _, provider := range providers {
		payloadBytes, err := d.liveness.HeartbeatPayload(ctx, provider.ProviderID)
		if errors.Is(err, ErrHeartbeatNotFresh) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read heartbeat for %s: %w", provider.ProviderID, err)
		}
		var payload controlplanev1.HeartbeatSigningPayload
		if err := proto.Unmarshal(payloadBytes, &payload); err != nil {
			return nil, fmt.Errorf("decode heartbeat for %s: %w", provider.ProviderID, err)
		}
		if payload.ProviderId != provider.ProviderID || payload.Capabilities == nil {
			return nil, fmt.Errorf("heartbeat identity mismatch for %s", provider.ProviderID)
		}
		available = append(available, SchedulableProvider{RegisteredProvider: provider, Capabilities: payload.Capabilities})
	}
	return available, nil
}

type PostgresRegistry struct{ pool *pgxpool.Pool }

func NewPostgresRegistry(pool *pgxpool.Pool) *PostgresRegistry { return &PostgresRegistry{pool: pool} }

func (r *PostgresRegistry) ListActive(ctx context.Context) ([]RegisteredProvider, error) {
	rows, err := r.pool.Query(ctx, `SELECT provider_id, public_key, protocol_version, agent_version, COALESCE(agent_endpoint, '') FROM providers WHERE status = $1 ORDER BY provider_id`, int16(sharedv1.NodeStatus_NODE_STATUS_ACTIVE))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var providers []RegisteredProvider
	for rows.Next() {
		var provider RegisteredProvider
		if err := rows.Scan(&provider.ProviderID, &provider.PublicKey, &provider.ProtocolVersion, &provider.AgentVersion, &provider.AgentEndpoint); err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

type RedisLivenessStore struct{ client redis.UniversalClient }

func NewRedisLivenessStore(client redis.UniversalClient) *RedisLivenessStore {
	return &RedisLivenessStore{client: client}
}

func (s *RedisLivenessStore) HeartbeatPayload(ctx context.Context, providerID string) ([]byte, error) {
	payload, err := s.client.HGet(ctx, heartbeatKeyPrefix+providerID, "payload").Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrHeartbeatNotFresh
	}
	return payload, err
}
