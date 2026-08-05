package orchestrator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/workloadapi"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

type PersistentStore interface {
	ClaimNext(context.Context, string, time.Duration) (workloadapi.Workload, error)
	BeginScheduling(context.Context, workloadapi.Workload) error
	AssignLease(context.Context, workloadapi.Workload, string, [32]byte) (uint64, error)
	MarkLeased(context.Context, workloadapi.Workload, uint64) error
	RetryLater(context.Context, workloadapi.Workload, string, string, time.Duration) error
	MarkDeploying(context.Context, workloadapi.Workload, uint64) error
	MarkRunning(context.Context, workloadapi.Workload, string) error
	MarkStopped(context.Context, workloadapi.Workload, uint64) error
}
type ProviderDirectory interface {
	ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error)
}
type LeaseRegistrar interface {
	EnsureLeaseActive(context.Context, uint64, [32]byte, [32]byte, uint32) (blockchainbridge.FinalizedLease, error)
	EnsureLeaseCompleted(context.Context, uint64) (blockchainbridge.FinalizedLease, error)
}
type AgentDispatcher interface {
	DeployAndConfirm(context.Context, agentmanager.RegisteredProvider, *agentv1.DeployRequest) (string, error)
	StopAndConfirm(context.Context, agentmanager.RegisteredProvider, string) error
}

// DeploymentReconciler queries authoritative Agent state before replaying a
// deployment whose previous response may have been lost.
type DeploymentReconciler interface {
	GetRunningWorkload(context.Context, agentmanager.RegisteredProvider, string) (bool, error)
}

type Worker struct {
	store               PersistentStore
	directory           ProviderDirectory
	leases              LeaseRegistrar
	dispatcher          AgentDispatcher
	interval, blockTime time.Duration
	workerID            string
	claimDuration       time.Duration
}

func NewWorker(store PersistentStore, directory ProviderDirectory, leases LeaseRegistrar, dispatcher AgentDispatcher) *Worker {
	return &Worker{store: store, directory: directory, leases: leases, dispatcher: dispatcher, interval: time.Second, blockTime: 3 * time.Second, workerID: uuid.NewString(), claimDuration: 2 * time.Minute}
}
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if err := w.processOne(ctx); err != nil && !errors.Is(err, workloadapi.ErrNotFound) && !errors.Is(err, context.Canceled) {
			slog.Error("workload orchestration step failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *Worker) processOne(ctx context.Context) error {
	item, err := w.store.ClaimNext(ctx, w.workerID, w.claimDuration)
	if err != nil {
		return err
	}
	switch item.State {
	case "REQUESTED":
		return w.store.BeginScheduling(ctx, item)
	case "SCHEDULING":
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return w.retry(ctx, item, "INVALID_DEFINITION", err)
		}
		providers, err := w.directory.ListSchedulableProviders(ctx)
		if err != nil {
			return w.retry(ctx, item, "DIRECTORY_UNAVAILABLE", err)
		}
		provider, err := selectProvider(providers, definition.Requirements)
		if err != nil {
			return w.retry(ctx, item, "NO_CAPACITY", err)
		}
		_, err = w.store.AssignLease(ctx, item, provider.ProviderID, canonicalResourceHash(item.Definition, item.Image))
		return err
	case "LEASE_PENDING":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse persisted lease id: %w", err)
		}
		providerKey, err := w.providerKey(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return err
		}
		duration := uint32((time.Duration(definition.DurationSeconds)*time.Second + w.blockTime - 1) / w.blockTime)
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := w.leases.EnsureLeaseActive(leaseCtx, leaseID, providerKey, item.ResourceHash, duration); err != nil {
			return w.retry(ctx, item, "LEASE_NOT_FINALIZED", err)
		}
		return w.store.MarkLeased(ctx, item, leaseID)
	case "LEASED":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return err
		}
		return w.store.MarkDeploying(ctx, item, leaseID)
	case "DEPLOYING":
		provider, err := w.provider(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return err
		}
		// A retry means the preceding Deploy result may have been lost. Query
		// Agent state first; Deploy itself remains idempotent and returns the
		// persisted container id when reconciliation finds an existing workload.
		if reconciler, ok := w.dispatcher.(DeploymentReconciler); ok && item.AttemptCount > 0 {
			statusCtx, statusCancel := context.WithTimeout(ctx, 10*time.Second)
			_, statusErr := reconciler.GetRunningWorkload(statusCtx, provider.RegisteredProvider, item.WorkloadID)
			statusCancel()
			if statusErr != nil {
				return w.retry(ctx, item, "AGENT_STATUS_UNKNOWN", statusErr)
			}
		}
		request := &agentv1.DeployRequest{WorkloadId: item.WorkloadID, LeaseId: item.LeaseID, Image: item.Image, Limits: &agentv1.ResourceLimits{CpuCores: definition.Requirements.Cpu, MemoryMb: definition.Requirements.RamMb}}
		deployCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		containerID, err := w.dispatcher.DeployAndConfirm(deployCtx, provider.RegisteredProvider, request)
		if err != nil {
			return w.retry(ctx, item, "AGENT_DEPLOY_FAILED", err)
		}
		return w.store.MarkRunning(ctx, item, containerID)
	case "STOPPING":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return err
		}
		provider, err := w.provider(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		stopCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := w.dispatcher.StopAndConfirm(stopCtx, provider.RegisteredProvider, item.WorkloadID); err != nil {
			return w.retry(ctx, item, "AGENT_STOP_FAILED", err)
		}
		chainCtx, chainCancel := context.WithTimeout(ctx, 30*time.Second)
		defer chainCancel()
		if _, err := w.leases.EnsureLeaseCompleted(chainCtx, leaseID); err != nil {
			return w.retry(ctx, item, "LEASE_COMPLETION_NOT_FINALIZED", err)
		}
		return w.store.MarkStopped(ctx, item, leaseID)
	default:
		return nil
	}
}
func (w *Worker) retry(ctx context.Context, item workloadapi.Workload, code string, cause error) error {
	if err := w.store.RetryLater(ctx, item, code, cause.Error(), 5*time.Second); err != nil {
		return err
	}
	return cause
}
func (w *Worker) providerKey(ctx context.Context, id string) ([32]byte, error) {
	provider, err := w.provider(ctx, id)
	if err != nil {
		return [32]byte{}, err
	}
	if len(provider.PublicKey) != 32 {
		return [32]byte{}, errors.New("provider public key is invalid")
	}
	var key [32]byte
	copy(key[:], provider.PublicKey)
	return key, nil
}
func (w *Worker) provider(ctx context.Context, id string) (agentmanager.SchedulableProvider, error) {
	providers, err := w.directory.ListSchedulableProviders(ctx)
	if err != nil {
		return agentmanager.SchedulableProvider{}, err
	}
	for _, p := range providers {
		if p.ProviderID == id {
			return p, nil
		}
	}
	return agentmanager.SchedulableProvider{}, errors.New("selected provider is no longer active with a fresh heartbeat")
}
func selectProvider(providers []agentmanager.SchedulableProvider, requirements *sharedv1.ResourceRequirements) (agentmanager.SchedulableProvider, error) {
	if requirements == nil {
		return agentmanager.SchedulableProvider{}, errors.New("requirements missing")
	}
	for _, p := range providers {
		c := p.Capabilities
		if p.AgentEndpoint != "" && c != nil && c.CpuAvailable >= requirements.Cpu && c.RamAvailableMb >= requirements.RamMb && c.StorageAvailableGb >= requirements.StorageGb {
			return p, nil
		}
	}
	return agentmanager.SchedulableProvider{}, errors.New("no active provider has sufficient resources")
}
func decodeDefinition(encoded []byte) (*sharedv1.WorkloadDefinition, error) {
	var definition sharedv1.WorkloadDefinition
	if err := proto.Unmarshal(encoded, &definition); err != nil {
		return nil, err
	}
	return &definition, nil
}
func canonicalResourceHash(definition []byte, image string) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("openinfra-resource-v1\x00"))
	hash.Write(definition)
	hash.Write([]byte{0})
	hash.Write([]byte(image))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
