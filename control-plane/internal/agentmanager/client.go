package agentmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Client struct {
	tlsConfig   *tls.Config
	dialTimeout time.Duration
}

// GetRunningWorkload reconciles an ambiguous Deploy result against the
// authoritative Agent before the idempotent Deploy request is replayed.
func (c *Client) GetRunningWorkload(ctx context.Context, provider RegisteredProvider, workloadID string) (bool, error) {
	connection, client, err := c.ConnectVerified(ctx, provider)
	if err != nil {
		return false, err
	}
	defer connection.Close()
	statusCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetWorkloadStatus(statusCtx, &agentv1.GetWorkloadStatusRequest{WorkloadId: workloadID})
	if status.Code(err) == codes.NotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reconcile workload status: %w", err)
	}
	switch response.State {
	case agentv1.GetWorkloadStatusResponse_STATE_RUNNING:
		return true, nil
	case agentv1.GetWorkloadStatusResponse_STATE_CREATED,
		agentv1.GetWorkloadStatusResponse_STATE_PENDING,
		agentv1.GetWorkloadStatusResponse_STATE_DEPLOYING:
		return false, nil
	default:
		return false, fmt.Errorf("Agent workload cannot be reconciled from state %s", response.State.String())
	}
}

func NewMTLSClient(certFile, keyFile, caFile string) (*Client, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load Agent client identity: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Agent CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("Agent CA contains no certificate")
	}
	return &Client{tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool}, dialTimeout: 5 * time.Second}, nil
}

func (c *Client) ConnectVerified(ctx context.Context, provider RegisteredProvider) (*grpc.ClientConn, agentv1.ProviderAgentServiceClient, error) {
	endpoint, err := url.Parse(provider.AgentEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return nil, nil, errors.New("provider has no valid HTTPS Agent endpoint")
	}
	configuration := c.tlsConfig.Clone()
	configuration.ServerName = endpoint.Hostname()
	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()
	connection, err := grpc.DialContext(dialCtx, endpoint.Host, grpc.WithTransportCredentials(credentials.NewTLS(configuration)), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("connect provider Agent: %w", err)
	}
	client := agentv1.NewProviderAgentServiceClient(connection)
	verifyCtx, verifyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer verifyCancel()
	info, err := client.GetAgentInfo(verifyCtx, &agentv1.GetAgentInfoRequest{})
	if err != nil {
		connection.Close()
		return nil, nil, fmt.Errorf("verify provider Agent identity: %w", err)
	}
	publicKey, err := hex.DecodeString(info.PublicKey)
	if err != nil || len(publicKey) != 32 {
		connection.Close()
		return nil, nil, errors.New("provider Agent returned an invalid public key")
	}
	digest := sha256.Sum256(publicKey)
	if info.NodeId != provider.ProviderID || hex.EncodeToString(digest[:]) != provider.ProviderID || !bytes.Equal(publicKey, provider.PublicKey) {
		connection.Close()
		return nil, nil, errors.New("provider Agent identity does not match authoritative registration")
	}
	return connection, client, nil
}

func (c *Client) DeployAndConfirm(ctx context.Context, provider RegisteredProvider, request *agentv1.DeployRequest) (string, error) {
	connection, client, err := c.ConnectVerified(ctx, provider)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deployCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	response, err := client.Deploy(deployCtx, request)
	cancel()
	if err != nil {
		return "", fmt.Errorf("deploy workload on Agent: %w", err)
	}
	if !response.Success {
		return "", fmt.Errorf("Agent rejected deployment: %s", response.Error)
	}
	if response.ContainerId == "" {
		return "", errors.New("Agent reported deployment success without container id")
	}
	statusCtx, statusCancel := context.WithTimeout(ctx, 10*time.Second)
	defer statusCancel()
	workloadStatus, err := client.GetWorkloadStatus(statusCtx, &agentv1.GetWorkloadStatusRequest{WorkloadId: request.WorkloadId})
	if err != nil {
		return "", fmt.Errorf("confirm workload status: %w", err)
	}
	if workloadStatus.State != agentv1.GetWorkloadStatusResponse_STATE_RUNNING {
		return "", fmt.Errorf("Agent workload state is %s, not RUNNING", workloadStatus.State.String())
	}
	return response.ContainerId, nil
}

// DeleteVolume asks provider's Agent to securely delete the Docker named
// volume backing a Cinder block volume (ADR-034 §6, issue #171).
// Idempotent at the Agent boundary, the same way StopAndConfirm already
// is (agent-executor's DeleteVolume handler treats "no such volume" as
// success -- see agent.proto's DeleteVolumeRequest doc comment): a retry
// after a lost response, or a delete of a volume this Agent never
// actually created (e.g. it was bound but never mounted), both succeed.
func (c *Client) DeleteVolume(ctx context.Context, provider RegisteredProvider, volumeID string) error {
	connection, client, err := c.ConnectVerified(ctx, provider)
	if err != nil {
		return err
	}
	defer connection.Close()
	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := client.DeleteVolume(deleteCtx, &agentv1.DeleteVolumeRequest{VolumeId: volumeID})
	if err != nil {
		return fmt.Errorf("delete volume on Agent: %w", err)
	}
	if !response.Success {
		return fmt.Errorf("Agent rejected volume deletion: %s", response.Error)
	}
	return nil
}

// VolumeDeleteDispatcher adapts a Client + ProviderLookup into the
// (providerID, volumeID string) error shape
// internal/openstackapi/cinder.VolumeDispatcher expects -- constructed
// here rather than in the cinder package, since agentmanager already
// owns both halves (the mTLS client, the provider directory) and cinder
// must not import agentmanager's concrete types to stay a pure
// translation layer over interfaces it declares itself (the same
// narrow-interface-at-the-call-site discipline
// internal/openstackapi/nova.WorkloadStore/ProviderDirectory already
// establish).
type VolumeDeleteDispatcher struct {
	client *Client
	lookup ProviderLookup
}

func NewVolumeDeleteDispatcher(client *Client, lookup ProviderLookup) *VolumeDeleteDispatcher {
	return &VolumeDeleteDispatcher{client: client, lookup: lookup}
}

func (d *VolumeDeleteDispatcher) DeleteVolume(ctx context.Context, providerID, volumeID string) error {
	provider, err := d.lookup.GetProvider(ctx, providerID)
	if err != nil {
		return fmt.Errorf("resolve provider %s for volume deletion: %w", providerID, err)
	}
	return d.client.DeleteVolume(ctx, provider, volumeID)
}

// FetchUsageSummary pulls one bounded, signed MeteringSummary from the
// Agent's GetUsageSummary RPC (ADR-029 §6 / issue #20) -- the
// least-invasive fit on ProviderAgentService (agent.proto's own doc
// comment), a pull matching GetWorkloadStatus's existing shape rather
// than ReportHeartbeat's push shape on ControlPlaneService. The caller
// (internal/metering's Service.RecordUsage) still independently
// verifies the response's signature against the provider's registered
// key before accepting anything; this method only transports it.
//
// Deliberately not wired to any automatic polling loop in this PR --
// see the implementing PR's description for why a periodic collection
// scheduler (calling this for every active workload on a cadence) is
// scoped out as its own follow-up issue rather than bundled here.
func (c *Client) FetchUsageSummary(ctx context.Context, provider RegisteredProvider, workloadID string) (*agentv1.GetUsageSummaryResponse, error) {
	connection, client, err := c.ConnectVerified(ctx, provider)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	usageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetUsageSummary(usageCtx, &agentv1.GetUsageSummaryRequest{WorkloadId: workloadID})
	if err != nil {
		return nil, fmt.Errorf("fetch usage summary from Agent: %w", err)
	}
	if response.Summary == nil {
		return nil, errors.New("Agent returned a usage summary response with no summary")
	}
	return response, nil
}

// StopAndConfirm is idempotent at the Agent boundary and returns only after
// inspection reports the exact persisted workload container as completed.
func (c *Client) StopAndConfirm(ctx context.Context, provider RegisteredProvider, workloadID string) error {
	connection, client, err := c.ConnectVerified(ctx, provider)
	if err != nil {
		return err
	}
	defer connection.Close()
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	response, err := client.Stop(stopCtx, &agentv1.StopRequest{WorkloadId: workloadID})
	cancel()
	if err != nil {
		return fmt.Errorf("stop workload on Agent: %w", err)
	}
	if !response.Success {
		return fmt.Errorf("Agent rejected stop: %s", response.Error)
	}
	statusCtx, statusCancel := context.WithTimeout(ctx, 10*time.Second)
	defer statusCancel()
	workloadStatus, err := client.GetWorkloadStatus(statusCtx, &agentv1.GetWorkloadStatusRequest{WorkloadId: workloadID})
	if err != nil {
		return fmt.Errorf("confirm stopped workload status: %w", err)
	}
	if workloadStatus.State != agentv1.GetWorkloadStatusResponse_STATE_COMPLETED {
		return fmt.Errorf("Agent workload state is %s, not COMPLETED", workloadStatus.State.String())
	}
	return nil
}
