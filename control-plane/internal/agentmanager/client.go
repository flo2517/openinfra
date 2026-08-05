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
	"google.golang.org/grpc/credentials"
)

type Client struct {
	tlsConfig   *tls.Config
	dialTimeout time.Duration
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
