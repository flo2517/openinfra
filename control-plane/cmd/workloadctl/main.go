// Command workloadctl is minimal, scriptable tooling for
// ControlPlaneService's user-facing workload RPCs (issue #116): submit,
// get, and stop a workload over the same mTLS transport the Control
// Plane already requires, given an image pinned by digest and a few
// resource numbers.
//
// It exists because nothing previously let a developer or a test script
// (tests/e2e/run.sh, issue #117) drive SubmitWorkload/GetWorkload/
// StopWorkload without hand-rolling an mTLS gRPC call: the server does
// not register reflection (cmd/controlplane/main.go), so a generic tool
// like grpcurl cannot discover the schema without also shipping a
// descriptor set, and this repo's convention (see cmd/controlplane-admin,
// cmd/networkvalidator) is a small purpose-built Go binary against the
// already-generated protocol/generated/go types instead.
//
// Since these three RPCs went through ADR-016's authenticated slice 1
// (issue #92, superseding issue #12's "not yet authenticated" note),
// every call here also requires OPENINFRA_API_KEY -- a bearer key minted
// by `controlplane-admin create-user`/`issue-key`. TLS_CERT_FILE/
// TLS_KEY_FILE/TLS_CA_FILE/TLS_SERVER_NAME are the same mTLS client
// identity env vars tests/e2e/run.sh already exports for agent-cli; the
// Control Plane's mTLS transport auth does not distinguish callers by
// identity beyond the shared CA, so that identity is reused as-is.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "workloadctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	// Validated before connect() dials anything: a typo'd subcommand or a
	// wrong arg count is a usage mistake, not a connectivity problem, and
	// should be reported as one even when TLS_CERT_FILE/TLS_KEY_FILE/
	// TLS_CA_FILE/TLS_SERVER_NAME aren't set -- an anticipated case for
	// ad-hoc interactive use (see this file's header comment), where an
	// unrelated TLS/dial error would otherwise mask the actual mistake.
	switch args[0] {
	case "submit":
		if len(args) != 6 {
			return errors.New("usage: workloadctl submit <image@sha256:digest> <cpu-cores> <ram-mb> <storage-gb> <duration-seconds>")
		}
	case "get":
		if len(args) != 2 {
			return errors.New("usage: workloadctl get <workload-id>")
		}
	case "stop":
		if len(args) != 2 {
			return errors.New("usage: workloadctl stop <workload-id>")
		}
	default:
		return usageError()
	}

	apiKey := os.Getenv("OPENINFRA_API_KEY")
	if apiKey == "" {
		return errors.New("OPENINFRA_API_KEY is required (mint one with `controlplane-admin create-user`)")
	}

	ctx := context.Background()
	client, closeConnection, err := connect(ctx)
	if err != nil {
		return err
	}
	defer closeConnection()

	switch args[0] {
	case "submit":
		return submit(ctx, client, apiKey, args[1], args[2], args[3], args[4], args[5])
	case "get":
		return get(ctx, client, apiKey, args[1])
	case "stop":
		return stop(ctx, client, apiKey, args[1])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: workloadctl {submit <image@sha256:digest> <cpu-cores> <ram-mb> <storage-gb> <duration-seconds> | get <workload-id> | stop <workload-id>}")
}

// connect dials the Control Plane over mTLS using the same
// TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE/TLS_SERVER_NAME env vars
// tests/e2e/run.sh already exports for agent-cli's Provider Agent side.
func connect(ctx context.Context) (controlplanev1.ControlPlaneServiceClient, func() error, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")
	serverName := os.Getenv("TLS_SERVER_NAME")
	if certFile == "" || keyFile == "" || caFile == "" || serverName == "" {
		return nil, nil, errors.New("TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE, and TLS_SERVER_NAME are required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load client identity: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("CA file contains no certificate")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool, ServerName: serverName}

	address := os.Getenv("CONTROL_PLANE_GRPC_ADDR")
	if address == "" {
		address = "127.0.0.1:50051"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(dialCtx, address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("connect Control Plane: %w", err)
	}
	return controlplanev1.NewControlPlaneServiceClient(connection), connection.Close, nil
}

func withAuth(ctx context.Context, apiKey string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+apiKey)
}

func submit(ctx context.Context, client controlplanev1.ControlPlaneServiceClient, apiKey, image, cpuArg, ramArg, storageArg, durationArg string) error {
	cpu, err := parseFloat32(cpuArg, "cpu-cores")
	if err != nil {
		return err
	}
	ramMB, err := parseInt64(ramArg, "ram-mb")
	if err != nil {
		return err
	}
	storageGB, err := parseInt64(storageArg, "storage-gb")
	if err != nil {
		return err
	}
	duration, err := parseInt32(durationArg, "duration-seconds")
	if err != nil {
		return err
	}

	workloadID := uuid.NewString()
	requestID := uuid.NewString()
	request := &controlplanev1.SubmitWorkloadRequest{
		RequestId: requestID,
		Image:     image,
		Definition: &sharedv1.WorkloadDefinition{
			WorkloadId: workloadID,
			// COMPUTE_INTENSIVE is an arbitrary but valid choice --
			// this tool doesn't yet need to distinguish profiles; a
			// profile of UNSPECIFIED is rejected by validateSubmission.
			Profile: sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE,
			Requirements: &sharedv1.ResourceRequirements{
				Cpu:       cpu,
				RamMb:     ramMB,
				StorageGb: storageGB,
			},
			DurationSeconds: duration,
		},
	}

	callCtx, cancel := context.WithTimeout(withAuth(ctx, apiKey), 15*time.Second)
	defer cancel()
	response, err := client.SubmitWorkload(callCtx, request)
	if err != nil {
		return fmt.Errorf("SubmitWorkload: %w", err)
	}
	fmt.Println("workload_id:", response.WorkloadId)
	fmt.Println("request_id:", requestID)
	fmt.Println("state:", response.State.String())
	return nil
}

func get(ctx context.Context, client controlplanev1.ControlPlaneServiceClient, apiKey, workloadID string) error {
	callCtx, cancel := context.WithTimeout(withAuth(ctx, apiKey), 15*time.Second)
	defer cancel()
	response, err := client.GetWorkload(callCtx, &controlplanev1.GetWorkloadRequest{WorkloadId: workloadID})
	if err != nil {
		return fmt.Errorf("GetWorkload: %w", err)
	}
	fmt.Println("workload_id:", response.WorkloadId)
	fmt.Println("state:", response.State.String())
	fmt.Println("provider_id:", response.ProviderId)
	fmt.Println("lease_id:", response.LeaseId)
	fmt.Println("container_id:", response.ContainerId)
	fmt.Println("error_code:", response.ErrorCode)
	return nil
}

func stop(ctx context.Context, client controlplanev1.ControlPlaneServiceClient, apiKey, workloadID string) error {
	requestID := uuid.NewString()
	callCtx, cancel := context.WithTimeout(withAuth(ctx, apiKey), 15*time.Second)
	defer cancel()
	response, err := client.StopWorkload(callCtx, &controlplanev1.StopWorkloadRequest{RequestId: requestID, WorkloadId: workloadID})
	if err != nil {
		return fmt.Errorf("StopWorkload: %w", err)
	}
	fmt.Println("workload_id:", response.WorkloadId)
	fmt.Println("state:", response.State.String())
	return nil
}

func parseFloat32(value, name string) (float32, error) {
	parsed, err := strconv.ParseFloat(value, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return float32(parsed), nil
}

func parseInt64(value, name string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return parsed, nil
}

func parseInt32(value, name string) (int32, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return int32(parsed), nil
}
