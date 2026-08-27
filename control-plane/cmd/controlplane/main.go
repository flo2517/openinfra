package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/dashboard"
	"github.com/openinfra/network/internal/openstackapi"
	"github.com/openinfra/network/internal/orchestrator"
	"github.com/openinfra/network/internal/pki"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/providerjoin"
	"github.com/openinfra/network/internal/ratelimit"
	"github.com/openinfra/network/internal/resourcemarket"
	"github.com/openinfra/network/internal/scheduler"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
	"github.com/openinfra/network/internal/wireguard"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	if err := run(); err != nil {
		slog.Error("control plane stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("connect PostgreSQL: %w", err)
	}
	if err := migrations.Apply(pingCtx, pool); err != nil {
		return fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return errors.New("REDIS_URL is required")
	}
	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("parse Redis URL: %w", err)
	}
	redisClient := redis.NewClient(redisOptions)
	defer redisClient.Close()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("connect Redis: %w", err)
	}

	substrateRPCURL := os.Getenv("SUBSTRATE_RPC_URL")
	if substrateRPCURL == "" {
		return errors.New("SUBSTRATE_RPC_URL is required")
	}
	chainClient, err := blockchainbridge.NewRPCClient(substrateRPCURL, &http.Client{})
	if err != nil {
		return err
	}
	chainCtx, chainCancel := context.WithTimeout(ctx, 5*time.Second)
	defer chainCancel()
	chainHealth, err := chainClient.Health(chainCtx)
	if err != nil {
		return fmt.Errorf("connect Substrate: %w", err)
	}
	header, err := chainClient.LatestHeader(chainCtx)
	if err != nil {
		return fmt.Errorf("read Substrate head: %w", err)
	}
	blockNumber, err := header.BlockNumber()
	if err != nil {
		return err
	}
	slog.Info("Substrate RPC connected", "block_number", blockNumber, "peers", chainHealth.Peers, "syncing", chainHealth.IsSyncing)
	signerKeyFile := os.Getenv("SUBSTRATE_SIGNER_KEY_FILE")
	if signerKeyFile == "" {
		return errors.New("SUBSTRATE_SIGNER_KEY_FILE is required")
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(chainClient, signerKeyFile)
	if err != nil {
		return fmt.Errorf("configure Substrate registrar: %w", err)
	}

	address := envOrDefault("CONTROL_PLANE_GRPC_ADDR", "127.0.0.1:50051")
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	defer listener.Close()

	// ADR-027: the Control Plane operates a single CA (§1). CA_KEY_FILE is
	// deliberately never set for provider-agent in deployments/docker-
	// compose.yml -- only control-plane mounts the same ./local/certs
	// volume ca.key already lives in, unread until now. Unset (or
	// OPENINFRA_DEV_INSECURE) keeps the pre-ADR-027 static-cert path
	// working, per the ADR §6 migration sequencing note: this is the
	// "keep it behind a flag" flag, satisfied by CA_KEY_FILE's presence
	// rather than a separate boolean, since the two are equivalent in
	// practice -- there is no meaningful "CA loaded but issuance
	// disabled" state worth a second knob.
	ca, revocationChecker, err := loadPKI(redisClient)
	if err != nil {
		return err
	}
	options, err := serverOptions(address, ca, revocationChecker)
	if err != nil {
		return err
	}
	if ca != nil {
		reconciler := pki.NewReconciler(providerjoin.NewPostgresRepository(pool), pki.NewRedisRevocationStore(redisClient), pki.DefaultReconcileInterval)
		go reconciler.Run(ctx)
		slog.Info("mTLS PKI enrollment/renewal/revocation enabled (ADR-027)")
	} else {
		slog.Warn("CA_KEY_FILE not set; falling back to the pre-ADR-027 static development mTLS certificates -- see deployments/scripts/generate-dev-certs.sh")
	}
	// issue #12: authenticate SubmitWorkload/GetWorkload/StopWorkload with
	// a bearer API key and enforce a per-tenant rate limit, layered on top
	// of the mTLS transport above (BeginJoin/CompleteJoin/ReportHeartbeat
	// keep their own Ed25519 challenge auth and are untouched by this).
	userRepository := userauth.NewPostgresRepository(pool)
	rateLimit := envIntOrDefault("USER_API_RATE_LIMIT_PER_MINUTE", 120)
	limiter := ratelimit.NewRedisLimiter(redisClient, rateLimit, 60)
	interceptors := []grpc.UnaryServerInterceptor{userauth.NewUnaryInterceptor(userRepository, limiter)}
	if ca != nil {
		// ADR-027 §4: every RPC, not only the ones the TLS handshake
		// already gated -- an already-open connection's very next call
		// after revocation must be rejected too.
		interceptors = append([]grpc.UnaryServerInterceptor{pki.UnaryServerInterceptor(ca, revocationChecker)}, interceptors...)
	}
	options = append(options,
		grpc.MaxRecvMsgSize(1<<20), // 1 MiB: bounds a WorkloadDefinition/image payload far above any legitimate size
		grpc.ChainUnaryInterceptor(interceptors...),
	)
	server := grpc.NewServer(options...)
	workloadRepository := workloadapi.NewPostgresRepository(pool)
	// Constructed once and shared: the gRPC ControlPlaneService server
	// (via providerjoin.Service.SetWorkloadService below) and the
	// dashboard's tenant-tier submitMyWorkload (internal/dashboard/
	// tenantviews.go) both call into this exact instance, so a
	// dashboard-submitted workload runs through the identical
	// validation/hashing/persistence path a `workloadctl submit` gRPC
	// call would.
	workloadService := workloadapi.NewService(workloadRepository)
	// ADR-033 §7: the operator-configured, narrow guest-image allowlist a
	// VM workload's image URL must match -- comma-separated host/path
	// prefixes (e.g. "https://cloud-images.ubuntu.com/,https://cloud.debian.org/images/cloud/"),
	// matching this file's existing envOrDefault convention for
	// operator tunables. Deliberately defaults to empty, not a built-in
	// guess at "known-good" URLs this repository cannot actually vet on
	// an operator's behalf -- an empty/unset allowlist means every VM
	// workload submission is rejected (see Service.vmImageAllowlist's own
	// doc comment), the same fail-closed default agent-core's
	// `max_vm_workloads`/`vm_enabled` already use on the Agent side of
	// this same ADR.
	workloadService.SetVMImageAllowlist(splitNonEmpty(envOrDefault("VM_IMAGE_ALLOWLIST", "")))
	providerRepository := providerjoin.NewPostgresRepository(pool)
	service := providerjoin.NewService(providerRepository, providerjoin.NewRedisHeartbeatStore(redisClient), registrar)
	service.SetWorkloadService(workloadService)
	// ADR-013 §3: push the current active-validator allowlist to Agents on
	// every heartbeat. chainClient already implements ValidatorSource via
	// RPCClient.LatestActiveNetworkValidators; a read failure degrades to
	// an empty list inside Service, it never fails ReportHeartbeat itself.
	service.SetValidatorSource(chainClient)
	// ADR-025 §2: persist each heartbeat's signed WorkloadBandwidthUsage
	// entries once the heartbeat signature itself has verified. A store
	// failure degrades to a warning log inside Service (see
	// SetBandwidthUsageStore's doc comment), the same fail-open posture
	// SetValidatorSource above already uses -- this is telemetry, not a
	// liveness-critical path.
	service.SetBandwidthUsageStore(providerjoin.NewPostgresBandwidthUsageStore(pool))
	// ADR-028 §4: status-first reconciliation on every heartbeat, against
	// the exact same workloadService instance SetWorkloadService above
	// already shares with the dashboard's tenant-tier submitMyWorkload --
	// one Repository, one source of truth for the workloads table. A
	// reconciliation failure degrades to a warning log inside Service
	// (see SetWorkloadReconciler's doc comment), never fails the
	// heartbeat itself.
	service.SetWorkloadReconciler(workloadService)
	if ca != nil {
		// ADR-027 §2/§3: CompleteJoin issues an enrollment certificate when
		// asked (tls_public_key set), and RenewCertificate becomes callable.
		service.SetCertificateAuthority(ca)
		service.SetRenewalNonceStore(providerjoin.NewRedisRenewalNonceStore(redisClient))
	}
	// Independently drives provider_chain_registrations rows left in
	// READY/RETRY (e.g. after a Control Plane or chain restart) to
	// FINALIZED, without depending on the Agent retrying CompleteJoin.
	reconciler := providerjoin.NewReconciler(providerRepository, providerRepository, registrar, providerjoin.DefaultReconcilerConfig())
	go reconciler.Run(ctx)
	directory := agentmanager.NewDirectory(agentmanager.NewPostgresRegistry(pool), agentmanager.NewRedisLivenessStore(redisClient))
	agentClient, err := agentmanager.NewMTLSClient(os.Getenv("AGENT_CLIENT_TLS_CERT_FILE"), os.Getenv("AGENT_CLIENT_TLS_KEY_FILE"), os.Getenv("AGENT_CLIENT_TLS_CA_FILE"))
	if err != nil {
		return fmt.Errorf("configure Provider Agent client: %w", err)
	}
	// Keeps pallet-resource-market's on-chain Offers in sync with each
	// schedulable provider's declared total capacity (issue #15).
	marketReconciler := resourcemarket.NewReconciler(directory, marketBridge{registrar: registrar, chain: chainClient}, resourcemarket.DefaultReconcilerConfig())
	go marketReconciler.Run(ctx)
	ranker := scheduler.NewRanker(scheduler.DefaultMaxReputationScore, scheduler.DefaultDefaultReputationScore)
	worker := orchestrator.NewWorker(workloadRepository, directory, registrar, agentClient, ranker)
	worker.SetReputationSource(chainClient)
	if interfaceName := os.Getenv("WIREGUARD_INTERFACE"); interfaceName != "" {
		firstPort := envIntOrDefault("WIREGUARD_FIRST_PORT", 51820)
		lastPort := envIntOrDefault("WIREGUARD_LAST_PORT", 51999)
		overlay, overlayErr := wireguard.NewManager(wireguard.NewCommandBackend(interfaceName), firstPort, lastPort)
		if overlayErr != nil {
			return fmt.Errorf("configure WireGuard overlay: %w", overlayErr)
		}
		// Every DEPLOYING workload gets an overlay peer attached once this is
		// set (see Worker.SetOverlay), so the ranker's bandwidth fit-scoring
		// and the capacity ledger both need to account for the same overhead
		// every one of those workloads will actually pay -- otherwise a
		// candidate ranked (or admitted) as "fits" at scheduling time can
		// under-deliver once its traffic is encapsulated. SetOverlay flips
		// both itself; there is no separate ranker call to make here.
		worker.SetOverlay(overlay)
		slog.Info("WireGuard workload overlay enabled", "interface", interfaceName, "first_port", firstPort, "last_port", lastPort)
	}
	go worker.Run(ctx)
	controlplanev1.RegisterControlPlaneServiceServer(server, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("openinfra.controlplane.v1.ControlPlaneService", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	httpAddress := envOrDefault("CONTROL_PLANE_HTTP_ADDR", "127.0.0.1:8080")
	httpListener, err := safeHTTPListener(httpAddress)
	if err != nil {
		return err
	}
	defer httpListener.Close()
	// ADR-014: wallet-based dashboard login. authLimiter is deliberately
	// tighter and separate from the gRPC user API's limiter above -- these
	// endpoints are unauthenticated by definition and each does real work
	// (a Postgres write, or a signature verification) per request.
	walletService := walletlogin.NewService(walletlogin.NewPostgresRepository(pool), userRepository)
	authRateLimit := envIntOrDefault("DASHBOARD_AUTH_RATE_LIMIT_PER_MINUTE", 10)
	authLimiter := ratelimit.NewRedisLimiter(redisClient, authRateLimit, 60)
	httpServer := &http.Server{
		Handler:           dashboard.New(pool, redisClient, chainClient, walletService, userRepository, authLimiter, workloadService).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// ADR-031 §2: a third HTTP surface, OpenStack-shaped REST/JSON, on
	// its own listener -- issue #23's Keystone token bridge today,
	// #24/#25/#26's Nova/Neutron/Glance/Cinder route groups extending the
	// same internal/openstackapi.Server.Handler() in their own PRs.
	// A separate listener (not merged into httpServer above), because
	// the ADR is explicit this is its own wire surface and a JSON-only
	// API has no business sharing internal/dashboard's HTML-serving
	// CSP/asset routes.
	openstackAPIAddress := envOrDefault("OPENSTACK_API_HTTP_ADDR", "127.0.0.1:8087")
	openstackAPIListener, err := loopbackHTTPListener(openstackAPIAddress, "OPENINFRA_DEV_OPENSTACK_API_INSECURE",
		"OpenStack API surface must bind to loopback; local Compose may explicitly set OPENINFRA_DEV_OPENSTACK_API_INSECURE=true")
	if err != nil {
		return err
	}
	defer openstackAPIListener.Close()
	openstackAPIBaseURL := envOrDefault("OPENSTACK_API_BASE_URL", "http://"+openstackAPIAddress)
	openstackTokenRateLimit := envIntOrDefault("OPENSTACK_TOKEN_RATE_LIMIT_PER_MINUTE", 30)
	openstackTokenLimiter := ratelimit.NewRedisLimiter(redisClient, openstackTokenRateLimit, 60)
	openstackAPIServer := &http.Server{
		Handler:           openstackapi.New(pool, userRepository, projects.NewPostgresRepository(pool), workloadService, workloadRepository, directory, openstackAPIBaseURL, openstackTokenLimiter).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	serveError := make(chan error, 3)
	go func() {
		slog.Info("Control Plane gRPC listening", "address", address)
		serveError <- server.Serve(listener)
	}()
	go func() {
		slog.Info("Control Plane dashboard listening", "address", httpAddress)
		serveError <- httpServer.Serve(httpListener)
	}()
	go func() {
		slog.Info("Control Plane OpenStack API listening", "address", openstackAPIAddress)
		serveError <- openstackAPIServer.Serve(openstackAPIListener)
	}()

	select {
	case <-ctx.Done():
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus("openinfra.controlplane.v1.ControlPlaneService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		server.GracefulStop()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown dashboard: %w", err)
		}
		if err := openstackAPIServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown OpenStack API: %w", err)
		}
		return nil
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve gRPC: %w", err)
	}
}

func safeHTTPListener(address string) (net.Listener, error) {
	return loopbackHTTPListener(address, "OPENINFRA_DEV_DASHBOARD_INSECURE",
		"dashboard without authentication must bind to loopback; local Compose may explicitly set OPENINFRA_DEV_DASHBOARD_INSECURE=true")
}

// loopbackHTTPListener is safeHTTPListener's general form, reused by
// internal/openstackapi's listener (below) so a second unauthenticated-
// by-default HTTP surface gets the exact same loopback-by-default
// posture with its own dedicated escape-hatch env var, rather than
// silently reusing the dashboard's flag (which would let one insecure
// flag quietly widen two different surfaces at once) or duplicating this
// function's logic a second time.
func loopbackHTTPListener(address, insecureEnvVar, insecureMessage string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && !strings.EqualFold(os.Getenv(insecureEnvVar), "true") {
		return nil, errors.New(insecureMessage)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}
	return listener, nil
}

// loadPKI reads ADR-027's Control-Plane-operated CA (see the run() call
// site's doc comment on why CA_KEY_FILE's presence is the flag) and
// builds the Redis-backed revocation checker it needs. Returns (nil, nil,
// nil) -- not an error -- when CA_KEY_FILE is unset, so run() falls back
// to the pre-ADR-027 static-cert path unaffected.
func loadPKI(redisClient *redis.Client) (*pki.CA, *pki.RedisRevocationStore, error) {
	if strings.EqualFold(os.Getenv("OPENINFRA_DEV_INSECURE"), "true") {
		return nil, nil, nil
	}
	caKeyFile := os.Getenv("CA_KEY_FILE")
	if caKeyFile == "" {
		return nil, nil, nil
	}
	caCertPEM, err := os.ReadFile(os.Getenv("TLS_CLIENT_CA_FILE"))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA private key: %w", err)
	}
	ca, err := pki.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA: %w", err)
	}
	return ca, pki.NewRedisRevocationStore(redisClient), nil
}

func serverOptions(address string, ca *pki.CA, revocation pki.RevocationChecker) ([]grpc.ServerOption, error) {
	if strings.EqualFold(os.Getenv("OPENINFRA_DEV_INSECURE"), "true") {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse listen address: %w", err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("insecure development mode requires a loopback address")
		}
		return nil, nil
	}

	certificate, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("load server TLS identity: %w", err)
	}

	if ca != nil {
		// ADR-027 §2: the dual trust basis (CA chain, or a bootstrap
		// self-signed certificate scoped to BeginJoin/CompleteJoin by
		// pki.UnaryServerInterceptor, wired in by run()) replaces the
		// single fixed CA-chain-or-reject check below.
		return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(pki.ServerTLSConfig(certificate, ca, revocation)))}, nil
	}

	clientCA, err := os.ReadFile(os.Getenv("TLS_CLIENT_CA_FILE"))
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("client CA contains no certificate")
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(configuration))}, nil
}

// marketBridge combines *blockchainbridge.Registrar's write methods with
// *blockchainbridge.RPCClient's read methods into the single
// resourcemarket.Market surface -- they are genuinely two different
// receiver types in blockchainbridge (signing/submitting vs. querying
// storage), not an arbitrary split introduced here.
type marketBridge struct {
	registrar *blockchainbridge.Registrar
	chain     *blockchainbridge.RPCClient
}

func (b marketBridge) AnnounceOfferFor(ctx context.Context, provider [32]byte, offer blockchainbridge.ResourceOffer) error {
	return b.registrar.AnnounceOfferFor(ctx, provider, offer)
}
func (b marketBridge) RemoveOfferFor(ctx context.Context, provider [32]byte) error {
	return b.registrar.RemoveOfferFor(ctx, provider)
}
func (b marketBridge) FinalizedOffer(ctx context.Context, provider [32]byte, blockHash string) (blockchainbridge.ResourceOffer, bool, error) {
	return b.chain.FinalizedOffer(ctx, provider, blockHash)
}
func (b marketBridge) FinalizedHead(ctx context.Context) (string, error) {
	return b.chain.FinalizedHead(ctx)
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// splitNonEmpty splits a comma-separated operator-supplied list (e.g.
// VM_IMAGE_ALLOWLIST), trims whitespace around each entry, and drops empty
// entries (a leading/trailing/doubled comma must not silently become an
// empty-string allowlist entry that then matches nothing forever, nor -- if
// a caller ever treated empty specially -- something unintended). An empty
// or unset input yields an empty (fail-closed) slice, not a slice
// containing one empty string.
func splitNonEmpty(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func envIntOrDefault(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		slog.Warn("invalid integer environment value; using default", "name", name, "error", err)
		return fallback
	}
	return parsed
}
