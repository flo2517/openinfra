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
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/dashboard"
	"github.com/openinfra/network/internal/orchestrator"
	"github.com/openinfra/network/internal/providerjoin"
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

	options, err := serverOptions(address)
	if err != nil {
		return err
	}
	server := grpc.NewServer(options...)
	workloadRepository := workloadapi.NewPostgresRepository(pool)
	service := providerjoin.NewService(providerjoin.NewPostgresRepository(pool), providerjoin.NewRedisHeartbeatStore(redisClient), registrar)
	service.SetWorkloadService(workloadapi.NewService(workloadRepository))
	directory := agentmanager.NewDirectory(agentmanager.NewPostgresRegistry(pool), agentmanager.NewRedisLivenessStore(redisClient))
	agentClient, err := agentmanager.NewMTLSClient(os.Getenv("AGENT_CLIENT_TLS_CERT_FILE"), os.Getenv("AGENT_CLIENT_TLS_KEY_FILE"), os.Getenv("AGENT_CLIENT_TLS_CA_FILE"))
	if err != nil {
		return fmt.Errorf("configure Provider Agent client: %w", err)
	}
	worker := orchestrator.NewWorker(workloadRepository, directory, registrar, agentClient)
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
	httpServer := &http.Server{
		Handler:           dashboard.New(pool, redisClient, chainClient).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	serveError := make(chan error, 2)
	go func() {
		slog.Info("Control Plane gRPC listening", "address", address)
		serveError <- server.Serve(listener)
	}()
	go func() {
		slog.Info("Control Plane dashboard listening", "address", httpAddress)
		serveError <- httpServer.Serve(httpListener)
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
		return nil
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve gRPC: %w", err)
	}
}

func safeHTTPListener(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse dashboard address: %w", err)
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && !strings.EqualFold(os.Getenv("OPENINFRA_DEV_DASHBOARD_INSECURE"), "true") {
		return nil, errors.New("dashboard without authentication must bind to loopback; local Compose may explicitly set OPENINFRA_DEV_DASHBOARD_INSECURE=true")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen dashboard on %s: %w", address, err)
	}
	return listener, nil
}

func serverOptions(address string) ([]grpc.ServerOption, error) {
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

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
