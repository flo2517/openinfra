//go:build e2e

// Package dashboard's end-to-end RBAC test (ADR-016 slice 6, issue #76).
//
// Build-tagged `e2e` so it never runs under a plain `go test ./...`:
// unlike every other test in this package, it does not create its own
// schema or fixtures -- it drives a *running* stack (`make dev-up`)
// through the same two surfaces a real client uses, the mTLS gRPC API
// and the dashboard's HTTP API, and asserts the tenant boundary holds
// across both. Invoked by tests/e2e/run.sh.
//
// Why this exists on top of the package's unit tests: those exercise
// handlers against a bare pgxpool, so they cannot catch a boundary that
// is only wrong once real wiring is involved -- an interceptor missing
// from the real server's chain, a route registered without its
// requireRole wrapper in cmd/controlplane, a migration not applied to
// the deployed database. Each of those would pass every unit test in
// this package and still hand one tenant another tenant's data.
package dashboard_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// e2eEnv collects everything this test needs to reach the running stack.
// Every value is required: a missing one fails the test rather than
// silently falling back to a default that might point at something else.
type e2eEnv struct {
	dashboardURL string
	grpcAddr     string
	certFile     string
	keyFile      string
	caFile       string
	serverName   string
	composeArgs  []string
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s must be set (tests/e2e/run.sh sets it; do not run this test directly)", key)
	}
	return value
}

func loadE2EEnv(t *testing.T) e2eEnv {
	t.Helper()
	return e2eEnv{
		dashboardURL: requireEnv(t, "E2E_DASHBOARD_URL"),
		grpcAddr:     requireEnv(t, "E2E_GRPC_ADDR"),
		certFile:     requireEnv(t, "TLS_CERT_FILE"),
		keyFile:      requireEnv(t, "TLS_KEY_FILE"),
		caFile:       requireEnv(t, "TLS_CA_FILE"),
		serverName:   requireEnv(t, "TLS_SERVER_NAME"),
		composeArgs:  strings.Fields(requireEnv(t, "E2E_COMPOSE")),
	}
}

// adminUser runs controlplane-admin inside the running control-plane
// container to provision a user and an API key, then optionally grants a
// role. This is the same break-glass path an operator would really use
// (ADR-016 §4) rather than an INSERT that could diverge from it.
func (e e2eEnv) adminUser(t *testing.T, displayName, role string) (userID, apiKey string) {
	t.Helper()
	output := e.compose(t, "exec", "-T", "control-plane", "/usr/local/bin/controlplane-admin", "create-user", displayName)
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "user_id:"); ok {
			userID = strings.TrimSpace(rest)
		}
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "api_key:"); ok {
			apiKey = strings.Fields(strings.TrimSpace(rest))[0]
		}
	}
	if userID == "" || apiKey == "" {
		t.Fatalf("could not parse user_id/api_key out of create-user output:\n%s", output)
	}
	if role != "" {
		e.compose(t, "exec", "-T", "control-plane", "/usr/local/bin/controlplane-admin", "grant-role", userID, role)
	}
	return userID, apiKey
}

func (e e2eEnv) compose(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	full := append(append([]string{}, e.composeArgs[1:]...), args...)
	command := exec.CommandContext(ctx, e.composeArgs[0], full...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", e.composeArgs[0], strings.Join(full, " "), err, output)
	}
	return string(output)
}

// submitWorkload calls the real ControlPlaneService over mTLS with the
// tenant's bearer key -- the same path a real client takes, so the
// resulting workload really is owned by that tenant rather than by a
// fixture that merely claims to be.
func (e e2eEnv) submitWorkload(t *testing.T, apiKey string) string {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(e.certFile, e.keyFile)
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}
	caPEM, err := os.ReadFile(e.caFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA file contained no usable certificate")
	}
	transport := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		ServerName:   e.serverName,
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := grpc.NewClient(e.grpcAddr, grpc.WithTransportCredentials(transport))
	if err != nil {
		t.Fatalf("dial control plane: %v", err)
	}
	defer connection.Close()

	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+apiKey)
	// The client supplies definition.workload_id; the server validates it
	// is a UUID (workloadapi.validateSubmission) rather than minting one.
	response, err := controlplanev1.NewControlPlaneServiceClient(connection).SubmitWorkload(authed,
		&controlplanev1.SubmitWorkloadRequest{
			RequestId: uuid.NewString(),
			Image:     "example.invalid/e2e@sha256:" + strings.Repeat("a", 64),
			Definition: &sharedv1.WorkloadDefinition{
				WorkloadId: uuid.NewString(),
				Profile:    sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE,
				Requirements: &sharedv1.ResourceRequirements{
					Cpu: 1, RamMb: 256, StorageGb: 1,
				},
				DurationSeconds: 60,
			},
		})
	if err != nil {
		t.Fatalf("SubmitWorkload: %v", err)
	}
	return response.WorkloadId
}

// get issues an HTTP GET against the dashboard, with the bearer key when
// one is given and entirely unauthenticated when it is empty.
func (e e2eEnv) get(t *testing.T, path, apiKey string) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.dashboardURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

// TestE2ETenantIsolationAcrossGRPCAndDashboard is ADR-016 slice 6's core
// scenario, against the real stack: tenant A submits a workload over
// gRPC; tenant B must not see it through any dashboard surface.
func TestE2ETenantIsolationAcrossGRPCAndDashboard(t *testing.T) {
	env := loadE2EEnv(t)

	_, aliceKey := env.adminUser(t, "e2e-tenant-alice-"+uuid.NewString()[:8], "")
	_, bobKey := env.adminUser(t, "e2e-tenant-bob-"+uuid.NewString()[:8], "")

	workloadID := env.submitWorkload(t, aliceKey)

	// Alice sees her own workload in the list...
	code, body := env.get(t, "/api/v1/my/workloads", aliceKey)
	if code != http.StatusOK {
		t.Fatalf("alice list status = %d, want 200: %s", code, body)
	}
	if !strings.Contains(string(body), workloadID) {
		t.Fatalf("alice's own workload %s missing from her list: %s", workloadID, body)
	}
	// ...and in the detail view.
	code, body = env.get(t, "/api/v1/my/workloads/"+workloadID, aliceKey)
	if code != http.StatusOK {
		t.Fatalf("alice detail status = %d, want 200: %s", code, body)
	}
	// The raw definition bytes must not cross the wire even end to end.
	var detail map[string]json.RawMessage
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if _, present := detail["definition"]; present {
		t.Fatal("raw definition bytes must never be serialized to a tenant")
	}

	// Bob must see neither, through either surface.
	code, body = env.get(t, "/api/v1/my/workloads", bobKey)
	if code != http.StatusOK {
		t.Fatalf("bob list status = %d, want 200: %s", code, body)
	}
	if strings.Contains(string(body), workloadID) {
		t.Fatalf("TENANT ISOLATION BREACH: bob's list contains alice's workload %s: %s", workloadID, body)
	}
	code, body = env.get(t, "/api/v1/my/workloads/"+workloadID, bobKey)
	if code != http.StatusNotFound {
		t.Fatalf("bob detail status = %d, want 404 (never 200, and never 403 which would confirm existence): %s", code, body)
	}

	// The same boundary must hold on the gRPC surface bob could reach
	// directly -- the dashboard is a presentation layer, not the only
	// place tenancy is enforced.
	assertGRPCGetIsDenied(t, env, bobKey, workloadID)
}

func assertGRPCGetIsDenied(t *testing.T, env e2eEnv, apiKey, workloadID string) {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(env.certFile, env.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	connection, err := grpc.NewClient(env.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		ServerName:   env.serverName,
		MinVersion:   tls.VersionTLS13,
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+apiKey)
	_, err = controlplanev1.NewControlPlaneServiceClient(connection).GetWorkload(authed,
		&controlplanev1.GetWorkloadRequest{WorkloadId: workloadID})
	if err == nil {
		t.Fatal("TENANT ISOLATION BREACH: bob's GetWorkload returned another tenant's workload over gRPC")
	}
	if code := status.Code(err); code != codes.NotFound {
		t.Fatalf("GetWorkload for another tenant's workload = %v, want NotFound", code)
	}
}

// TestE2EOperatorViewsRequireTheOperatorRole checks both directions of
// ADR-016 §1's ranking against the real server: a tenant is refused, a
// granted operator is served.
func TestE2EOperatorViewsRequireTheOperatorRole(t *testing.T) {
	env := loadE2EEnv(t)
	_, tenantKey := env.adminUser(t, "e2e-tenant-"+uuid.NewString()[:8], "")
	_, operatorKey := env.adminUser(t, "e2e-operator-"+uuid.NewString()[:8], "operator_readonly")

	for _, path := range []string{"/api/v1/operator/queue", "/api/v1/operator/workers", "/api/v1/operator/audit"} {
		if code, body := env.get(t, path, tenantKey); code != http.StatusForbidden {
			t.Errorf("GET %s as tenant = %d, want 403: %s", path, code, body)
		}
		if code, body := env.get(t, path, operatorKey); code != http.StatusOK {
			t.Errorf("GET %s as operator_readonly = %d, want 200: %s", path, code, body)
		}
		if code, body := env.get(t, path, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated = %d, want 401: %s", path, code, body)
		}
	}
}

// TestE2EUnauthenticatedCallerGetsExactlyPublicTierData is ADR-016 §2's
// Public tier, asserted from outside: the overview stays reachable
// without a credential (providers and chain health are public by
// design), while every tenant- and operator-tier route refuses.
func TestE2EUnauthenticatedCallerGetsExactlyPublicTierData(t *testing.T) {
	env := loadE2EEnv(t)

	code, body := env.get(t, "/api/v1/overview", "")
	if code != http.StatusOK {
		t.Fatalf("unauthenticated GET /api/v1/overview = %d, want 200 (this tier is public by design): %s", code, body)
	}
	var overview map[string]json.RawMessage
	if err := json.Unmarshal(body, &overview); err != nil {
		t.Fatal(err)
	}
	if _, present := overview["providers"]; !present {
		t.Fatal("the public overview should still carry provider data")
	}

	for _, path := range []string{
		"/api/v1/my/workloads",
		"/api/v1/my/workloads/" + uuid.NewString(),
		"/api/v1/operator/queue",
		"/api/v1/operator/workers",
		"/api/v1/operator/audit",
	} {
		if code, body := env.get(t, path, ""); code != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d, want 401: %s", path, code, body)
		}
	}
}

// TestE2EStopIsAuditedAndVisibleToAnOperator closes the loop across
// tiers: a tenant's write action shows up in the operator's audit view,
// naming that tenant -- the audit log is only worth having if it
// actually records real actions taken through the real server.
func TestE2EStopIsAuditedAndVisibleToAnOperator(t *testing.T) {
	env := loadE2EEnv(t)
	aliceID, aliceKey := env.adminUser(t, "e2e-tenant-"+uuid.NewString()[:8], "")
	_, operatorKey := env.adminUser(t, "e2e-operator-"+uuid.NewString()[:8], "operator_readonly")
	workloadID := env.submitWorkload(t, aliceKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		env.dashboardURL+"/api/v1/my/workloads/"+workloadID+"/stop", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+aliceKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("stop status = %d, want 202: %s", response.StatusCode, body)
	}

	code, auditBody := env.get(t, "/api/v1/operator/audit?limit=500", operatorKey)
	if code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200: %s", code, auditBody)
	}
	if !strings.Contains(string(auditBody), workloadID) {
		t.Fatalf("the stop action on %s is missing from the audit log: %s", workloadID, auditBody)
	}
	if !strings.Contains(string(auditBody), aliceID) {
		t.Fatalf("the audit log does not name the acting tenant %s: %s", aliceID, auditBody)
	}

	// A tenant must never be able to read the audit log, even about
	// their own actions -- it is cross-tenant by construction.
	if code, body := env.get(t, "/api/v1/operator/audit", aliceKey); code != http.StatusForbidden {
		t.Fatalf("tenant reading the audit log = %d, want 403: %s", code, body)
	}
}
