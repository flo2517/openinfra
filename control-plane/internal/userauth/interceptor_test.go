package userauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openinfra/network/internal/userauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeRepository struct {
	users map[[32]byte]userauth.User
	err   error
}

func (r fakeRepository) CreateUser(context.Context, string) (userauth.User, error) { panic("unused") }
func (r fakeRepository) CreateAPIKey(context.Context, string) (userauth.APIKey, error) {
	panic("unused")
}
func (r fakeRepository) CreateAPIKeyWithExpiry(context.Context, string, *time.Time) (userauth.APIKey, error) {
	panic("unused")
}
func (r fakeRepository) RevokeAPIKey(context.Context, string) error { panic("unused") }
func (r fakeRepository) Authenticate(_ context.Context, hash [32]byte) (userauth.User, error) {
	if r.err != nil {
		return userauth.User{}, r.err
	}
	user, ok := r.users[hash]
	if !ok {
		return userauth.User{}, userauth.ErrInvalidKey
	}
	return user, nil
}

type fakeLimiter struct {
	allow bool
	err   error
	calls []string
}

func (l *fakeLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.calls = append(l.calls, key)
	return l.allow, l.err
}

const rawKey = "oiu_test-key"

func newTestRepository() fakeRepository {
	user := userauth.User{UserID: "user-1"}
	return fakeRepository{users: map[[32]byte]userauth.User{userauth.HashAPIKey(rawKey): user}}
}

func handlerRecordingContext(t *testing.T, ctx *context.Context) grpc.UnaryHandler {
	return func(handlerCtx context.Context, req any) (any, error) {
		*ctx = handlerCtx
		return "ok", nil
	}
}

func callWith(t *testing.T, interceptor grpc.UnaryServerInterceptor, method string, md metadata.MD) (any, error, context.Context) {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(), md)
	var handlerCtx context.Context
	resp, err := interceptor(ctx, "req", &grpc.UnaryServerInfo{FullMethod: method}, handlerRecordingContext(t, &handlerCtx))
	return resp, err, handlerCtx
}

func TestInterceptorAcceptsAValidBearerKeyAndInjectsUserID(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	md := metadata.Pairs("authorization", "Bearer "+rawKey)

	resp, err, handlerCtx := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/SubmitWorkload", md)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp != "ok" {
		t.Fatalf("unexpected response %v", resp)
	}
	userID, ok := userauth.UserIDFromContext(handlerCtx)
	if !ok || userID != "user-1" {
		t.Fatalf("UserIDFromContext() = %q, %v, want user-1, true", userID, ok)
	}
}

func TestInterceptorRejectsMissingAuthorizationMetadata(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/GetWorkload", metadata.MD{})
	assertCode(t, err, codes.Unauthenticated)
}

func TestInterceptorRejectsAWrongScheme(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	md := metadata.Pairs("authorization", "Basic "+rawKey)
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/GetWorkload", md)
	assertCode(t, err, codes.Unauthenticated)
}

func TestInterceptorRejectsAnInvalidKey(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	md := metadata.Pairs("authorization", "Bearer oiu_wrong-key")
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/GetWorkload", md)
	assertCode(t, err, codes.Unauthenticated)
}

func TestInterceptorFailsClosedWhenTheRepositoryErrors(t *testing.T) {
	repository := fakeRepository{err: errors.New("connection refused")}
	interceptor := userauth.NewUnaryInterceptor(repository, &fakeLimiter{allow: true})
	md := metadata.Pairs("authorization", "Bearer "+rawKey)
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/GetWorkload", md)
	assertCode(t, err, codes.Unauthenticated)
}

func TestInterceptorSkipsAuthForUnprotectedMethods(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	resp, err, handlerCtx := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat", metadata.MD{})
	if err != nil {
		t.Fatalf("expected an unprotected method to bypass auth entirely, got %v", err)
	}
	if resp != "ok" {
		t.Fatalf("unexpected response %v", resp)
	}
	if _, ok := userauth.UserIDFromContext(handlerCtx); ok {
		t.Fatal("expected no user ID to be injected for an unprotected method")
	}
}

func TestInterceptorEnforcesTheRateLimitAfterAuthentication(t *testing.T) {
	limiter := &fakeLimiter{allow: false}
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), limiter)
	md := metadata.Pairs("authorization", "Bearer "+rawKey)
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/SubmitWorkload", md)
	assertCode(t, err, codes.ResourceExhausted)
	if len(limiter.calls) != 1 || limiter.calls[0] != "user-1" {
		t.Fatalf("expected the rate limiter to be checked once with the authenticated user ID, got %v", limiter.calls)
	}
}

func TestInterceptorFailsClosedWhenTheRateLimiterErrors(t *testing.T) {
	limiter := &fakeLimiter{err: errors.New("redis unavailable")}
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), limiter)
	md := metadata.Pairs("authorization", "Bearer "+rawKey)
	_, err, _ := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/SubmitWorkload", md)
	assertCode(t, err, codes.Unavailable)
}

func TestInterceptorGeneratesACorrelationIDWhenNoneIsSupplied(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	_, err, handlerCtx := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat", metadata.MD{})
	if err != nil {
		t.Fatal(err)
	}
	if userauth.CorrelationIDFromContext(handlerCtx) == "" {
		t.Fatal("expected a correlation ID to be assigned even for an unprotected, unauthenticated call")
	}
}

func TestInterceptorPreservesAClientSuppliedCorrelationID(t *testing.T) {
	interceptor := userauth.NewUnaryInterceptor(newTestRepository(), &fakeLimiter{allow: true})
	const supplied = "11111111-1111-1111-1111-111111111111"
	md := metadata.Pairs("x-correlation-id", supplied)
	_, err, handlerCtx := callWith(t, interceptor, "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat", md)
	if err != nil {
		t.Fatal(err)
	}
	if got := userauth.CorrelationIDFromContext(handlerCtx); got != supplied {
		t.Fatalf("CorrelationIDFromContext() = %q, want the client-supplied %q", got, supplied)
	}
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := status.Code(err); got != want {
		t.Fatalf("status code = %v, want %v (error: %v)", got, want, err)
	}
}
