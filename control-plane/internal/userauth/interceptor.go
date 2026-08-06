package userauth

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// protectedMethods are the user-facing RPCs on ControlPlaneService that
// require an authenticated tenant. BeginJoin/CompleteJoin/ReportHeartbeat
// are provider-originated and keep their own Ed25519 challenge-signature
// auth (internal/providerjoin) -- deliberately not gated here.
var protectedMethods = map[string]bool{
	"/openinfra.controlplane.v1.ControlPlaneService/SubmitWorkload": true,
	"/openinfra.controlplane.v1.ControlPlaneService/GetWorkload":    true,
	"/openinfra.controlplane.v1.ControlPlaneService/StopWorkload":   true,
}

// RateLimiter is satisfied by internal/ratelimit.RedisLimiter; kept as an
// interface here so userauth doesn't depend on Redis directly.
type RateLimiter interface {
	// Allow reports whether another request identified by key is
	// permitted within the current window.
	Allow(ctx context.Context, key string) (bool, error)
}

// correlationHeader is the metadata key clients may set to correlate a
// request across logs; if absent, the interceptor mints one so every call
// -- including unauthenticated denials -- is traceable end to end (the
// "audit-safe correlation IDs" acceptance criterion applies to denials
// too, not just successes).
const correlationHeader = "x-correlation-id"

type correlationIDKeyType int

const correlationIDKey correlationIDKeyType = 0

// CorrelationIDFromContext returns the correlation ID assigned to this
// call, for handlers/log lines that want to include it.
func CorrelationIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(correlationIDKey).(string)
	return id
}

// defaultCallDeadline bounds how long a protected RPC may run when the
// caller supplied no deadline of its own -- a client that never times out
// should not be able to hold a server-side goroutine (and a Postgres
// connection) open indefinitely.
const defaultCallDeadline = 30 * time.Second

// NewUnaryInterceptor builds the single interceptor wired into the Control
// Plane's gRPC server. It assigns a correlation ID to every call, and for
// protectedMethods additionally: requires a valid, unexpired, unrevoked
// bearer API key (Authenticate never sees or logs the raw key -- only its
// hash), enforces a default deadline, and applies a per-user rate limit.
func NewUnaryInterceptor(repository Repository, limiter RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, correlationID := withCorrelationID(ctx)

		if !protectedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, defaultCallDeadline)
			defer cancel()
		}

		user, err := authenticate(ctx, repository)
		if err != nil {
			slog.Warn("userauth: rejected unauthenticated request", "method", info.FullMethod, "correlation_id", correlationID, "error", err)
			return nil, err
		}

		if limiter != nil {
			allowed, limitErr := limiter.Allow(ctx, user.UserID)
			if limitErr != nil {
				slog.Error("userauth: rate limiter unavailable; failing closed", "method", info.FullMethod, "correlation_id", correlationID, "error", limitErr)
				return nil, status.Error(codes.Unavailable, "rate limiter unavailable")
			}
			if !allowed {
				return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
			}
		}

		ctx = WithUserID(ctx, user.UserID)
		return handler(ctx, req)
	}
}

func authenticate(ctx context.Context, repository Repository) (User, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return User{}, status.Error(codes.Unauthenticated, "authorization metadata is required")
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return User{}, status.Error(codes.Unauthenticated, "exactly one authorization header is required")
	}
	const schemePrefix = "Bearer "
	if !strings.HasPrefix(values[0], schemePrefix) {
		return User{}, status.Error(codes.Unauthenticated, "authorization header must use the Bearer scheme")
	}
	raw := strings.TrimPrefix(values[0], schemePrefix)
	if raw == "" {
		return User{}, status.Error(codes.Unauthenticated, "bearer token must not be empty")
	}
	user, err := repository.Authenticate(ctx, HashAPIKey(raw))
	if err != nil {
		// ErrInvalidKey and any repository-level failure are surfaced
		// identically to the caller -- an unreachable Postgres must not
		// look distinguishable from a wrong key to a client probing for
		// which case it hit.
		return User{}, status.Error(codes.Unauthenticated, "invalid or expired API key")
	}
	return user, nil
}

func withCorrelationID(ctx context.Context) (context.Context, string) {
	id := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(correlationHeader); len(values) == 1 {
			if parsed, err := uuid.Parse(values[0]); err == nil {
				id = parsed.String()
			}
		}
	}
	if id == "" {
		id = uuid.NewString()
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs(correlationHeader, id)); err != nil {
		slog.Debug("userauth: failed to echo correlation id header", "error", err)
	}
	return context.WithValue(ctx, correlationIDKey, id), id
}
