// Package ratelimit provides a simple Redis-backed fixed-window limiter,
// used to bound how often an authenticated tenant may call the user-facing
// workload RPCs (issue #12's "rate limits" acceptance criterion). Redis is
// the right store for this: the limit only needs to be approximately right
// and self-heals on flush, matching AGENTS.md's "Redis is reconstructible,
// never authoritative" rule -- a lost rate-limit window degrades to
// briefly permissive, never to an incorrect tenancy/ownership decision.
package ratelimit

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// window script atomically increments the per-key counter and sets its
// expiry only on the first increment of a window, so the window's actual
// lifetime is bounded by windowSeconds regardless of request rate --
// two separate INCR/EXPIRE calls would let a key with no expiry survive
// forever if the process crashed between them.
const windowScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`

type RedisLimiter struct {
	client        *redis.Client
	limit         int
	windowSeconds int
	keyPrefix     string
}

// NewRedisLimiter allows up to limit calls per windowSeconds, per key.
func NewRedisLimiter(client *redis.Client, limit, windowSeconds int) *RedisLimiter {
	return &RedisLimiter{client: client, limit: limit, windowSeconds: windowSeconds, keyPrefix: "ratelimit:"}
}

func (l *RedisLimiter) Allow(ctx context.Context, key string) (bool, error) {
	count, err := l.client.Eval(ctx, windowScript, []string{l.keyPrefix + key}, l.windowSeconds).Int()
	if err != nil {
		return false, fmt.Errorf("evaluate rate limit window: %w", err)
	}
	return count <= l.limit, nil
}
