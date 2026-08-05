package providerjoin

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const heartbeatKeyPrefix = "openinfra:heartbeat:"

var acceptHeartbeatScript = redis.NewScript(`
local current_request = redis.call("HGET", KEYS[1], "request_id")
local current_hash = redis.call("HGET", KEYS[1], "payload_hash")
local current_sequence = redis.call("HGET", KEYS[1], "sequence")
if current_request == ARGV[1] then
  if current_hash == ARGV[3] then
    redis.call("PEXPIRE", KEYS[1], ARGV[5])
    return 1
  end
  return -1
end
if current_sequence and tonumber(ARGV[2]) <= tonumber(current_sequence) then
  return -2
end
redis.call("HSET", KEYS[1], "request_id", ARGV[1], "sequence", ARGV[2], "payload_hash", ARGV[3], "payload", ARGV[4])
redis.call("PEXPIRE", KEYS[1], ARGV[5])
return 1
`)

type RedisHeartbeatStore struct {
	client redis.UniversalClient
}

func NewRedisHeartbeatStore(client redis.UniversalClient) *RedisHeartbeatStore {
	return &RedisHeartbeatStore{client: client}
}

func (s *RedisHeartbeatStore) Accept(ctx context.Context, providerID, requestID string, sequence uint64, payloadHash [sha256.Size]byte, payload []byte, ttl time.Duration) error {
	result, err := acceptHeartbeatScript.Run(ctx, s.client, []string{heartbeatKeyPrefix + providerID}, requestID, sequence, fmt.Sprintf("%x", payloadHash), payload, ttl.Milliseconds()).Int64()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case -1:
		return ErrConflict
	case -2:
		return ErrHeartbeatReplay
	default:
		return errors.New("unexpected Redis heartbeat result")
	}
}
