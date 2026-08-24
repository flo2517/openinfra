package blockchainbridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
)

const maxRPCResponseBytes = 1 << 20

type RPCError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (e *RPCError) Error() string {
	if len(e.Data) != 0 && string(e.Data) != "null" {
		return fmt.Sprintf("Substrate RPC error %d: %s (%s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("Substrate RPC error %d: %s", e.Code, e.Message)
}

// IsTemporarilyBanned reports whether err is a Substrate transaction-pool
// "1012: Transaction is temporarily banned" rejection -- the pool already
// has this exact extrinsic (same account, same nonce, same call bytes) on a
// cooldown from a prior submission. Confirmed live, repeatedly (issue
// #141): a caller whose nonce is derived from *finalized* state (as
// Registrar.EnsureActive's is) cannot escape this by simply retrying --
// finalized state cannot advance past a transaction that is itself what's
// blocking finalization, so an immediate retry reproduces the identical
// extrinsic byte-for-byte and re-triggers the same ban. Callers should wait
// longer than their normal retry schedule before resubmitting after this
// specific error, not shorter -- see providerjoin.Reconciler.fail's use of
// this.
func IsTemporarilyBanned(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr) && rpcErr.Code == 1012
}

type ChainHealth struct {
	Peers           uint64 `json:"peers"`
	IsSyncing       bool   `json:"isSyncing"`
	ShouldHavePeers bool   `json:"shouldHavePeers"`
}

type Header struct {
	ParentHash     string `json:"parentHash"`
	Number         string `json:"number"`
	StateRoot      string `json:"stateRoot"`
	ExtrinsicsRoot string `json:"extrinsicsRoot"`
}

type RuntimeVersion struct {
	SpecVersion        uint32 `json:"specVersion"`
	TransactionVersion uint32 `json:"transactionVersion"`
}

func (h Header) BlockNumber() (uint64, error) {
	if len(h.Number) < 3 || h.Number[:2] != "0x" {
		return 0, fmt.Errorf("invalid Substrate block number %q", h.Number)
	}
	number, err := strconv.ParseUint(h.Number[2:], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse Substrate block number %q: %w", h.Number, err)
	}
	return number, nil
}

type RPCClient struct {
	endpoint string
	http     *http.Client
	nextID   atomic.Uint64
}

func NewRPCClient(endpoint string, client *http.Client) (*RPCClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse Substrate RPC URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("Substrate RPC URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("Substrate RPC URL requires a host and must not contain credentials")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &RPCClient{endpoint: parsed.String(), http: client}, nil
}

func (c *RPCClient) Health(ctx context.Context) (ChainHealth, error) {
	var health ChainHealth
	if err := c.call(ctx, "system_health", []any{}, &health); err != nil {
		return ChainHealth{}, err
	}
	return health, nil
}

func (c *RPCClient) LatestHeader(ctx context.Context) (Header, error) {
	var header Header
	if err := c.call(ctx, "chain_getHeader", []any{}, &header); err != nil {
		return Header{}, err
	}
	return header, nil
}

func (c *RPCClient) RuntimeVersion(ctx context.Context) (RuntimeVersion, error) {
	var version RuntimeVersion
	if err := c.call(ctx, "state_getRuntimeVersion", []any{}, &version); err != nil {
		return RuntimeVersion{}, err
	}
	return version, nil
}

func (c *RPCClient) BlockHash(ctx context.Context, number uint64) (string, error) {
	var hash string
	if err := c.call(ctx, "chain_getBlockHash", []any{number}, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

func (c *RPCClient) FinalizedHead(ctx context.Context) (string, error) {
	var hash string
	if err := c.call(ctx, "chain_getFinalizedHead", []any{}, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

func (c *RPCClient) HeaderAt(ctx context.Context, hash string) (Header, error) {
	var header Header
	if err := c.call(ctx, "chain_getHeader", []any{hash}, &header); err != nil {
		return Header{}, err
	}
	return header, nil
}

func (c *RPCClient) AccountNextIndex(ctx context.Context, account string) (uint64, error) {
	var nonce uint64
	if err := c.call(ctx, "system_accountNextIndex", []any{account}, &nonce); err != nil {
		return 0, err
	}
	return nonce, nil
}

func (c *RPCClient) SubmitExtrinsic(ctx context.Context, encoded string) (string, error) {
	var hash string
	if err := c.call(ctx, "author_submitExtrinsic", []any{encoded}, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

func (c *RPCClient) Storage(ctx context.Context, key, blockHash string) ([]byte, bool, error) {
	var value *string
	if err := c.callNullable(ctx, "state_getStorage", []any{key, blockHash}, &value); err != nil {
		return nil, false, err
	}
	if value == nil {
		return nil, false, nil
	}
	decoded, err := decodeHex(*value)
	if err != nil {
		return nil, false, fmt.Errorf("decode Substrate storage value: %w", err)
	}
	return decoded, true, nil
}

func (c *RPCClient) call(ctx context.Context, method string, params any, result any) error {
	return c.callWithNullPolicy(ctx, method, params, result, false)
}

func (c *RPCClient) callNullable(ctx context.Context, method string, params any, result any) error {
	return c.callWithNullPolicy(ctx, method, params, result, true)
}

func (c *RPCClient) callWithNullPolicy(ctx context.Context, method string, params any, result any, allowNull bool) error {
	id := c.nextID.Add(1)
	payload, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encode Substrate RPC request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Substrate RPC request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("call Substrate RPC %s: %w", method, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRPCResponseBytes))
		return fmt.Errorf("call Substrate RPC %s: unexpected HTTP status %s", method, response.Status)
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      uint64          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *RPCError       `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxRPCResponseBytes+1))
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("decode Substrate RPC %s response: %w", method, err)
	}
	if envelope.JSONRPC != "2.0" || envelope.ID != id {
		return fmt.Errorf("invalid Substrate RPC %s response envelope", method)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if len(envelope.Result) == 0 || (!allowNull && string(envelope.Result) == "null") {
		return fmt.Errorf("Substrate RPC %s returned no result", method)
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("decode Substrate RPC %s result: %w", method, err)
	}
	return nil
}

func decodeHex(value string) ([]byte, error) {
	if len(value) < 2 || value[:2] != "0x" {
		return nil, errors.New("hex value must start with 0x")
	}
	if len(value)%2 != 0 {
		return nil, errors.New("hex value has odd length")
	}
	return hex.DecodeString(value[2:])
}
