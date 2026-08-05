package blockchainbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRPCClientHealthAndHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) == "" {
			t.Fatal("expected JSON-RPC request body")
		}
		if bytes.Contains(body, []byte(`"method":"system_health"`)) {
			_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"peers":0,"isSyncing":false,"shouldHavePeers":false}}`))
			return
		}
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"parentHash":"0x01","number":"0x2a","stateRoot":"0x02","extrinsicsRoot":"0x03"}}`))
	}))
	defer server.Close()

	client, err := NewRPCClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	health, err := client.Health(context.Background())
	if err != nil || health.IsSyncing {
		t.Fatalf("unexpected health result: %+v, %v", health, err)
	}
	header, err := client.LatestHeader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	number, err := header.BlockNumber()
	if err != nil || number != 42 {
		t.Fatalf("unexpected block number: %d, %v", number, err)
	}
}

func TestRPCClientRejectsRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`))
	}))
	defer server.Close()
	client, err := NewRPCClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Health(context.Background())
	var rpcError *RPCError
	if !errors.As(err, &rpcError) || rpcError.Code != -32601 {
		t.Fatalf("expected typed RPC error, got %v", err)
	}
}

func TestRPCClientHonorsContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer server.Close()
	client, err := NewRPCClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Health(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestNewRPCClientValidatesEndpoint(t *testing.T) {
	for _, endpoint := range []string{"ws://127.0.0.1:9944", "http://user:secret@localhost:9944", "http:///missing-host"} {
		t.Run(fmt.Sprintf("endpoint_%q", endpoint), func(t *testing.T) {
			if _, err := NewRPCClient(endpoint, nil); err == nil {
				t.Fatalf("expected %q to be rejected", endpoint)
			}
		})
	}
}
