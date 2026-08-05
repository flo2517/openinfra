package agentmanager

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

func TestMTLSClientVerifiesRunningAgent(t *testing.T) {
	if os.Getenv("OPENINFRA_AGENT_INTEGRATION") != "1" {
		t.Skip("set OPENINFRA_AGENT_INTEGRATION=1")
	}
	publicKey, err := hex.DecodeString(os.Getenv("OPENINFRA_AGENT_PUBLIC_KEY_HEX"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewMTLSClient(os.Getenv("OPENINFRA_AGENT_CLIENT_CERT"), os.Getenv("OPENINFRA_AGENT_CLIENT_KEY"), os.Getenv("OPENINFRA_AGENT_CA"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, _, err := client.ConnectVerified(ctx, RegisteredProvider{ProviderID: os.Getenv("OPENINFRA_AGENT_PROVIDER_ID"), PublicKey: publicKey, AgentEndpoint: os.Getenv("OPENINFRA_AGENT_ENDPOINT")})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
}
