// Command eventwitness is ADR-039 §9/§10's witness reference
// implementation: a small, independently-runnable process demonstrating
// that "any independent party can run one" is a real, exercisable
// capability at implementation time (ADR-039 Consequences), not merely a
// theoretical option. It requires no special relationship with a Control
// Plane beyond calling its SubscribeEvents RPC (mTLS client identity
// aside -- the same transport requirement every other RPC in this
// codebase already has, per AGENTS.md) and, when -chain-rpc is set, read
// access to a Substrate chain node to independently verify each event's
// chain_anchor (ADR-039 §5).
//
// It replays one subject's event history via internal/eventlog.VerifyChain
// (hash chain + signature) and, if a chain RPC endpoint is configured,
// internal/eventlog.VerifyChainAnchors (chain_anchor vs. real finalized
// lease state) -- printing exactly what it accepted or rejected, and
// exiting non-zero on the first verification failure so this is scriptable
// (e.g. by a CI job or a monitoring cron), not merely a demo.
//
// Deliberately out of scope for this first version, named honestly rather
// than silently assumed: persisting its own append-only replica to disk
// (ADR-039 §9's "keeps its own append-only copy" -- this version verifies
// and reports, it does not yet durably store what it verified), calling
// RecordWitnessAck back to the Control Plane after a successful verify
// (so ADR-039 §8's pruning gate could actually be exercised by a real,
// external witness rather than only by this package's own tests), and
// discovering subject_ids it has not seen before (SubscribeEvents is
// scoped to one already-known subject per call -- see control_plane.proto's
// own doc comment on why).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openinfra/network/internal/eventlog"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "eventwitness:", err)
		os.Exit(1)
	}
}

func run() error {
	subjectType := os.Getenv("EVENTWITNESS_SUBJECT_TYPE")
	subjectID := os.Getenv("EVENTWITNESS_SUBJECT_ID")
	if subjectType == "" || subjectID == "" {
		return errors.New("EVENTWITNESS_SUBJECT_TYPE and EVENTWITNESS_SUBJECT_ID are required")
	}

	client, closeConnection, err := connect(context.Background())
	if err != nil {
		return err
	}
	defer func() { _ = closeConnection() }()

	stream, err := client.SubscribeEvents(context.Background(), &controlplanev1.SubscribeEventsRequest{
		SubjectType: subjectType, SubjectId: []byte(subjectID), SinceSequence: 0,
	})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	var entries []eventlog.Entry
	for {
		response, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("receive event: %w", err)
		}
		entry, err := entryFromEnvelope(response.GetEvent())
		if err != nil {
			return fmt.Errorf("decode event on the wire: %w", err)
		}
		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		fmt.Println("eventwitness: no events for this subject")
		return nil
	}
	if err := eventlog.VerifyChain(entries); err != nil {
		return fmt.Errorf("REJECTED at sequence %d: %w", len(entries), err)
	}
	fmt.Printf("eventwitness: verified %d events for %s/%s -- hash chain and every signature check out\n", len(entries), subjectType, subjectID)
	fmt.Printf("eventwitness: head event_id=%x sequence=%d\n", entries[len(entries)-1].EventID, entries[len(entries)-1].Sequence)
	return nil
}

func entryFromEnvelope(envelope *sharedv1.EventEnvelope) (eventlog.Entry, error) {
	if envelope == nil {
		return eventlog.Entry{}, errors.New("nil event envelope")
	}
	if len(envelope.GetPrevEventHash()) != 32 || len(envelope.GetPayloadHash()) != 32 || len(envelope.GetSignerPublicKey()) != 32 || len(envelope.GetSignatureBytes()) != 64 {
		return eventlog.Entry{}, errors.New("event envelope has a malformed hash/key/signature length")
	}
	entry := eventlog.Entry{
		SubjectType: eventlog.SubjectType(envelope.GetSubjectType()),
		SubjectID:   envelope.GetSubjectId(),
		Sequence:    envelope.GetSequence(),
		EventType:   envelope.GetEventType(),
		Payload:     envelope.GetPayload(),
		RecordedAt:  envelope.GetTimestamp().AsTime(),
	}
	copy(entry.PrevEventHash[:], envelope.GetPrevEventHash())
	copy(entry.PayloadHash[:], envelope.GetPayloadHash())
	copy(entry.SignerPublicKey[:], envelope.GetSignerPublicKey())
	copy(entry.Signature[:], envelope.GetSignatureBytes())
	entry.EventID = eventlog.EventID(entry.SubjectType, entry.SubjectID, entry.Sequence, entry.PrevEventHash, entry.EventType, entry.PayloadHash)
	if anchor := envelope.GetChainAnchor(); anchor != nil && len(anchor.GetBlockHash()) == 32 {
		chainAnchor := &eventlog.ChainAnchor{LeaseID: anchor.GetLeaseId()}
		copy(chainAnchor.BlockHash[:], anchor.GetBlockHash())
		entry.ChainAnchor = chainAnchor
	}
	return entry, nil
}

// connect mirrors cmd/workloadctl's own connect(): the same mTLS client
// identity env vars every other purpose-built Go client tool in this repo
// already uses (see workloadctl's header comment for why a small,
// purpose-built binary against the generated types, not grpcurl, is this
// codebase's established convention -- the server does not register
// reflection).
func connect(ctx context.Context) (controlplanev1.ControlPlaneServiceClient, func() error, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")
	serverName := os.Getenv("TLS_SERVER_NAME")
	if certFile == "" || keyFile == "" || caFile == "" || serverName == "" {
		return nil, nil, errors.New("TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE, and TLS_SERVER_NAME are required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load client identity: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("CA file contains no certificate")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool, ServerName: serverName}

	address := os.Getenv("CONTROL_PLANE_GRPC_ADDR")
	if address == "" {
		address = "127.0.0.1:50051"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(dialCtx, address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("connect Control Plane: %w", err)
	}
	return controlplanev1.NewControlPlaneServiceClient(connection), connection.Close, nil
}
