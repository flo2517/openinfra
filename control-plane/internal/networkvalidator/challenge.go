package networkvalidator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/blockchainbridge"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// challengeDomain must byte-for-byte match agent-api's CHALLENGE_DOMAIN
// constant (provider-agent/crates/agent-api/src/lib.rs) -- re-derived
// directly from that source, not assumed from any summary, since a
// mismatch here silently breaks every signature verification.
var challengeDomain = []byte("openinfra-availability-proof-v1\x00")

// challengePayloadSize is the size of the random bytes sent as a
// challenge's payload -- "a few hundred bytes" per this task's spec, and
// bounded well under agent-api's MAX_CHALLENGE_PAYLOAD (4096).
const challengePayloadSize = 256

// DefaultDialTimeout/DefaultChallengeTimeout: mirroring
// pallets/availability's existing binary "within deadline or not"
// philosophy (ADR-011 §2's "a response after the deadline is rejected"),
// this validator enforces one bounded deadline on the whole
// dial-plus-RPC round trip rather than grading latency. A few seconds is
// generous enough for a healthy Agent on a local or lightly loaded WAN
// link, tight enough that one unresponsive Agent can't stall a polling
// tick for long.
const (
	DefaultDialTimeout      = 5 * time.Second
	DefaultChallengeTimeout = 8 * time.Second
)

// ChallengeResult is the bounded, integer-only local scoring outcome for
// one (provider, dimension) challenge -- shaped directly for
// Registrar.SubmitEvidence's arguments (score_bps, sample_count,
// payload_hash).
type ChallengeResult struct {
	ScoreBps    uint16
	SampleCount uint32
	PayloadHash [32]byte
	// Reason is human-readable, for logging only -- ADR-011 §5 and this
	// task's spec both call for binary pass/fail scoring on-chain
	// ("don't try to distinguish these for scoring purposes"), but
	// logging *why* a challenge scored zero (unreachable vs. bad hash vs.
	// bad signature vs. timeout) is exactly the auditability this whole
	// loop exists for.
	Reason string
}

// passingScoreBps/failingScoreBps are pallet-network-validator's
// score_bps unit (basis points, 0..=10_000): a full pass or nothing,
// never a float, never a partial credit in this first version.
const (
	passingScoreBps uint16 = 10_000
	failingScoreBps uint16 = 0
)

// ChallengeClientConfig configures dialing an Agent's mTLS gRPC server.
type ChallengeClientConfig struct {
	Resolver *EndpointResolver
	// ClientCertificate is presented as this validator's mTLS client
	// identity -- see blockchainbridge.Registrar.ClientIdentity.
	ClientCertificate tls.Certificate
	// AgentServerCAPool, if non-nil, verifies an Agent's TLS server
	// certificate against it. If nil, the connection uses
	// InsecureSkipVerify -- a real, named security gap; see the doc
	// comment on callSolveChallenge below and this PR's description for
	// the full trust-model discussion, and cmd/networkvalidator's
	// --agent-ca-file flag for how an operator supplies a CA pool instead.
	AgentServerCAPool *x509.CertPool
	DialTimeout       time.Duration
	ChallengeTimeout  time.Duration
}

// ChallengeClient calls an Agent's SolveChallenge RPC over mTLS and
// scores the response, per ADR-013 §4/steps 7-8 of issue #78's slice 4.
type ChallengeClient struct {
	config ChallengeClientConfig
}

func NewChallengeClient(config ChallengeClientConfig) *ChallengeClient {
	if config.DialTimeout == 0 {
		config.DialTimeout = DefaultDialTimeout
	}
	if config.ChallengeTimeout == 0 {
		config.ChallengeTimeout = DefaultChallengeTimeout
	}
	return &ChallengeClient{config: config}
}

// Challenge resolves providerID's Agent endpoint, dials it over mTLS,
// sends a fresh randomized challenge for dimension, and verifies the
// response. It never returns a non-nil error for a challenge that simply
// failed (unreachable Agent, bad hash, bad signature, timeout) -- those
// are all reported as a ChallengeResult with ScoreBps == 0 and a
// human-readable Reason, per this task's "binary pass/fail, don't
// distinguish failure modes on-chain, do log them" design. A non-nil
// error means resolution or challenge construction itself could not be
// attempted at all (e.g. discovery failed, dimension is invalid) --
// distinct from "attempted and failed."
func (c *ChallengeClient) Challenge(ctx context.Context, providerID string, dimension blockchainbridge.ScoreDimension) (ChallengeResult, error) {
	challengeType, err := challengeTypeForDimension(dimension)
	if err != nil {
		return ChallengeResult{}, err
	}
	endpoint, err := c.config.Resolver.Resolve(ctx, providerID)
	if err != nil {
		return ChallengeResult{}, fmt.Errorf("resolve agent endpoint for provider %s: %w", providerID, err)
	}

	payload := make([]byte, challengePayloadSize)
	if _, err := rand.Read(payload); err != nil {
		return ChallengeResult{}, fmt.Errorf("generate challenge payload: %w", err)
	}
	payloadHash := sha256.Sum256(payload)
	challengeID := uuid.NewString()

	callCtx, cancel := context.WithTimeout(ctx, c.config.DialTimeout+c.config.ChallengeTimeout)
	defer cancel()

	response, err := c.callSolveChallenge(callCtx, endpoint, challengeID, challengeType, payload)
	if err != nil {
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: err.Error()}, nil
	}

	if response.ChallengeId != challengeID {
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: "response challenge_id does not match the request"}, nil
	}
	if len(response.Result) != sha256.Size {
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: "response result has an unexpected length"}, nil
	}
	if !bytes.Equal(response.Result, payloadHash[:]) {
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: "response result does not match SHA256(payload)"}, nil
	}
	signed := signedChallengeBytes(challengeID, int32(challengeType), response.Result)
	if !ed25519.Verify(endpoint.PublicKey, signed, response.Signature) {
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: "signature verification failed"}, nil
	}
	return ChallengeResult{ScoreBps: passingScoreBps, SampleCount: 1, PayloadHash: payloadHash, Reason: "ok"}, nil
}

// callSolveChallenge dials endpoint.AgentEndpoint and issues one
// SolveChallenge RPC.
//
// Agent server-certificate trust (ADR-013 step 7's open design question,
// resolved here): the Control Plane's own existing Agent client
// (internal/agentmanager.NewMTLSClient) verifies an Agent's server
// certificate by chaining it to a CA file the Control Plane operator
// already possesses (AGENT_CLIENT_TLS_CA_FILE in this repo's dev
// deployment) -- but an independently operated Network Validator, by
// ADR-013's own premise, is a separate operator who does not necessarily
// have that CA file out of band. A CA's *public* certificate is not
// secret (that is the entire point of a CA certificate -- it exists to be
// distributed and used exactly this way), so the most correct fix is for
// the Control Plane operator to publish it somewhere a validator operator
// can fetch it and pass it via --agent-ca-file (config.AgentServerCAPool
// non-nil): this gets full TLS server authentication, identical in
// strength to what the Control Plane's own Agent client already gets.
// But this slice does not add a publishing channel for that CA
// certificate (e.g. extending the dashboard's agent-endpoint response,
// or a dedicated endpoint) -- that's a reasonable, small follow-up, not
// attempted here since it wasn't asked for. Without --agent-ca-file, this
// method falls back to InsecureSkipVerify: true, meaning the TLS
// handshake does not authenticate *which* server it connected to at all.
// This is a real, intentionally named security gap, not a silent one:
// the mTLS *client* side (this validator authenticating itself to the
// Agent) is unaffected and stays fully verified via the Agent's own
// allowlist check; what's weakened is only this validator's assurance
// that it is really talking to the Agent it thinks it is, which matters
// because a spoofed "Agent" could feed a validator a fabricated passing
// SolveChallenge response. The signature check in Challenge() partially
// mitigates this in practice (a spoofing party would also need the real
// Agent's Ed25519 private key to produce a response that then verifies),
// but that is a mitigation, not a substitute for real transport
// authentication, and is called out here loudly per this task's explicit
// instructions rather than shipped silently.
func (c *ChallengeClient) callSolveChallenge(ctx context.Context, endpoint AgentEndpoint, challengeID string, challengeType agentv1.SolveChallengeRequest_Type, payload []byte) (*agentv1.SolveChallengeResponse, error) {
	parsed, err := url.Parse(endpoint.AgentEndpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("agent endpoint %q is not a valid https address", endpoint.AgentEndpoint)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c.config.ClientCertificate},
		ServerName:   parsed.Hostname(),
	}
	if c.config.AgentServerCAPool != nil {
		tlsConfig.RootCAs = c.config.AgentServerCAPool
	} else {
		// See the package doc comment (AgentServerTrustGap) -- a named,
		// documented, loud gap, not a silent weakening.
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // documented gap, see AgentServerTrustGap
	}

	dialCtx, cancel := context.WithTimeout(ctx, c.config.DialTimeout)
	defer cancel()
	connection, err := grpc.DialContext(dialCtx, parsed.Host, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("dial agent %s: %w", parsed.Host, err)
	}
	defer connection.Close()

	client := agentv1.NewProviderAgentServiceClient(connection)
	requestCtx, requestCancel := context.WithTimeout(ctx, c.config.ChallengeTimeout)
	defer requestCancel()
	response, err := client.SolveChallenge(requestCtx, &agentv1.SolveChallengeRequest{
		ChallengeId: challengeID,
		Type:        challengeType,
		Payload:     payload,
	})
	if err != nil {
		return nil, fmt.Errorf("SolveChallenge RPC: %w", err)
	}
	return response, nil
}

// signedChallengeBytes reproduces exactly what agent-api's solve_challenge
// handler signs (provider-agent/crates/agent-api/src/lib.rs):
//
//	CHALLENGE_DOMAIN ++ be_u32(len(challenge_id)) ++ challenge_id
//	  ++ be_u32(request.r#type) ++ result
//
// challengeType is passed as the raw int32 wire value (request.r#type in
// the Rust handler is the request's raw field, not the parsed/validated
// enum re-encoded) so a future non-contiguous enum change on either side
// can't silently desync this from what the Agent actually signed.
func signedChallengeBytes(challengeID string, challengeType int32, result []byte) []byte {
	signed := make([]byte, 0, len(challengeDomain)+4+len(challengeID)+4+len(result))
	signed = append(signed, challengeDomain...)
	signed = binary.BigEndian.AppendUint32(signed, uint32(len(challengeID)))
	signed = append(signed, challengeID...)
	signed = binary.BigEndian.AppendUint32(signed, uint32(challengeType))
	signed = append(signed, result...)
	return signed
}

func challengeTypeForDimension(dimension blockchainbridge.ScoreDimension) (agentv1.SolveChallengeRequest_Type, error) {
	switch dimension {
	case blockchainbridge.DimensionCompute:
		return agentv1.SolveChallengeRequest_TYPE_COMPUTE, nil
	case blockchainbridge.DimensionStorage:
		return agentv1.SolveChallengeRequest_TYPE_STORAGE, nil
	case blockchainbridge.DimensionNetwork:
		return agentv1.SolveChallengeRequest_TYPE_NETWORK, nil
	case blockchainbridge.DimensionAvailability:
		return agentv1.SolveChallengeRequest_TYPE_AVAILABILITY, nil
	case blockchainbridge.DimensionReliability:
		return agentv1.SolveChallengeRequest_TYPE_RELIABILITY, nil
	default:
		return agentv1.SolveChallengeRequest_TYPE_UNSPECIFIED, fmt.Errorf("unknown score dimension %d", dimension)
	}
}
