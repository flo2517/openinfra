package networkvalidator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
)

// bandwidthProbeDomain must byte-for-byte match agent-api's
// BANDWIDTH_PROBE_DOMAIN constant (provider-agent/crates/agent-api/
// src/lib.rs) -- re-derived directly from that source, not assumed from
// a summary, matching challengeDomain's identical discipline above: a
// mismatch here silently breaks every MeasureBandwidth signature
// verification.
var bandwidthProbeDomain = []byte("openinfra-bandwidth-probe-v1\x00")

// bandwidthProbeBytes is the size of the random upload payload this
// validator sends in a MeasureBandwidth probe, and also the size it
// requests back in the download direction (symmetric by default: ADR-015
// does not require symmetry, but there is no a priori reason for this
// validator to probe one direction harder than the other). Matches
// agent-api's MAX_BANDWIDTH_PROBE_BYTES exactly (the largest probe
// agent-api will accept) -- see that constant's doc comment for the
// "large enough to time meaningfully, small enough to bound the Agent's
// per-request cost" reasoning ADR-015 §3 documents; using the maximum
// bound maximizes this probe's timing resolution.
const bandwidthProbeBytes = 8 * 1024 * 1024

// bandwidthMessageSizeLimit raises grpc-go's default 4 MiB per-message
// limit (see dial's doc comment) to accommodate a bandwidthProbeBytes-
// sized payload plus a fixed margin for protobuf/gRPC framing overhead
// beyond the raw payload bytes -- matching agent-api's own raised
// server-side limit (BANDWIDTH_MESSAGE_SIZE_LIMIT in agent-cli/src/
// main.rs) so neither side rejects the other's message first.
const bandwidthMessageSizeLimit = bandwidthProbeBytes + 64*1024

// bandwidthToleranceBps (ADR-015 §5): measured throughput must reach at
// least this fraction (basis points, matching this codebase's existing
// 0..10_000 convention elsewhere, e.g. pallet-network-validator's
// score_bps) of a provider's own declared bandwidth in *both* directions
// to pass. 70% -- ADR-015 §5's own suggested value, adopted here as the
// actual threshold: generous enough to absorb this measurement's
// documented coarseness (one HTTP/2 stream, no multi-connection
// saturation, no TCP-slow-start removal, and estimateThroughputMbps's own
// proportional time-split approximation below), tight enough to still
// catch a materially false declaration, which is this dimension's
// explicit bar (ADR-015 §5's "honest caveat") -- not a precise SLA check.
const bandwidthToleranceBps = 7000

// DefaultBandwidthProbesPerRound is ADR-025 §1's default probe count.
// Small enough to keep the challenge loop's per-round latency budget for
// the Network dimension bounded (each probe is a full
// bandwidthProbeBytes-sized round trip), large enough that a provider
// cannot simply sustain a boosted link for one probe's duration and pass.
const DefaultBandwidthProbesPerRound = 3

// bandwidthProbeOutcome is one probe's result: either a verified
// measurement (failed == false) or the reason it wasn't (failed == true,
// mirroring MeasureBandwidth's own convention of never returning a
// non-nil error for an attempted-but-failed probe).
type bandwidthProbeOutcome struct {
	ingressMbps, egressMbps float64
	payloadHash             [32]byte
	failed                  bool
	reason                  string
}

// MeasureBandwidth is ADR-015's replacement for a generic SolveChallenge
// call on the Network dimension, extended by ADR-025 §1 to run
// config.BandwidthProbesPerRound independent probes and score the
// *minimum* measured throughput across all of them in each direction --
// a provider that detects and rides out one probe still has to sustain
// every other one. Like Challenge, a non-nil error means discovery could
// not even be attempted; every attempted-but-failed outcome (unreachable
// Agent, bad hash, bad signature, under-tolerance measurement -- in any
// single probe) is a ChallengeResult with ScoreBps == 0 and a
// human-readable Reason, never a non-nil error. One failed probe fails
// the whole round: a minimum is meaningless over a set that includes a
// probe with no valid measurement at all.
func (c *ChallengeClient) MeasureBandwidth(ctx context.Context, providerID string) (ChallengeResult, error) {
	endpoint, err := c.config.Resolver.Resolve(ctx, providerID)
	if err != nil {
		return ChallengeResult{}, fmt.Errorf("resolve agent endpoint for provider %s: %w", providerID, err)
	}

	probes := c.config.BandwidthProbesPerRound
	if probes <= 0 {
		probes = DefaultBandwidthProbesPerRound
	}

	// Nothing to score against is not a pass -- and, just as importantly,
	// not a fail either. Both directions are checked because a provider
	// declaring only one of them still leaves the other unverifiable, and
	// a result that verified half of what it claims to verify should not
	// be submitted as a full pass. Captured once up front, before the
	// probe loop, so this verdict is not at the mercy of *how* a probe
	// turns out: a provider with no declared capacity must get Unscored
	// even when a probe also fails outright (unreachable Agent, bad
	// signature) -- there was never a judgement to make in the first
	// place, so a transient network hiccup on top of that must not turn
	// into a permanent, on-chain failing score. See the loop below.
	capacityDeclared := endpoint.DeclaredIngressMbps > 0 && endpoint.DeclaredEgressMbps > 0

	var minIngress, minEgress float64
	var lastPayloadHash [32]byte
	for i := 0; i < probes; i++ {
		outcome, err := c.runOneBandwidthProbe(ctx, endpoint)
		if err != nil {
			return ChallengeResult{}, err
		}
		lastPayloadHash = outcome.payloadHash
		if outcome.failed {
			if !capacityDeclared {
				return ChallengeResult{
					Unscored:    true,
					PayloadHash: outcome.payloadHash,
					Reason: fmt.Sprintf(
						"unscored: no declared capacity to verify against (declared ingress=%dMbps, egress=%dMbps); probe %d/%d also failed: %s",
						endpoint.DeclaredIngressMbps, endpoint.DeclaredEgressMbps, i+1, probes, outcome.reason,
					),
				}, nil
			}
			return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: outcome.payloadHash, Reason: fmt.Sprintf("probe %d/%d: %s", i+1, probes, outcome.reason)}, nil
		}
		if i == 0 || outcome.ingressMbps < minIngress {
			minIngress = outcome.ingressMbps
		}
		if i == 0 || outcome.egressMbps < minEgress {
			minEgress = outcome.egressMbps
		}
	}

	if !capacityDeclared {
		return ChallengeResult{
			Unscored:    true,
			PayloadHash: lastPayloadHash,
			Reason: fmt.Sprintf(
				"unscored: no declared capacity to verify against (declared ingress=%dMbps, egress=%dMbps); measured ingress=%.1fMbps egress=%.1fMbps",
				endpoint.DeclaredIngressMbps, endpoint.DeclaredEgressMbps, minIngress, minEgress,
			),
		}, nil
	}

	ingressPasses := passesBandwidthTolerance(minIngress, endpoint.DeclaredIngressMbps)
	egressPasses := passesBandwidthTolerance(minEgress, endpoint.DeclaredEgressMbps)
	if !ingressPasses || !egressPasses {
		reason := fmt.Sprintf(
			"minimum across %d probes below tolerance: ingress=%.1fMbps (declared %dMbps), egress=%.1fMbps (declared %dMbps)",
			probes, minIngress, endpoint.DeclaredIngressMbps, minEgress, endpoint.DeclaredEgressMbps,
		)
		return ChallengeResult{ScoreBps: failingScoreBps, SampleCount: 1, PayloadHash: lastPayloadHash, Reason: reason}, nil
	}
	return ChallengeResult{
		ScoreBps: passingScoreBps, SampleCount: 1, PayloadHash: lastPayloadHash,
		Reason: fmt.Sprintf("ok: min-of-%d ingress=%.1fMbps egress=%.1fMbps", probes, minIngress, minEgress),
	}, nil
}

// runOneBandwidthProbe is a single ADR-015 round trip: send and request a
// large random payload, verify the Agent's signed response, and estimate
// this probe's ingress/egress throughput. Factored out of MeasureBandwidth
// so ADR-025 §1 can run several independently without duplicating the
// verification logic.
func (c *ChallengeClient) runOneBandwidthProbe(ctx context.Context, endpoint AgentEndpoint) (bandwidthProbeOutcome, error) {
	uploadPayload := make([]byte, bandwidthProbeBytes)
	if _, err := rand.Read(uploadPayload); err != nil {
		return bandwidthProbeOutcome{}, fmt.Errorf("generate bandwidth probe payload: %w", err)
	}
	uploadPayloadHash := sha256.Sum256(uploadPayload)
	probeID := uuid.NewString()

	callCtx, cancel := context.WithTimeout(ctx, c.config.DialTimeout+c.config.ChallengeTimeout)
	defer cancel()

	response, elapsed, err := c.callMeasureBandwidth(callCtx, endpoint, probeID, uploadPayload, bandwidthProbeBytes)
	if err != nil {
		// No response exists to derive ADR-015 §5's SHA256(upload_
		// payload_hash ++ download_payload) payload_hash from -- falling
		// back to a hash of what this validator sent so a failed attempt
		// still carries *some* addressable evidence, not an all-zero
		// hash.
		return bandwidthProbeOutcome{payloadHash: uploadPayloadHash, failed: true, reason: err.Error()}, nil
	}

	// ADR-015 §5's payload_hash formula is response-dependent (it hashes
	// what the Agent returned, not what this validator sent), so it's
	// computed once a response exists at all, before any verification
	// step below -- every subsequent return, pass or fail, reports the
	// same hash, matching what was actually received.
	payloadHash := sha256.Sum256(append(append([]byte{}, response.UploadPayloadHash...), response.DownloadPayload...))

	if response.ProbeId != probeID {
		return bandwidthProbeOutcome{payloadHash: payloadHash, failed: true, reason: "response probe_id does not match the request"}, nil
	}
	if len(response.UploadPayloadHash) != sha256.Size {
		return bandwidthProbeOutcome{payloadHash: payloadHash, failed: true, reason: "response upload_payload_hash has an unexpected length"}, nil
	}
	if !bytes.Equal(response.UploadPayloadHash, uploadPayloadHash[:]) {
		return bandwidthProbeOutcome{payloadHash: payloadHash, failed: true, reason: "response upload_payload_hash does not match SHA256(upload_payload)"}, nil
	}
	if len(response.DownloadPayload) != bandwidthProbeBytes {
		return bandwidthProbeOutcome{payloadHash: payloadHash, failed: true, reason: "response download_payload length does not match requested_download_bytes"}, nil
	}
	signed := bandwidthSignedBytes(response.ProbeId, response.UploadPayloadHash, response.DownloadPayload, response.ServerProcessingMs)
	if !ed25519.Verify(endpoint.PublicKey, signed, response.Signature) {
		return bandwidthProbeOutcome{payloadHash: payloadHash, failed: true, reason: "signature verification failed"}, nil
	}

	ingressMbps, egressMbps := estimateThroughputMbps(elapsed, response.ServerProcessingMs, len(uploadPayload), len(response.DownloadPayload))
	return bandwidthProbeOutcome{ingressMbps: ingressMbps, egressMbps: egressMbps, payloadHash: payloadHash}, nil
}

// callMeasureBandwidth dials endpoint.AgentEndpoint (same mTLS trust
// model as callSolveChallenge, see dial's doc comment) and issues one
// MeasureBandwidth RPC, returning the validator's own wall-clock
// measurement of the whole round trip alongside the response --
// estimateThroughputMbps needs both.
func (c *ChallengeClient) callMeasureBandwidth(ctx context.Context, endpoint AgentEndpoint, probeID string, uploadPayload []byte, requestedDownloadBytes uint32) (*agentv1.MeasureBandwidthResponse, time.Duration, error) {
	connection, err := c.dial(ctx, endpoint)
	if err != nil {
		return nil, 0, err
	}
	defer connection.Close()

	client := agentv1.NewProviderAgentServiceClient(connection)
	requestCtx, requestCancel := context.WithTimeout(ctx, c.config.ChallengeTimeout)
	defer requestCancel()

	started := time.Now()
	response, err := client.MeasureBandwidth(requestCtx, &agentv1.MeasureBandwidthRequest{
		ProbeId:                probeID,
		UploadPayload:          uploadPayload,
		RequestedDownloadBytes: requestedDownloadBytes,
	})
	elapsed := time.Since(started)
	if err != nil {
		return nil, 0, fmt.Errorf("MeasureBandwidth RPC: %w", err)
	}
	return response, elapsed, nil
}

// estimateThroughputMbps is ADR-015 §2's approximation, spelled out: a
// single unary gRPC call over the standard client API does not expose
// "time spent only writing the request" separately from "time spent only
// reading the response," so there is no way to time each direction
// exactly from this side. Instead: subtract the Agent's own reported
// server_processing_ms from the validator's wall-clock round trip to get
// the network-attributable portion, then split that time between the two
// directions proportionally to each direction's byte count, then convert
// each direction's slice of time into Mbps. ADR-015 §2/§5 name this exact
// class of coarseness as the deliberate MVP tradeoff, not an oversight.
func estimateThroughputMbps(elapsed time.Duration, serverProcessingMs uint32, uploadBytes, downloadBytes int) (ingressMbps, egressMbps float64) {
	networkMs := elapsed.Seconds()*1000 - float64(serverProcessingMs)
	if networkMs < 1 {
		// Guards against clock skew/rounding producing a non-positive
		// duration (e.g. a near-instant loopback round trip) -- 1ms is a
		// floor, not a measurement.
		networkMs = 1
	}
	totalBytes := uploadBytes + downloadBytes
	if totalBytes == 0 {
		return 0, 0
	}
	if uploadBytes > 0 {
		uploadMs := networkMs * float64(uploadBytes) / float64(totalBytes)
		ingressMbps = float64(uploadBytes) * 8 / uploadMs / 1000
	}
	if downloadBytes > 0 {
		downloadMs := networkMs * float64(downloadBytes) / float64(totalBytes)
		egressMbps = float64(downloadBytes) * 8 / downloadMs / 1000
	}
	return ingressMbps, egressMbps
}

// passesBandwidthTolerance applies ADR-015 §5's tolerance check for one
// direction.
//
// A non-positive declaredMbps is rejected by MeasureBandwidth before this
// is ever called, as unscored rather than as a pass -- see the guard
// there. The check is repeated here so this function is safe on its own
// terms and can never be the place a "nothing to verify against" case
// quietly becomes a pass: an unverifiable direction returns false, and
// the caller is responsible for having already classified it as unscored.
func passesBandwidthTolerance(measuredMbps float64, declaredMbps int32) bool {
	if declaredMbps <= 0 {
		return false
	}
	threshold := float64(declaredMbps) * float64(bandwidthToleranceBps) / 10000
	return measuredMbps >= threshold
}

// bandwidthSignedBytes reproduces exactly what agent-api's
// measure_bandwidth handler signs (provider-agent/crates/agent-api/
// src/lib.rs's bandwidth_signed_bytes):
//
//	BANDWIDTH_PROBE_DOMAIN ++ be_u32(len(probe_id)) ++ probe_id
//	  ++ upload_payload_hash (32 bytes, fixed)
//	  ++ be_u32(len(download_payload)) ++ download_payload
//	  ++ be_u32(server_processing_ms)
func bandwidthSignedBytes(probeID string, uploadPayloadHash []byte, downloadPayload []byte, serverProcessingMs uint32) []byte {
	signed := make([]byte, 0, len(bandwidthProbeDomain)+4+len(probeID)+len(uploadPayloadHash)+4+len(downloadPayload)+4)
	signed = append(signed, bandwidthProbeDomain...)
	signed = binary.BigEndian.AppendUint32(signed, uint32(len(probeID)))
	signed = append(signed, probeID...)
	signed = append(signed, uploadPayloadHash...)
	signed = binary.BigEndian.AppendUint32(signed, uint32(len(downloadPayload)))
	signed = append(signed, downloadPayload...)
	signed = binary.BigEndian.AppendUint32(signed, serverProcessingMs)
	return signed
}
