// Package metering implements issue #20's off-chain, auditable usage-
// metering and invoice ledger, per ADR-029's evidence model (§6): the
// Control Plane verifies each signed MeteringSummary an Agent's
// GetUsageSummary RPC produces, persists an append-only evidence/
// invoice trail, and quarantines anything that cannot be safely billed.
package metering

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// meteringDomain must match agent-api's METERING_DOMAIN byte-for-byte --
// a mismatch here means every metering signature fails verification.
const meteringDomain = "openinfra-metering-v1\x00"

// signedBytes builds the exact byte sequence agent-api's
// metering_signed_bytes (provider-agent/crates/agent-api/src/lib.rs)
// signs and hashes for a MeteringSummary (ADR-029 §6). Deliberately a
// hand-rolled encoding, not this package's own proto marshal of
// `summary` -- the same reasoning ReportHeartbeat's domain-separated
// signing already established for this codebase's own RPCs, extended
// here across the Rust/Go boundary specifically so agreement never
// depends on prost and protobuf-go producing byte-identical output.
//
//	METERING_DOMAIN
//	  ++ be_u32(len(workload_id)) ++ workload_id
//	  ++ be_u32(len(lease_id)) ++ lease_id
//	  ++ be_u64(sequence)
//	  ++ be_u64(period_start)
//	  ++ be_u64(period_end)
//	  ++ be_u32(metering_schema_version)
//	  ++ be_u64(cpu_core_seconds)
//	  ++ be_u64(ram_mb_seconds)
//	  ++ be_u64(storage_gb_seconds)
//	  ++ be_u64(network_egress_mb)
//	  ++ be_u64(network_ingress_mb)
//	  ++ be_u64(gpu_seconds)
func signedBytes(summary *sharedv1.MeteringSummary) []byte {
	workloadID := []byte(summary.WorkloadId)
	leaseID := []byte(summary.LeaseId)
	signed := make([]byte, 0, len(meteringDomain)+4+len(workloadID)+4+len(leaseID)+8*8+4)
	signed = append(signed, meteringDomain...)
	signed = appendU32Prefixed(signed, workloadID)
	signed = appendU32Prefixed(signed, leaseID)
	signed = appendU64(signed, summary.Sequence)
	signed = appendU64(signed, summary.PeriodStart)
	signed = appendU64(signed, summary.PeriodEnd)
	signed = appendU32(signed, summary.MeteringSchemaVersion)
	signed = appendU64(signed, summary.CpuCoreSeconds)
	signed = appendU64(signed, summary.RamMbSeconds)
	signed = appendU64(signed, summary.StorageGbSeconds)
	signed = appendU64(signed, summary.NetworkEgressMb)
	signed = appendU64(signed, summary.NetworkIngressMb)
	signed = appendU64(signed, summary.GpuSeconds)
	return signed
}

func appendU32Prefixed(dst []byte, value []byte) []byte {
	dst = appendU32(dst, uint32(len(value)))
	return append(dst, value...)
}

func appendU32(dst []byte, value uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	return append(dst, buf[:]...)
}

func appendU64(dst []byte, value uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	return append(dst, buf[:]...)
}

// evidenceHash is SHA-256 over the identical canonical bytes the
// signature covers -- not a hash of any proto wire encoding, and not
// itself signed separately (agent-api's GetUsageSummaryResponse.
// evidence_hash is computed the same way, purely so a caller does not
// need to recompute it just to correlate a response with a stored row).
//
// SHA-256, not blake2_256 (this codebase's existing on-chain hashing
// convention, e.g. pallet-network-validator's selection seed): #21's
// pallet-escrow does not exist yet, and even matching its hash function
// would not make this hash byte-identical to whatever on-chain
// evidence_hash it eventually computes, since that will hash a SCALE
// encoding of its own Rust struct, not this package's canonical bytes.
// True byte-for-byte cross-hash compatibility is therefore not
// achievable from this side alone; SHA-256 is chosen instead because
// it is already this codebase's off-chain hashing convention
// (provider_id, heartbeat payload_hash) and needs no new Go dependency.
// Coordinating #21's on-chain evidence_hash construction against this
// one is named as follow-up work in the implementing PR's description.
func evidenceHash(signed []byte) [32]byte {
	return sha256.Sum256(signed)
}

// verifySignature checks `signature` is a valid Ed25519 signature by
// `publicKey` over `summary`'s canonical bytes.
func verifySignature(publicKey ed25519.PublicKey, summary *sharedv1.MeteringSummary, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, signedBytes(summary), signature)
}
