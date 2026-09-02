// Package eventlog implements ADR-039's (issue #33) replicated off-chain
// data plane: a signed, per-subject-sequenced, hash-chained, append-only
// event log, generalizing internal/metering's already-shipped
// metering_evidence pattern (ADR-029 §6) from a single subject class
// (metering) to the workload-lifecycle and lease-correlation classes
// ADR-039 actually targets.
//
// Scope of this package, honestly stated: it implements the log itself
// (canonical event IDs, hash-chaining, signing/verification, idempotent
// append, quarantine of anything that fails verification, snapshotting,
// witness-gated pruning) and the witness-side verifier any independent
// party needs to replay and check a log it received. It does not itself
// wire metering_evidence onto this log (ADR-039's own "Out of scope":
// "Any change to internal/metering's existing, already-shipped evidence
// pipeline... this ADR builds on its pattern, does not modify it") and it
// does not implement tenant key custody for the envelope-encryption
// mechanism in encryption.go (ADR-039 §7's own explicit non-goal).
package eventlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// domain must stay in lockstep with any future non-Go implementation
// (e.g. a Rust witness) that needs to compute the identical event_id/
// signed bytes -- the same cross-language-agreement reasoning
// internal/metering/signing.go's meteringDomain already documents.
const domain = "openinfra-eventlog-v1\x00"

// SubjectType enumerates the subject classes ADR-039 §1 names. Only
// SubjectWorkloadLifecycle is actually written by this PR (see package
// doc); the other two are declared now so their wire/storage shape
// (migration 000024's CHECK constraint) does not need to change again the
// next time a subject class is wired in.
type SubjectType string

const (
	SubjectWorkloadLifecycle SubjectType = "WORKLOAD_LIFECYCLE"
	SubjectLeaseCorrelation  SubjectType = "LEASE_CORRELATION"
	SubjectMeteringEvidence  SubjectType = "METERING_EVIDENCE"
)

// ChainAnchor is ADR-039 §5's ChainAnchor{lease_id, block_hash}: a
// reference to an already-finalized pallet-lease fact (LeaseCreated /
// LeaseStateChanged) an independent witness can check this event against
// without trusting the Control Plane's own word for it.
type ChainAnchor struct {
	LeaseID   uint64
	BlockHash [32]byte
}

// Entry is ADR-039 §1's EventLogEntry, field for field. EventID,
// PayloadHash, PrevEventHash and Signature are always exactly the sizes
// migration 000024 checks; RecordedAt is informational only and
// participates in no ordering or verification decision anywhere in this
// package (ADR-039 §2).
type Entry struct {
	EventID         [32]byte
	SubjectType     SubjectType
	SubjectID       []byte
	Sequence        uint64
	PrevEventHash   [32]byte
	EventType       string
	Payload         []byte
	PayloadHash     [32]byte
	ChainAnchor     *ChainAnchor
	SignerPublicKey [32]byte
	Signature       [64]byte
	RecordedAt      time.Time
}

// ZeroHash is prev_event_hash's required value for sequence = 1 (ADR-039
// §2: "zero for sequence=1").
var ZeroHash [32]byte

// CoreBytes builds the exact canonical byte encoding ADR-039 §1 specifies
// for event_id, verbatim:
//
//	domain
//	  ++ subject_type ++ be_u32(len(subject_id)) ++ subject_id
//	  ++ be_u64(sequence) ++ prev_event_hash
//	  ++ be_u32(len(event_type)) ++ event_type
//	  ++ payload_hash
//
// A hand-rolled encoding, not a proto marshal, for the identical reason
// internal/metering/signing.go's signedBytes already gives: agreement
// between an eventual Rust witness and this Go implementation must never
// depend on prost and protobuf-go producing byte-identical output.
// event_type is length-prefixed here (the ADR's pseudocode omits an
// explicit delimiter for it, unlike subject_id) so no event_type value
// can ever be crafted to shift subsequent bytes and collide with a
// different (subject_id, event_type) pair's encoding.
func CoreBytes(subjectType SubjectType, subjectID []byte, sequence uint64, prevEventHash [32]byte, eventType string, payloadHash [32]byte) []byte {
	out := make([]byte, 0, len(domain)+len(subjectType)+4+len(subjectID)+8+32+4+len(eventType)+32)
	out = append(out, domain...)
	out = append(out, subjectType...)
	out = appendU32Prefixed(out, subjectID)
	out = appendU64(out, sequence)
	out = append(out, prevEventHash[:]...)
	out = appendU32Prefixed(out, []byte(eventType))
	out = append(out, payloadHash[:]...)
	return out
}

// EventID computes ADR-039 §1's deterministic event_id: sha256 of
// CoreBytes. Two independently-constructed replicas that received the
// same event compute the same event_id without coordinating.
func EventID(subjectType SubjectType, subjectID []byte, sequence uint64, prevEventHash [32]byte, eventType string, payloadHash [32]byte) [32]byte {
	return sha256.Sum256(CoreBytes(subjectType, subjectID, sequence, prevEventHash, eventType, payloadHash))
}

// SignedBytes is what Sign/Verify actually cover.
//
// Judgment call, flagged per this task's own instruction not to silently
// improvise on anything affecting the signing/verifiability guarantees:
// ADR-039 §1's pseudocode comments the `signature` field as "Ed25519 over
// the canonical byte encoding below" -- but the literal event_id formula
// it gives immediately after deliberately excludes chain_anchor and
// signer_public_key (so that two replicas can agree on an event's
// identity independent of who signed it or what it's anchored to). Taken
// completely literally, "the canonical byte encoding" would mean the
// signature covers only CoreBytes -- which would leave chain_anchor
// unsigned, so a party holding a validly-signed event could swap its
// anchor to an unrelated (but real) lease/block without invalidating the
// signature at all, silently defeating §5's entire "anchored to finalized
// chain facts" guarantee. That gap is exactly the kind of thing this task
// says never to improvise past silently. The conservative reading taken
// here: SignedBytes = CoreBytes plus chain_anchor plus signer_public_key
// (everything the verifier needs to trust about *this* event except its
// own event_id and signature), so tampering with the claimed anchor or
// the claimed signer always invalidates the signature. This is the
// smallest change consistent with §5's stated reasoning; it is flagged
// explicitly in this PR's description as a resolved ambiguity, not a
// silent extension.
func SignedBytes(entry Entry) []byte {
	core := CoreBytes(entry.SubjectType, entry.SubjectID, entry.Sequence, entry.PrevEventHash, entry.EventType, entry.PayloadHash)
	out := make([]byte, 0, len(core)+1+8+32+32)
	out = append(out, core...)
	if entry.ChainAnchor != nil {
		out = append(out, 1)
		out = appendU64(out, entry.ChainAnchor.LeaseID)
		out = append(out, entry.ChainAnchor.BlockHash[:]...)
	} else {
		out = append(out, 0)
		out = append(out, ZeroHash[:]...)
		out = append(out, ZeroHash[:]...)
	}
	out = append(out, entry.SignerPublicKey[:]...)
	return out
}

func appendU32Prefixed(dst, value []byte) []byte {
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

// Signer produces an Ed25519 signature under a key this package never
// holds or generates itself -- ADR-039 §3's "reuse existing keys, no new
// enrollment". blockchainbridge.Registrar implements this (see its Sign
// method) for Control-Plane-originated events; a provider-signed event
// arrives already signed by the Agent's own agent-core::identity key and
// is verified, not (re)signed, by this package -- see VerifyEntry.
type Signer interface {
	PublicKey() [32]byte
	Sign(payload []byte) [64]byte
}

// Sign builds a fully-populated, self-consistent Entry for a Control-
// Plane-originated (or, in a future caller, any Signer-held-key-
// originated) event: computes payload_hash, event_id, and signature from
// the given fields and signer.
func Sign(signer Signer, subjectType SubjectType, subjectID []byte, sequence uint64, prevEventHash [32]byte, eventType string, payload []byte, anchor *ChainAnchor) Entry {
	payloadHash := sha256.Sum256(payload)
	entry := Entry{
		SubjectType:     subjectType,
		SubjectID:       subjectID,
		Sequence:        sequence,
		PrevEventHash:   prevEventHash,
		EventType:       eventType,
		Payload:         payload,
		PayloadHash:     payloadHash,
		ChainAnchor:     anchor,
		SignerPublicKey: signer.PublicKey(),
	}
	entry.EventID = EventID(subjectType, subjectID, sequence, prevEventHash, eventType, payloadHash)
	entry.Signature = signer.Sign(SignedBytes(entry))
	return entry
}

// ErrInvalidSignature, ErrInvalidEventID, ErrHashChainBreak are the three
// structural verification failures VerifyEntry/VerifyChain distinguish --
// each maps to a distinct event_log_rejections.reason, per ADR-039 §6's
// "quarantine, never silently drop" discipline.
var (
	ErrInvalidSignature = errors.New("eventlog: signature does not verify against signer_public_key")
	ErrInvalidEventID   = errors.New("eventlog: event_id does not match recomputed hash of entry contents")
	ErrHashChainBreak   = errors.New("eventlog: prev_event_hash does not match the previous event's event_id")
)

// VerifyEntry checks an Entry's internal self-consistency: its event_id
// is exactly what CoreBytes/EventID recomputes from its own fields (ADR-039
// §1), and its signature verifies against signer_public_key (ADR-039 §3).
// It does not check hash-chain continuity against a previous event (see
// VerifyChain, which does, across a whole per-subject sequence) or chain-
// anchor validity against real finalized chain state (a witness's own
// job, requiring chain RPC access this package deliberately does not
// take a dependency on -- see ChainAnchorChecker).
func VerifyEntry(entry Entry) error {
	wantID := EventID(entry.SubjectType, entry.SubjectID, entry.Sequence, entry.PrevEventHash, entry.EventType, entry.PayloadHash)
	if wantID != entry.EventID {
		return ErrInvalidEventID
	}
	wantPayloadHash := sha256.Sum256(entry.Payload)
	if wantPayloadHash != entry.PayloadHash {
		return ErrInvalidEventID
	}
	if !ed25519.Verify(entry.SignerPublicKey[:], SignedBytes(entry), entry.Signature[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyChain replays an ordered, single-subject run of entries (as a
// witness would after fetching them via the export RPC, or as
// PostgresRepository.Append does defensively before its own insert) and
// checks: every entry's own self-consistency (VerifyEntry), strict
// sequence continuity starting at 1, and hash-chain continuity
// (entries[i].PrevEventHash == entries[i-1].EventID). It does not check
// chain anchors -- see ChainAnchorChecker and VerifyChainAnchors, kept
// separate because anchor verification needs chain RPC access this
// package has no dependency on, while hash-chain/signature verification
// needs none.
func VerifyChain(entries []Entry) error {
	var prev [32]byte
	for i, entry := range entries {
		if err := VerifyEntry(entry); err != nil {
			return err
		}
		wantSequence := uint64(i + 1)
		if entry.Sequence != wantSequence {
			return errors.New("eventlog: sequence is not strictly increasing from 1")
		}
		if entry.PrevEventHash != prev {
			return ErrHashChainBreak
		}
		prev = entry.EventID
	}
	return nil
}

// ChainAnchorChecker is a witness's (or the Control Plane's own) read
// access to finalized chain state -- exactly enough to answer ADR-039
// §5's question: does this claimed lease_id/block_hash correspond to a
// real finalized fact, for the right provider/consumer? Implemented in
// production by a thin adapter over blockchainbridge.RPCClient; a package
// here takes only the interface, never the concrete chain client, so this
// package stays free of any chain-RPC dependency.
type ChainAnchorChecker interface {
	// LeaseExistsAtBlock reports whether lease_id is present in finalized
	// storage at exactly block_hash, per ADR-039 §5.
	LeaseExistsAtBlock(leaseID uint64, blockHash [32]byte) (bool, error)
}

// VerifyChainAnchors checks every anchored entry in a verified chain (call
// after VerifyChain, not instead of it) against real finalized chain
// state via checker. An entry with a nil ChainAnchor (ADR-039 §5's
// honestly-named pre-lease gap) is skipped, not rejected -- absence of an
// anchor is expected and valid for a subject's very first event.
func VerifyChainAnchors(entries []Entry, checker ChainAnchorChecker) error {
	for _, entry := range entries {
		if entry.ChainAnchor == nil {
			continue
		}
		found, err := checker.LeaseExistsAtBlock(entry.ChainAnchor.LeaseID, entry.ChainAnchor.BlockHash)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("eventlog: chain_anchor does not correspond to a real finalized fact")
		}
	}
	return nil
}
