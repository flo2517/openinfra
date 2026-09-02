package eventlog

import (
	"crypto/ed25519"
	"testing"
)

// fakeSigner is a minimal, in-memory Signer for tests -- exactly the
// shape blockchainbridge.Registrar's real Sign/PublicKey methods have,
// without needing a chain client to construct one.
type fakeSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newFakeSigner(t *testing.T) fakeSigner {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return fakeSigner{public: public, private: private}
}

func (f fakeSigner) PublicKey() [32]byte {
	var key [32]byte
	copy(key[:], f.public)
	return key
}

func (f fakeSigner) Sign(payload []byte) [64]byte {
	var signature [64]byte
	copy(signature[:], ed25519.Sign(f.private, payload))
	return signature
}

// TestEventIDIsDeterministic pins ADR-039 §1's core claim: two
// independently-constructed replicas that receive the same event content
// compute the same event_id without coordinating -- i.e. EventID is a
// pure function of its documented inputs, nothing else.
func TestEventIDIsDeterministic(t *testing.T) {
	payloadHash := [32]byte{1, 2, 3}
	prev := [32]byte{4, 5, 6}
	a := EventID(SubjectWorkloadLifecycle, []byte("workload-1"), 3, prev, "RUNNING", payloadHash)
	b := EventID(SubjectWorkloadLifecycle, []byte("workload-1"), 3, prev, "RUNNING", payloadHash)
	if a != b {
		t.Fatalf("expected identical event_id for identical inputs, got %x vs %x", a, b)
	}
	c := EventID(SubjectWorkloadLifecycle, []byte("workload-1"), 4, prev, "RUNNING", payloadHash)
	if a == c {
		t.Fatalf("expected a different sequence to change event_id")
	}
}

// TestSignAndVerifyEntryRoundTrips exercises Sign/VerifyEntry together:
// a freshly signed Entry (with and without a chain anchor) must verify.
func TestSignAndVerifyEntryRoundTrips(t *testing.T) {
	signer := newFakeSigner(t)
	entry := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "SCHEDULING", nil, nil)
	if err := VerifyEntry(entry); err != nil {
		t.Fatalf("expected a freshly signed entry to verify, got %v", err)
	}

	anchored := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 2, entry.EventID, "LEASED", []byte("payload"), &ChainAnchor{LeaseID: 42, BlockHash: [32]byte{9, 9, 9}})
	if err := VerifyEntry(anchored); err != nil {
		t.Fatalf("expected an anchored, signed entry to verify, got %v", err)
	}
}

// TestSignatureCoversChainAnchor is the regression test for the judgment
// call SignedBytes' doc comment names explicitly: swapping a validly
// signed event's chain_anchor to a different (but well-formed) anchor
// must invalidate the signature, not silently succeed. If this test
// fails, ADR-039 §5's "anchored to finalized chain facts" guarantee is
// not actually enforced by the signature.
func TestSignatureCoversChainAnchor(t *testing.T) {
	signer := newFakeSigner(t)
	entry := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "LEASED", []byte("payload"), &ChainAnchor{LeaseID: 1, BlockHash: [32]byte{1}})
	tampered := entry
	tampered.ChainAnchor = &ChainAnchor{LeaseID: 999, BlockHash: [32]byte{2}}
	if err := VerifyEntry(tampered); err == nil {
		t.Fatal("expected swapping the chain_anchor to invalidate the signature")
	}
}

// TestSignatureCoversSigner is the identical regression test for
// signer_public_key: a party cannot take a validly signed event and
// relabel it as signed by a different key.
func TestSignatureCoversSigner(t *testing.T) {
	signerA := newFakeSigner(t)
	signerB := newFakeSigner(t)
	entry := Sign(signerA, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "SCHEDULING", nil, nil)
	tampered := entry
	tampered.SignerPublicKey = signerB.PublicKey()
	if err := VerifyEntry(tampered); err == nil {
		t.Fatal("expected relabeling signer_public_key to invalidate the signature")
	}
}

// TestVerifyEntryRejectsPayloadTamper: changing Payload without
// re-signing must be detected, since payload_hash (covered by both
// event_id and the signature) would no longer match.
func TestVerifyEntryRejectsPayloadTamper(t *testing.T) {
	signer := newFakeSigner(t)
	entry := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "RUNNING", []byte("container-abc"), nil)
	entry.Payload = []byte("container-evil")
	if err := VerifyEntry(entry); err == nil {
		t.Fatal("expected a tampered payload (stale payload_hash) to fail verification")
	}
}

// TestVerifyChainAcceptsAValidRun builds a 3-event, single-subject chain
// exactly the way workloadapi.PostgresRepository's dual-write would
// (SCHEDULING -> LEASE_PENDING -> LEASED, the last carrying a chain
// anchor) and confirms a witness's VerifyChain accepts it whole.
func TestVerifyChainAcceptsAValidRun(t *testing.T) {
	signer := newFakeSigner(t)
	e1 := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "SCHEDULING", nil, nil)
	e2 := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 2, e1.EventID, "LEASE_PENDING", []byte("provider-1"), nil)
	e3 := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 3, e2.EventID, "LEASED", nil, &ChainAnchor{LeaseID: 7, BlockHash: [32]byte{7, 7, 7}})
	if err := VerifyChain([]Entry{e1, e2, e3}); err != nil {
		t.Fatalf("expected a well-formed chain to verify, got %v", err)
	}
}

// TestVerifyChainDetectsHashChainBreak: a subject's history that skips or
// substitutes an event (its own prev_event_hash chain broken) must be
// rejected, not silently accepted as "close enough".
func TestVerifyChainDetectsHashChainBreak(t *testing.T) {
	signer := newFakeSigner(t)
	e1 := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "SCHEDULING", nil, nil)
	// e2 claims to follow e1 but its prev_event_hash points at the wrong
	// value (as if an event were dropped/reordered).
	e2 := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 2, [32]byte{1, 1, 1}, "LEASE_PENDING", nil, nil)
	err := VerifyChain([]Entry{e1, e2})
	if err == nil {
		t.Fatal("expected a hash-chain break to be detected")
	}
}

// TestVerifyChainAnchorsRejectsUnfinalizedAnchor: an event claiming a
// chain_anchor that the chain does not actually confirm must be rejected
// by a witness checking against real chain state (ADR-039 §5).
func TestVerifyChainAnchorsRejectsUnfinalizedAnchor(t *testing.T) {
	signer := newFakeSigner(t)
	entry := Sign(signer, SubjectWorkloadLifecycle, []byte("workload-1"), 1, ZeroHash, "LEASED", nil, &ChainAnchor{LeaseID: 5, BlockHash: [32]byte{5}})
	checker := fakeChainAnchorChecker{found: false}
	if err := VerifyChainAnchors([]Entry{entry}, checker); err == nil {
		t.Fatal("expected an anchor the chain does not confirm to be rejected")
	}
	checker.found = true
	if err := VerifyChainAnchors([]Entry{entry}, checker); err != nil {
		t.Fatalf("expected a confirmed anchor to verify, got %v", err)
	}
}

type fakeChainAnchorChecker struct{ found bool }

func (f fakeChainAnchorChecker) LeaseExistsAtBlock(uint64, [32]byte) (bool, error) {
	return f.found, nil
}
