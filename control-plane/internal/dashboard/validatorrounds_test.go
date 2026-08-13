package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openinfra/network/internal/blockchainbridge"
)

// activeSetForTest builds n distinct accounts, none of which is the
// provider under test (accounts start at 1; the provider is account 0).
func activeSetForTest(n int) [][32]byte {
	accounts := make([][32]byte, 0, n)
	for i := 1; i <= n; i++ {
		var account [32]byte
		account[0] = byte(i)
		accounts = append(accounts, account)
	}
	return accounts
}

func submissionFrom(validator [32]byte, scoreBps uint16) blockchainbridge.Submission {
	return blockchainbridge.Submission{Validator: validator, ScoreBps: scoreBps, SampleCount: 1}
}

// TestBuildOpenRoundSeparatesAnsweredFromAwaitedCommitteeMembers is the
// core of the "challenge queue" view: the committee members who have not
// answered are exactly the queue. The committee is computed with the same
// pure function the endpoint uses rather than hardcoded, because this test
// is about the join between assignment and evidence, not about selection
// (Committee's own byte-for-byte agreement with the pallet is pinned in
// blockchainbridge/committee_test.go).
func TestBuildOpenRoundSeparatesAnsweredFromAwaitedCommitteeMembers(t *testing.T) {
	var provider [32]byte
	active := activeSetForTest(8)
	const round = uint64(4)
	committee := blockchainbridge.Committee(provider, round, active, blockchainbridge.NetworkValidatorTargetCommitteeSize)
	if len(committee) != int(blockchainbridge.NetworkValidatorTargetCommitteeSize) {
		t.Fatalf("expected a full committee from 8 candidates, got %d", len(committee))
	}

	submissions := []blockchainbridge.Submission{
		submissionFrom(committee[0], 9_000),
		submissionFrom(committee[2], 8_000),
	}
	got := buildOpenRound(provider, round, submissions, active)

	if len(got.Committee) != len(committee) {
		t.Fatalf("committee = %d entries, want %d", len(got.Committee), len(committee))
	}
	if len(got.Submissions) != 2 {
		t.Fatalf("submissions = %d, want 2", len(got.Submissions))
	}
	wantAwaiting := []string{accountHex(committee[1]), accountHex(committee[3]), accountHex(committee[4])}
	if len(got.AwaitingResponse) != len(wantAwaiting) {
		t.Fatalf("awaiting_response = %v, want %v", got.AwaitingResponse, wantAwaiting)
	}
	for i, want := range wantAwaiting {
		if got.AwaitingResponse[i] != want {
			t.Fatalf("awaiting_response[%d] = %s, want %s", i, got.AwaitingResponse[i], want)
		}
	}
	if got.CommitteeStale {
		t.Fatal("every submitter is in the committee, so the round must not be flagged stale")
	}
}

// TestBuildOpenRoundReportsQuorumAgainstMinQuorumNotCommitteeSize pins the
// distinction the JSON has to carry: close_round needs MinQuorum (3)
// answers, not a full committee (5). Reporting "not enough yet" at 3
// submissions would tell an operator to keep waiting on a round that can
// already close.
func TestBuildOpenRoundReportsQuorumAgainstMinQuorumNotCommitteeSize(t *testing.T) {
	var provider [32]byte
	active := activeSetForTest(8)
	const round = uint64(11)
	committee := blockchainbridge.Committee(provider, round, active, blockchainbridge.NetworkValidatorTargetCommitteeSize)

	below := buildOpenRound(provider, round, []blockchainbridge.Submission{
		submissionFrom(committee[0], 1),
		submissionFrom(committee[1], 2),
	}, active)
	if below.QuorumReached {
		t.Fatal("2 submissions must not reach a quorum of 3")
	}
	if below.QuorumRequired != blockchainbridge.NetworkValidatorMinQuorum {
		t.Fatalf("quorum_required = %d, want %d", below.QuorumRequired, blockchainbridge.NetworkValidatorMinQuorum)
	}

	atQuorum := buildOpenRound(provider, round, []blockchainbridge.Submission{
		submissionFrom(committee[0], 1),
		submissionFrom(committee[1], 2),
		submissionFrom(committee[2], 3),
	}, active)
	if !atQuorum.QuorumReached {
		t.Fatal("exactly MinQuorum submissions must count as reaching quorum, as close_round's >= check does")
	}
	if len(atQuorum.AwaitingResponse) != 2 {
		t.Fatalf("awaiting_response = %d, want 2 -- a reached quorum does not empty the queue", len(atQuorum.AwaitingResponse))
	}
}

// TestBuildOpenRoundFlagsAStaleCommitteeWhenASubmitterIsNoLongerAssigned
// covers the one case where the recomputed committee genuinely disagrees
// with the chain: the active set changed after a submission landed. The
// chain enforced assignment against the set as it was, so the response
// must say so rather than presenting a wrong committee as fact.
func TestBuildOpenRoundFlagsAStaleCommitteeWhenASubmitterIsNoLongerAssigned(t *testing.T) {
	var provider, departed [32]byte
	departed[0] = 0xFE
	active := activeSetForTest(8)
	const round = uint64(2)

	got := buildOpenRound(provider, round, []blockchainbridge.Submission{submissionFrom(departed, 5_000)}, active)
	if !got.CommitteeStale {
		t.Fatal("a submission from an account outside the recomputed committee must set committee_stale")
	}
	if len(got.Submissions) != 1 {
		t.Fatal("a stale committee must not drop the submission that revealed it")
	}
}

// TestBuildOpenRoundStillReportsSubmissionsWithoutAnActiveSet covers the
// degraded path: LatestActiveNetworkValidators failed, so no committee can
// be computed, but the evidence read succeeded and is still worth serving.
func TestBuildOpenRoundStillReportsSubmissionsWithoutAnActiveSet(t *testing.T) {
	var provider, validator [32]byte
	validator[0] = 3

	got := buildOpenRound(provider, 1, []blockchainbridge.Submission{submissionFrom(validator, 7_000)}, nil)
	if len(got.Submissions) != 1 {
		t.Fatalf("submissions = %d, want 1", len(got.Submissions))
	}
	if len(got.Committee) != 0 || len(got.AwaitingResponse) != 0 {
		t.Fatal("without an active set there is nothing to compute a committee or a queue from")
	}
	if got.CommitteeStale {
		t.Fatal("an unavailable active set is not evidence that the committee is stale")
	}
	if got.QuorumRequired != blockchainbridge.NetworkValidatorMinQuorum {
		t.Fatal("quorum is a runtime constant and stays reportable without the active set")
	}
}

// TestBuildOpenRoundEncodesAccountsInFullAndHashesAsHex pins the wire
// shape: full 32-byte accounts (unlike /api/v1/overview's abbreviation --
// see accountHex's comment) and a 0x-prefixed payload hash.
func TestBuildOpenRoundEncodesAccountsInFullAndHashesAsHex(t *testing.T) {
	var provider, validator, payload [32]byte
	validator[0], validator[31] = 0xA1, 0xB2
	payload[0] = 0xC3

	got := buildOpenRound(provider, 1, []blockchainbridge.Submission{{
		Validator: validator, ScoreBps: 1, SampleCount: 1, PayloadHash: payload,
	}}, nil)

	submission := got.Submissions[0]
	if !strings.HasPrefix(submission.Validator, "0x") || len(submission.Validator) != 66 {
		t.Fatalf("validator = %q, want a 0x-prefixed 32-byte hex account", submission.Validator)
	}
	if !strings.HasSuffix(submission.Validator, "b2") {
		t.Fatalf("validator = %q, want the account rendered in full (last byte present)", submission.Validator)
	}
	if !strings.HasPrefix(submission.PayloadHash, "0xc3") || len(submission.PayloadHash) != 66 {
		t.Fatalf("payload_hash = %q, want a 0x-prefixed 32-byte hex hash", submission.PayloadHash)
	}
}

// TestOpenRoundIsInformativeDropsRoundsNobodyWasAssignedTo pins the
// filter that keeps the response readable: against a chain with no active
// validators, every round of every dimension is technically open, which
// rendered as 20 identical empty rows before this existed.
func TestOpenRoundIsInformativeDropsRoundsNobodyWasAssignedTo(t *testing.T) {
	var provider, validator [32]byte
	validator[0] = 4
	active := activeSetForTest(8)

	if openRoundIsInformative(buildOpenRound(provider, 1, nil, nil)) {
		t.Fatal("a round with no submissions and no committee has nothing to report and must be dropped")
	}
	if !openRoundIsInformative(buildOpenRound(provider, 1, nil, active)) {
		t.Fatal("a round whose committee owes an answer is the queue itself and must be kept")
	}
	if !openRoundIsInformative(buildOpenRound(provider, 1, []blockchainbridge.Submission{submissionFrom(validator, 1)}, nil)) {
		t.Fatal("a round with a submission must be kept even when the committee cannot be computed")
	}
}

// The handler tests below reuse newValidatorScoresTestServer: the two
// endpoints have identical dependencies (Postgres for the provider lookup,
// a live chain for every read) and it is already gated on both.

func TestValidatorRoundsReturnsNotFoundForAnUnknownProvider(t *testing.T) {
	_, server, _ := newValidatorScoresTestServer(t)
	recorder := doJSON(t, server.Handler(), http.MethodGet, "/api/v1/validator/rounds/never-registered", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestValidatorRoundsRejectsAnOversizedProviderID(t *testing.T) {
	_, server, _ := newValidatorScoresTestServer(t)
	recorder := doJSON(t, server.Handler(), http.MethodGet, "/api/v1/validator/rounds/"+strings.Repeat("a", 200), nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

// TestValidatorHealthReturnsTheActiveSetAgainstALiveChain proves the read
// path end to end. It asserts the shape and the runtime constants rather
// than a validator count: the dev chain may legitimately have an empty
// active set, and a test that demanded registered validators would fail
// for an environment reason rather than a code one.
func TestValidatorHealthReturnsTheActiveSetAgainstALiveChain(t *testing.T) {
	_, server, _ := newValidatorScoresTestServer(t)
	recorder := doJSON(t, server.Handler(), http.MethodGet, "/api/v1/validator/health", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response ValidatorSet
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.MinQuorum != blockchainbridge.NetworkValidatorMinQuorum {
		t.Fatalf("min_quorum = %d, want %d", response.MinQuorum, blockchainbridge.NetworkValidatorMinQuorum)
	}
	if response.Committee != blockchainbridge.NetworkValidatorTargetCommitteeSize {
		t.Fatalf("target_committee_size = %d, want %d", response.Committee, blockchainbridge.NetworkValidatorTargetCommitteeSize)
	}
	if response.ActiveCount != len(response.Validators) && !response.Truncated {
		t.Fatalf("active_count = %d but %d validators returned without truncation", response.ActiveCount, len(response.Validators))
	}
	for _, validator := range response.Validators {
		if !strings.HasPrefix(validator.Validator, "0x") || len(validator.Validator) != 66 {
			t.Fatalf("validator = %q, want a 0x-prefixed 32-byte hex account", validator.Validator)
		}
	}
}
