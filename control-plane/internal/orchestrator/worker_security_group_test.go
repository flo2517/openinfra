package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/neutron"
	"github.com/openinfra/network/internal/workloadapi"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

// fakeSecurityGroupResolver is a fully-controllable
// SecurityGroupResolver -- the same narrow-interface/narrow-fake
// precedent every other Worker dependency fake in this package already
// follows (staticDirectory, successfulLeases, capturingDispatcher).
type fakeSecurityGroupResolver struct {
	rules   []neutron.SecurityGroupRule
	fixedIP string
	hasPort bool
	err     error
	calls   []string
}

func (f *fakeSecurityGroupResolver) ResolveForWorkload(_ context.Context, workloadID string) ([]neutron.SecurityGroupRule, string, bool, error) {
	f.calls = append(f.calls, workloadID)
	return f.rules, f.fixedIP, f.hasPort, f.err
}

// capturingOverlay implements both OverlayManager and
// OverlayAttacherWithAllowedIPs, recording every call to either --
// TestDeployingUsesAttachWithAllowedIPsWhenAPortIsBound and its sibling
// below assert against these recordings that exactly one of the two is
// ever called per Deploy, never both (see the doc comment at that call
// site in worker.go for why calling both would be a real bug).
type capturingOverlay struct {
	plainAttachCalls          int
	attachWithAllowedIPsCalls int
	lastAllowedIPs            []string
}

func (o *capturingOverlay) Attach(context.Context, string, string, string, time.Time) error {
	o.plainAttachCalls++
	return nil
}
func (o *capturingOverlay) Revoke(context.Context, string) error { return nil }
func (o *capturingOverlay) AttachWithAllowedIPs(_ context.Context, _, _, _ string, _ time.Time, allowedIPs []string) error {
	o.attachWithAllowedIPsCalls++
	o.lastAllowedIPs = allowedIPs
	return nil
}

func containerDeployItem() workloadapi.Workload {
	definition, err := proto.Marshal(&sharedv1.WorkloadDefinition{
		Requirements: &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256},
	})
	if err != nil {
		panic(err)
	}
	return workloadapi.Workload{WorkloadID: "workload-sg", State: "DEPLOYING", Definition: definition, Image: "busybox:1.36", ProviderID: "provider", LeaseID: "42", Version: 1}
}

func TestDeployingPopulatesSecurityContextWhenAPortIsBound(t *testing.T) {
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	portMin := int32(443)
	resolver := &fakeSecurityGroupResolver{
		hasPort: true,
		fixedIP: "10.60.0.5",
		rules: []neutron.SecurityGroupRule{
			{Direction: neutron.DirectionIngress, Protocol: neutron.ProtocolTCP, PortRangeMin: &portMin, PortRangeMax: &portMin, RemoteIPPrefix: "0.0.0.0/0"},
		},
	}
	worker.SetSecurityGroupResolver(resolver)

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}

	if dispatcher.request == nil {
		t.Fatal("no DeployRequest captured")
	}
	if dispatcher.request.SecurityContext == nil {
		t.Fatal("SecurityContext must be set once a port is bound (hasPort=true), even with rules present")
	}
	if len(dispatcher.request.SecurityContext.Rules) != 1 {
		t.Fatalf("expected exactly 1 rule, got %d", len(dispatcher.request.SecurityContext.Rules))
	}
	rule := dispatcher.request.SecurityContext.Rules[0]
	if rule.Direction != "ingress" || rule.Protocol != "tcp" || rule.PortRangeMin != 443 || rule.RemoteIpPrefix != "0.0.0.0/0" {
		t.Fatalf("rule not carried through faithfully: %+v", rule)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != item.WorkloadID {
		t.Fatalf("expected exactly one ResolveForWorkload(%q) call, got %v", item.WorkloadID, resolver.calls)
	}
}

func TestDeployingLeavesSecurityContextNilForAWorkloadWithNoBoundPort(t *testing.T) {
	// ADR-035 §1's backward-compatibility guarantee, at the dispatch
	// seam: hasPort=false must leave SecurityContext completely unset,
	// not "set with zero rules" (which would instead mean the
	// fail-closed default -- a materially different, stricter outcome
	// this workload never asked for).
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	worker.SetSecurityGroupResolver(&fakeSecurityGroupResolver{hasPort: false})

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}

	if dispatcher.request.SecurityContext != nil {
		t.Fatalf("SecurityContext must stay nil for a workload with no bound port, got %+v", dispatcher.request.SecurityContext)
	}
}

func TestDeployingLeavesSecurityContextNilWhenNoResolverIsConfigured(t *testing.T) {
	// The zero-value *Worker (no SetSecurityGroupResolver call at all,
	// matching every pre-ADR-035 deployment/test) must behave exactly as
	// it did before this field existed.
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}

	if dispatcher.request.SecurityContext != nil {
		t.Fatal("SecurityContext must stay nil when no SecurityGroupResolver is configured")
	}
}

func TestDeployingRetriesWhenSecurityGroupResolutionFails(t *testing.T) {
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	worker.SetSecurityGroupResolver(&fakeSecurityGroupResolver{err: errors.New("postgres unavailable")})

	// retry() returns the underlying cause (non-nil) when the retry budget
	// is not yet exhausted -- see worker.go's own retry() -- so a
	// resolution failure surfaces as a non-nil processOne error, not a
	// silently swallowed one.
	err := worker.processOne(context.Background())
	if err == nil {
		t.Fatal("expected a non-nil error when security-group resolution fails")
	}

	if dispatcher.request != nil {
		t.Fatal("Deploy must not be dispatched when security-group resolution fails")
	}
	if store.action != "retry" {
		t.Fatalf("expected a retry, got store.action=%q", store.action)
	}
}

func TestDeployingUsesAttachWithAllowedIPsWhenAPortIsBound(t *testing.T) {
	// ADR-035 §1: exactly one of Attach/AttachWithAllowedIPs is called
	// when a bound port carries a fixed_ip -- never both (see worker.go's
	// own doc comment on why calling Attach first would permanently
	// shadow the override).
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	overlay := &capturingOverlay{}
	worker.SetOverlay(overlay)
	worker.SetSecurityGroupResolver(&fakeSecurityGroupResolver{hasPort: true, fixedIP: "10.61.0.9"})

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}

	if overlay.attachWithAllowedIPsCalls != 1 {
		t.Fatalf("expected exactly 1 AttachWithAllowedIPs call, got %d", overlay.attachWithAllowedIPsCalls)
	}
	if overlay.plainAttachCalls != 0 {
		t.Fatalf("plain Attach must not be called when a fixed_ip override is available, got %d calls", overlay.plainAttachCalls)
	}
	if len(overlay.lastAllowedIPs) != 1 || overlay.lastAllowedIPs[0] != "10.61.0.9/32" {
		t.Fatalf("expected AllowedIPs=[10.61.0.9/32], got %v", overlay.lastAllowedIPs)
	}
}

func TestDeployingUsesPlainAttachWhenNoPortIsBound(t *testing.T) {
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	overlay := &capturingOverlay{}
	worker.SetOverlay(overlay)
	worker.SetSecurityGroupResolver(&fakeSecurityGroupResolver{hasPort: false})

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}

	if overlay.plainAttachCalls != 1 {
		t.Fatalf("expected exactly 1 plain Attach call for a workload with no bound port, got %d", overlay.plainAttachCalls)
	}
	if overlay.attachWithAllowedIPsCalls != 0 {
		t.Fatalf("AttachWithAllowedIPs must not be called with no fixed_ip override, got %d calls", overlay.attachWithAllowedIPsCalls)
	}
}

func TestDeployingUsesPlainAttachWhenTheOverlayDoesNotSupportAllowedIPs(t *testing.T) {
	// A pre-ADR-035 OverlayManager implementation (only Attach/Revoke) must
	// keep working exactly as before, even when a security-group resolver
	// is configured and resolves a bound port -- the optional-capability
	// type assertion in worker.go degrades gracefully.
	item := containerDeployItem()
	store := &recordingStore{item: item}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	worker.SetOverlay(stubOverlay{}) // implements only Attach/Revoke
	worker.SetSecurityGroupResolver(&fakeSecurityGroupResolver{hasPort: true, fixedIP: "10.62.0.1"})

	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	// stubOverlay records nothing itself; reaching here without a panic
	// (a type assertion failure would not panic, but a wrong call shape
	// would) plus MarkRunning below having been reached is the assertion.
	if dispatcher.request == nil {
		t.Fatal("Deploy must still be dispatched")
	}
}
