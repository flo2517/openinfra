package nova_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/openstackapi/glance"
	"github.com/openinfra/network/internal/projects"
)

// TestListResourceProvidersReflectsSchedulerState is ADR-031 §4's "a
// Placement-shaped allocation/resource-provider read API reflecting
// scheduler state" acceptance criterion: the same provider the
// fakeDirectory (standing in for agentmanager.Directory, exactly as the
// scheduler itself reads it) reports is what this endpoint returns.
func TestListResourceProvidersReflectsSchedulerState(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-list", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/resource_providers", actor.token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var decoded struct {
		ResourceProviders []struct {
			UUID string `json:"uuid"`
		} `json:"resource_providers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.ResourceProviders) != 1 || decoded.ResourceProviders[0].UUID != testProvider().ProviderID {
		t.Fatalf("resource_providers = %+v, want exactly [%q]", decoded.ResourceProviders, testProvider().ProviderID)
	}
}

func TestListResourceProvidersRejectsWithoutAToken(t *testing.T) {
	_, s := newTestServer(t)
	recorder := doRequest(s.handler, http.MethodGet, "/resource_providers", "", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

// TestResourceProviderInventoriesReportsDeclaredCapacity proves the
// inventories endpoint reflects the provider's declared total capacity
// (testProvider's Capabilities), converted into Placement's own
// resource-class vocabulary.
func TestResourceProviderInventoriesReportsDeclaredCapacity(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-inv", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/resource_providers/"+testProvider().ProviderID+"/inventories", actor.token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var decoded struct {
		Inventories map[string]struct {
			Total int64 `json:"total"`
		} `json:"inventories"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Inventories["VCPU"].Total != 8 {
		t.Fatalf("VCPU total = %d, want 8", decoded.Inventories["VCPU"].Total)
	}
	if decoded.Inventories["MEMORY_MB"].Total != 16384 {
		t.Fatalf("MEMORY_MB total = %d, want 16384", decoded.Inventories["MEMORY_MB"].Total)
	}
	if decoded.Inventories["DISK_GB"].Total != 200 {
		t.Fatalf("DISK_GB total = %d, want 200", decoded.Inventories["DISK_GB"].Total)
	}
}

func TestResourceProviderInventoriesReturns404ForAnUnknownProvider(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-inv-404", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/resource_providers/"+uuid.NewString()+"/inventories", actor.token, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

// TestResourceProviderUsagesReflectsAnOpenWorkload proves usages tracks
// real committed reservations (workloadapi.ProviderReservedTotals),
// before and after a server is created against that provider -- the same
// aggregate AssignLease's own atomic capacity check computes, exercised
// end to end through a real create + real orchestrator scheduling pass.
func TestResourceProviderUsagesReflectsAnOpenWorkload(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-usage", projects.RoleMember)

	zeroRecorder := doRequest(s.handler, http.MethodGet, "/resource_providers/"+testProvider().ProviderID+"/usages", actor.token, nil)
	if zeroRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", zeroRecorder.Code, http.StatusOK)
	}
	var zero struct {
		Usages map[string]int64 `json:"usages"`
	}
	if err := json.Unmarshal(zeroRecorder.Body.Bytes(), &zero); err != nil {
		t.Fatal(err)
	}
	if zero.Usages["VCPU"] != 0 {
		t.Fatalf("VCPU usage before any workload = %d, want 0", zero.Usages["VCPU"])
	}

	imageID := registerGlanceImage(t, ctx, s, actor.projectID, testImageSourceRef, testImageDigest, glance.VisibilityPrivate)
	worker, _ := newWorker(s)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	go worker.Run(workerCtx)
	defer cancelWorker()

	createRecorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("usage-probe", imageID, "2", nil)) // oi.medium: 2 vcpus
	if createRecorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d; body=%s", createRecorder.Code, http.StatusAccepted, createRecorder.Body.String())
	}
	var created struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	waitForWorkloadState(t, ctx, s, actor.projectID, created.Server.ID, "RUNNING", 20*time.Second)

	usageRecorder := doRequest(s.handler, http.MethodGet, "/resource_providers/"+testProvider().ProviderID+"/usages", actor.token, nil)
	var usage struct {
		Usages map[string]int64 `json:"usages"`
	}
	if err := json.Unmarshal(usageRecorder.Body.Bytes(), &usage); err != nil {
		t.Fatal(err)
	}
	if usage.Usages["VCPU"] != 2 {
		t.Fatalf("VCPU usage after a RUNNING oi.medium workload = %d, want 2", usage.Usages["VCPU"])
	}
}

// TestAllocationsForConsumerReflectsAWorkloadAndDeniesOtherProjects
// covers /allocations/{consumer_uuid}'s own cross-project boundary check
// (sourced from the resource, since Placement's real URL shape has no
// {project_id} segment -- see allocationsForConsumer's doc comment).
func TestAllocationsForConsumerReflectsAWorkloadAndDeniesOtherProjects(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-alloc", projects.RoleMember)
	other := newProjectActor(t, ctx, s, "placement-alloc-other", projects.RoleMember)

	imageID := registerGlanceImage(t, ctx, s, actor.projectID, testImageSourceRef, testImageDigest, glance.VisibilityPrivate)
	worker, _ := newWorker(s)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	go worker.Run(workerCtx)
	defer cancelWorker()

	createRecorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("alloc-probe", imageID, "1", nil))
	if createRecorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d; body=%s", createRecorder.Code, http.StatusAccepted, createRecorder.Body.String())
	}
	var created struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	waitForWorkloadState(t, ctx, s, actor.projectID, created.Server.ID, "RUNNING", 20*time.Second)

	ownRecorder := doRequest(s.handler, http.MethodGet, "/allocations/"+created.Server.ID, actor.token, nil)
	if ownRecorder.Code != http.StatusOK {
		t.Fatalf("own-project status = %d, want %d; body=%s", ownRecorder.Code, http.StatusOK, ownRecorder.Body.String())
	}
	var allocations struct {
		Allocations map[string]any `json:"allocations"`
	}
	if err := json.Unmarshal(ownRecorder.Body.Bytes(), &allocations); err != nil {
		t.Fatal(err)
	}
	if _, ok := allocations.Allocations[testProvider().ProviderID]; !ok {
		t.Fatalf("allocations = %+v, want an entry for provider %q", allocations.Allocations, testProvider().ProviderID)
	}

	otherRecorder := doRequest(s.handler, http.MethodGet, "/allocations/"+created.Server.ID, other.token, nil)
	if otherRecorder.Code != http.StatusForbidden {
		t.Fatalf("other-project status = %d, want %d; body=%s", otherRecorder.Code, http.StatusForbidden, otherRecorder.Body.String())
	}
}

// TestAllocationsForConsumerReturns200WithEmptyAllocationsForAnUnknownConsumer
// matches real Placement's own behavior: an unknown consumer_uuid is a
// successful, empty answer, not a 404.
func TestAllocationsForConsumerReturns200WithEmptyAllocationsForAnUnknownConsumer(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "placement-alloc-unknown", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/allocations/"+uuid.NewString(), actor.token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var decoded struct {
		Allocations map[string]any `json:"allocations"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Allocations) != 0 {
		t.Fatalf("allocations = %+v, want empty", decoded.Allocations)
	}
}
