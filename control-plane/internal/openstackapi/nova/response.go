package nova

import (
	"encoding/json"
	"net/http"
)

type linkBody struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// selfLinks builds the minimal Nova "links" array every server/flavor
// representation carries: a single "self" link, relative to this
// package's own /v2.1/{project_id}/... routes. Real Nova also includes a
// "bookmark" link (a version-independent alternate); omitted here since
// nothing in this slice needs it, and inventing a second URL scheme with
// no consumer would be speculative.
func selfLinks(collection, id, projectID string) []linkBody {
	return []linkBody{{Rel: "self", Href: "/v2.1/" + projectID + "/" + collection + "/" + id}}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// novaStatus maps workloadapi's own workload-state vocabulary onto Nova's
// server-status vocabulary (ADR-031 §4's compute-mapping table).
// Approximate by necessity: Nova's status enum describes a VM's
// lifecycle, this system's states describe a container's
// scheduling/lease/deploy pipeline, and the two do not line up
// one-to-one everywhere -- most notably STOPPING and COMPLETED, both
// folded into Nova's SHUTOFF, since a real Nova deployment distinguishes
// a task in progress from a terminal shutdown with a separate task_state
// field this system has no equivalent signal for. Documented once, here,
// rather than left as an implicit assumption a caller might read too much
// into.
func novaStatus(state string) string {
	switch state {
	case "REQUESTED", "SCHEDULING", "LEASE_PENDING", "LEASED", "DEPLOYING":
		return "BUILD"
	case "RUNNING":
		return "ACTIVE"
	case "STOPPING", "STOPPED", "COMPLETED":
		return "SHUTOFF"
	case "FAILED":
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
