package nova

import "net/http"

// Flavor is ADR-031 §4's static flavor catalog entry: a fixed CPU/RAM/
// storage tuple mapped directly onto the existing
// sharedv1.ResourceRequirements shape workloadapi.SubmitWorkload already
// validates and reserves capacity for -- no new resource model, just a
// named preset over the one that already exists.
type Flavor struct {
	ID     string
	Name   string
	VCPUs  int32
	RAMMB  int64
	DiskGB int64
}

// DefaultFlavors is the catalog New falls back to when the caller passes
// nil -- four sizes, deliberately legible round numbers, not derived from
// any measurement (matching scheduler.DefaultProfileWeights' own "chosen
// to be legible and easy to argue with" precedent). A real deployment can
// pass its own list to New instead, satisfying the task's "fixed/
// configurable catalog" requirement: fixed by default, configurable by
// construction.
var DefaultFlavors = []Flavor{
	{ID: "1", Name: "oi.small", VCPUs: 1, RAMMB: 1024, DiskGB: 10},
	{ID: "2", Name: "oi.medium", VCPUs: 2, RAMMB: 4096, DiskGB: 20},
	{ID: "3", Name: "oi.large", VCPUs: 4, RAMMB: 8192, DiskGB: 40},
	{ID: "4", Name: "oi.xlarge", VCPUs: 8, RAMMB: 16384, DiskGB: 80},
}

func (s *Server) flavorByID(id string) (Flavor, bool) {
	for _, f := range s.flavors {
		if f.ID == id {
			return f, true
		}
	}
	return Flavor{}, false
}

type flavorBody struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	VCPUs  int32      `json:"vcpus"`
	RAMMB  int64      `json:"ram"`
	DiskGB int64      `json:"disk"`
	Links  []linkBody `json:"links"`
}

func flavorDetail(f Flavor, projectID string) flavorBody {
	return flavorBody{ID: f.ID, Name: f.Name, VCPUs: f.VCPUs, RAMMB: f.RAMMB, DiskGB: f.DiskGB, Links: selfLinks("flavors", f.ID, projectID)}
}

// listFlavors is GET /v2.1/{project_id}/flavors: real Nova's "brief"
// listing (id, name, links only -- see listFlavorsDetail for the full
// representation, matching Nova's own two-endpoint convention).
func (s *Server) listFlavors(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	flavors := make([]map[string]any, 0, len(s.flavors))
	for _, f := range s.flavors {
		flavors = append(flavors, map[string]any{"id": f.ID, "name": f.Name, "links": selfLinks("flavors", f.ID, projectID)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"flavors": flavors})
}

func (s *Server) listFlavorsDetail(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	flavors := make([]flavorBody, 0, len(s.flavors))
	for _, f := range s.flavors {
		flavors = append(flavors, flavorDetail(f, projectID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"flavors": flavors})
}

func (s *Server) showFlavor(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	flavor, found := s.flavorByID(r.PathValue("flavor_id"))
	if !found {
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "Flavor not found.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flavor": flavorDetail(flavor, projectID)})
}
