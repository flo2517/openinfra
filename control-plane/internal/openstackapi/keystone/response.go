package keystone

import (
	"time"

	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/userauth"
)

// keystoneDomain is the single implicit "default" domain ADR-031 §3
// deliberately settles for this slice -- every user/project in this
// system belongs to it; there is no domain table or domain_id column
// anywhere in the schema to look this up from.
var keystoneDomain = domainBody{ID: "default", Name: "Default"}

type domainBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type userBody struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Domain domainBody `json:"domain"`
}
type projectBody struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Domain domainBody `json:"domain"`
}
type roleBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type endpointBody struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
	Region    string `json:"region"`
	URL       string `json:"url"`
}
type catalogEntryBody struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name"`
	Endpoints []endpointBody `json:"endpoints"`
}

type tokenBody struct {
	Methods   []string           `json:"methods"`
	User      userBody           `json:"user"`
	IssuedAt  string             `json:"issued_at"`
	ExpiresAt string             `json:"expires_at"`
	Project   *projectBody       `json:"project,omitempty"`
	Roles     []roleBody         `json:"roles,omitempty"`
	Catalog   []catalogEntryBody `json:"catalog,omitempty"`
}
type tokenResponse struct {
	Token tokenBody `json:"token"`
}

// keystoneRoleName maps this system's project-scoped role strings
// (internal/projects.RoleMember/RoleAdmin) onto the names a real
// Keystone deployment's default roles use ("member"/"admin") -- purely a
// response-body convenience for client tooling that recognizes those
// names; the actual authorization decision anywhere in this codebase
// always reads internal/projects' own role strings, never this mapping.
func keystoneRoleName(role string) string {
	switch role {
	case projects.RoleAdmin:
		return "admin"
	case projects.RoleMember:
		return "member"
	default:
		return role
	}
}

// tokenResponseBody builds the Keystone v3 token response shape shared
// by issueToken and validateToken. catalog is included only when scoped
// (project non-nil) -- real Keystone only returns a service catalog for
// a scoped token, since an unscoped token has no project context to
// resolve service endpoints/quotas against.
func tokenResponseBody(baseURL string, user userauth.User, method string, issuedAt, expiresAt time.Time, project *projects.Project, role string) tokenResponse {
	body := tokenBody{
		Methods:   []string{method},
		User:      userBody{ID: user.UserID, Name: user.DisplayName, Domain: keystoneDomain},
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
	if project != nil {
		body.Project = &projectBody{ID: project.ProjectID, Name: project.Name, Domain: keystoneDomain}
		if role != "" {
			body.Roles = []roleBody{{ID: role, Name: keystoneRoleName(role)}}
		}
		body.Catalog = serviceCatalog(baseURL)
	}
	return tokenResponse{Token: body}
}

// serviceCatalog is ADR-031 §3's static, Control-Plane-config-driven
// catalog: one entry per implemented service, pointing at this Control
// Plane's own internal/openstackapi base URL. "network" was added by
// ADR-031 §5/§8's QoS/AZ mapping slice (internal/openstackapi/neutron) --
// #24 (compute) and #26 (storage) have not landed yet; a future PR adds
// its own entry here (or, more likely, this function grows a small
// registry future packages append to) rather than this package guessing
// at endpoints that don't exist yet.
func serviceCatalog(baseURL string) []catalogEntryBody {
	return []catalogEntryBody{
		{
			ID:   "identity",
			Type: "identity",
			Name: "keystone",
			Endpoints: []endpointBody{
				{ID: "identity-public", Interface: "public", Region: "RegionOne", URL: baseURL + "/v3"},
			},
		},
		{
			ID:   "network",
			Type: "network",
			Name: "neutron",
			Endpoints: []endpointBody{
				{ID: "network-public", Interface: "public", Region: "RegionOne", URL: baseURL + "/v2.0"},
			},
		},
	}
}
