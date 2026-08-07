package dashboard

import (
	"net/http"

	"github.com/openinfra/network/internal/userauth"
)

// requireRole is ADR-016 slice 1's authorization enforcement point: wrap
// any handler that should only run for a caller holding a valid
// session/API key whose users.role is at least as privileged as minRole
// (userauth.RoleSatisfies -- an operator satisfies a "tenant"
// requirement too, see that function's doc comment). Intended to be
// applied once per route at registration time (Server.Handler in
// dashboard.go), the same place every route is already declared, so the
// entire dashboard authorization surface is auditable by reading one
// function rather than hunting for ad hoc checks inside individual
// handlers.
//
// Two distinct failure responses, not one generic "forbidden": 401 when
// there is no valid credential at all (the caller should log in), 403
// once a real identity is established but under-privileged for this
// route (the caller is who they say they are, just not allowed here) --
// collapsing these into one response would make "you're not logged in"
// indistinguishable from "you're logged in as the wrong role," which is
// a worse debugging experience for a legitimate caller and gives an
// attacker no useful signal either way (both already require a valid
// credential to get past the first check).
//
// Slice 1 introduces this function with zero routes wrapped in it yet --
// see ADR-016's Sequencing section. It is still real, tested code: a
// later slice's diff is "wrap the new route in requireRole," not "invent
// and test this function for the first time under deadline pressure."
func (s *Server) requireRole(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user, ok := s.authenticatedUser(ctx, r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if !userauth.RoleSatisfies(user.Role, minRole) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role"})
			return
		}
		next(w, r)
	}
}
