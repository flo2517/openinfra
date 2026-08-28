package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openinfra/network/internal/frontendrelease"
)

// wellKnownFrontend serves ADR-037 §3's canonical trust root: the signed
// manifest of the currently active (latest, non-revoked) frontend
// release, exactly as published (frontend_releases.manifest_json,
// verbatim -- see migrations/000022_frontend_releases.sql). A verifier
// that trusts this server's own domain-validated TLS certificate can
// learn the currently-canonical CID, its allowed_login_origins, and the
// release-signing public key's signature over both, without ever having
// to trust an IPFS gateway to tell it the truth.
//
// 404 (not 503) when no frontendrelease.Repository is wired at all --
// this is the same "endpoint genuinely does not exist yet on this
// deployment" case as any other optional feature, not a degraded-read
// case worth Overview.Partial's "authoritative data unavailable"
// treatment. 503 is reserved for a read that was attempted and failed.
func (s *Server) wellKnownFrontend(w http.ResponseWriter, r *http.Request) {
	if s.releases == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	release, err := s.releases.Latest(ctx)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(release.Manifest)
	case errors.Is(err, frontendrelease.ErrNoActiveRelease):
		http.NotFound(w, r)
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "release trust root unavailable"})
	}
}
