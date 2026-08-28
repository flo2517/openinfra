package dashboard

import (
	"context"
	"crypto/ed25519"
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
// treatment. 503 is reserved for a read that was attempted and failed --
// which now includes "no trusted release-signing public key is
// configured at all" and "the latest release does not verify against it"
// (the internal security review's finding this fixes: this handler used
// to serve release.Manifest verbatim with no frontendrelease.Verify call
// at all, trusting whatever Postgres happened to contain).
func (s *Server) wellKnownFrontend(w http.ResponseWriter, r *http.Request) {
	if s.releases == nil {
		http.NotFound(w, r)
		return
	}
	if len(s.releaseTrustedKey) != ed25519.PublicKeySize {
		// Fail closed: an absent FRONTEND_RELEASE_PUBLIC_KEY must never be
		// read as "everything verifies" -- see Server.releaseTrustedKey.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "release trust root unavailable: no trusted release-signing public key is configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	release, err := s.releases.Latest(ctx)
	switch {
	case err == nil:
		if verifyErr := frontendrelease.Verify(s.releaseTrustedKey, release.Manifest); verifyErr != nil {
			// A release that made it into Postgres without verifying
			// against the trusted key (tampered row, wrong-key signature,
			// unsigned) must never be served as the trust root.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "release trust root unavailable: latest release does not verify against the trusted public key"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(release.Manifest)
	case errors.Is(err, frontendrelease.ErrNoActiveRelease):
		http.NotFound(w, r)
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "release trust root unavailable"})
	}
}
