package dashboard

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/openinfra/network/internal/frontendrelease"
)

// credentialedPathPrefixes are the endpoints ADR-037 §4 requires the
// CORS/origin-allowlist to actually gate: everything that either mints,
// consumes, or is scoped by a bearer credential. /api/v1/overview and
// the read-only provider/validator/on-chain endpoints stay outside this
// list deliberately -- they are already public, aggregate-only data
// (ADR-016 §3), so blocking them cross-origin would add friction with no
// phishing-resistance benefit; a browser that cannot read their response
// body cross-origin (no Access-Control-Allow-Origin) is already
// unaffected either way, since nothing there can be turned into
// credential theft.
var credentialedPathPrefixes = []string{
	"/api/v1/auth/",
	"/api/v1/me",
	"/api/v1/my/",
	"/api/v1/operator/",
}

func isCredentialedPath(path string) bool {
	for _, prefix := range credentialedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// originAllowlistTTL bounds how long a cached read of the current active
// release's allowed_login_origins is trusted before the next credentialed
// request re-reads it from Postgres -- long enough that this adds no
// meaningful latency to the request path (every existing dashboard
// endpoint already does at least one Postgres round trip), short enough
// that a revocation (ADR-037 §7 step 3, "needs no propagation delay at
// all") is felt by this process within a bounded, small window rather
// than only on process restart.
const originAllowlistTTL = 10 * time.Second

// corsAllowlist enforces ADR-037 §4's phishing-resistance control: a
// credentialed request whose Origin header is neither this server's own
// origin nor an origin the currently active frontend release explicitly
// trusts (static config, plus -- if a frontendrelease.Repository is
// wired -- the latest non-revoked release's allowed_login_origins) is
// rejected outright, before it ever reaches userauth/walletlogin's own
// authentication logic. This is deliberately the server's own decision,
// not the frontend's: a malicious static clone can strip any
// client-side check, but cannot make the browser ignore what this
// middleware puts in (or withholds from) Access-Control-Allow-Origin
// (ADR-037 §4).
//
// A request with no Origin header at all (same-origin navigation, most
// non-browser/test/CLI clients) is passed straight through unmodified --
// this is what keeps every existing same-origin dev flow, and every
// existing test in this package that doesn't set Origin, working
// unchanged. This also means the middleware does nothing to stop a
// non-browser, non-CORS-checked relay (ADR-037 §4's stated residual
// risk: a live-relay phishing attack), which is expected and documented,
// not a gap unique to this implementation.
func (s *Server) corsAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if origin == sameOrigin(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.originAllowed(r.Context(), origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if isCredentialedPath(r.URL.Path) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin not allowed"})
			return
		}
		// A cross-origin, non-allowlisted request to a non-credentialed
		// path: no CORS headers are set (so the browser cannot read the
		// response cross-origin), but the request itself still runs --
		// matching how a Go http.Handler with no CORS support behaves by
		// default, and how /api/v1/overview already worked before this
		// middleware existed.
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reconstructs the origin this request itself arrived at
// (scheme + host), so a same-origin fetch() call -- which some browsers
// still send an Origin header for, even though it is not cross-origin --
// is never rejected by the allowlist below it. TLS termination in front
// of this server (if any) is expected to forward X-Forwarded-Proto; its
// absence falls back to the request's own r.TLS, matching this server's
// own dev/prod posture elsewhere (dashboard.go has no existing
// X-Forwarded-* handling to mirror, so this is a new, narrowly-scoped
// addition).
func sameOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}

// originAllowed checks origin against the server's static allowlist
// (allowedOrigins, set at construction from operator config) and, if a
// frontendrelease.Repository is wired, the currently active release's own
// allowed_login_origins -- cached for originAllowlistTTL so a revocation
// (frontendrelease Repository.Revoke) is picked up within a bounded,
// short window without a Postgres round trip on every single request.
func (s *Server) originAllowed(ctx context.Context, origin string) bool {
	if frontendrelease.IsAllowedOrigin(origin, s.allowedOrigins) {
		return true
	}
	if s.releases == nil {
		return false
	}
	return frontendrelease.IsAllowedOrigin(origin, s.activeReleaseOrigins(ctx))
}

// activeReleaseOrigins returns the latest non-revoked release's
// allowed_login_origins, refreshing from s.releases at most once per
// originAllowlistTTL. A read failure (or no active release at all) is
// treated as "no additional origins trusted right now" -- fail-closed,
// consistent with every other trust decision in this package -- rather
// than falling back to a stale cache indefinitely or, worse, allowing
// everything.
func (s *Server) activeReleaseOrigins(ctx context.Context) []string {
	s.releaseOriginsMu.Lock()
	defer s.releaseOriginsMu.Unlock()
	if s.now().Sub(s.releaseOriginsAt) < originAllowlistTTL {
		return s.releaseOriginsCache
	}
	release, err := s.releases.Latest(ctx)
	s.releaseOriginsAt = s.now()
	if err != nil {
		s.releaseOriginsCache = nil
		return nil
	}
	s.releaseOriginsCache = release.AllowedLoginOrigins
	return s.releaseOriginsCache
}
