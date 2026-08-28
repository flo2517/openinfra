// ADR-037 §10: offline/cache behavior for the dashboard's static shell.
//
// This release's bundle (a fixed content-addressed CID) never mutates in
// place -- a new release is always a new CID, served at a new URL/DNSLink
// target, never an in-place edit of this one. That makes a cache-first
// strategy for the static shell correct rather than merely convenient:
// once fetched, this exact release's assets can never change under this
// worker, so there is nothing to revalidate against.
//
// /api/* calls are explicitly excluded (network-only, no caching at all)
// -- matching dashboard.go's own `Cache-Control: no-store` on every /api/*
// response (securityHeaders) exactly, so this worker never introduces a
// second, possibly-stale source of truth for anything server-rendered or
// per-tenant.
//
// Known, named limitation (ADR-037 §10's own "left genuinely open"): a
// client with this worker still caching an old release has no built-in
// "your cached copy is stale, please refresh" UX if that release is later
// revoked (§7) or superseded (§9) -- API calls from a stale-cached shell
// still go through openinfraApiUrl/CORS (config.js, cors.go) exactly as
// normal, so a stale *shell* cannot itself serve stale *data*, but the
// shell's own HTML/JS could still be an old version until the browser's
// own Service Worker update cycle (or a manual refresh) picks up the new
// one. Not solved here, by design -- flagged rather than silently
// glossed over.
const CACHE_NAME = 'openinfra-dashboard-shell-v1';
const SHELL_PATHS = ['./', 'index.html', 'style.css', 'config.js', 'app.js', 'auth.js', 'tenant.js', 'operator.js'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_PATHS)).catch(() => {
      // A partial/failed pre-cache must not prevent installation -- the
      // fetch handler below still falls back to the network for anything
      // not yet cached.
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Network-only, never cached: every dynamic value (auth, per-tenant
  // data, operator views) lives here, and must always reflect the
  // authoritative server state (AGENTS.md: "never report ... before
  // receiving authoritative confirmation" -- the same discipline applied
  // here to "never serve a cached response for anything authoritative").
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/.well-known/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  if (event.request.method !== 'GET' || url.origin !== self.location.origin) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(event.request).then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      });
    })
  );
});
