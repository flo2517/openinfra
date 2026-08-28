// ADR-037 §2/§4: config.json is folded into this release's own
// content-addressed tree, so its api_origin/allowed_login_origins travel
// with, and are tamper-evident against, this exact CID (a gateway serving
// a tampered config.json produces a different CID entirely). This file
// reads it once, synchronously (not fetch/async), before any of
// auth.js/app.js/tenant.js/operator.js run -- see index.html's own
// comment for why this must be a synchronous, non-deferred, external
// script rather than an inline one or an async fetch.
//
// config.json is always same-origin relative to wherever index.html
// itself was served from (gateway or canonical alike), so this request
// needs no api_origin substitution of its own -- openinfraApiUrl below is
// what every actual API call goes through instead.
(function () {
  var config = { api_origin: '', allowed_login_origins: [] };
  try {
    var request = new XMLHttpRequest();
    request.open('GET', 'config.json', false);
    request.send(null);
    if (request.status === 200) {
      config = JSON.parse(request.responseText);
    }
  } catch (error) {
    // No config.json, or it didn't parse as JSON: fall back to
    // same-origin relative API calls -- exactly this dashboard's
    // pre-ADR-037 behavior, so a deployment that never runs the release
    // pipeline (e.g. the checked-in go:embed default this file itself
    // ships as, api_origin: "") keeps working unchanged.
  }
  window.OPENINFRA_CONFIG = config;

  // openinfraApiUrl(path) is the one place every fetch() call in this
  // bundle should route through instead of hard-coding a same-origin
  // relative path -- ADR-037 §2's "app.js/auth.js/tenant.js/operator.js
  // read [api_origin] instead of the same-origin-relative paths they use
  // today." An empty api_origin (config.json's checked-in default)
  // reproduces the exact same-origin-relative behavior this dashboard
  // had before ADR-037.
  window.openinfraApiUrl = function (path) {
    var origin = (config.api_origin || '').replace(/\/$/, '');
    return origin + path;
  };

  if ('serviceWorker' in navigator) {
    // ADR-037 §10: cache-first over the static shell, network-only for
    // /api/* (sw.js itself explains and enforces the split). Best-effort
    // only -- a registration failure (e.g. served over plain HTTP in
    // local dev, where the Service Worker API is unavailable) must never
    // block the rest of this page from working.
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
})();
