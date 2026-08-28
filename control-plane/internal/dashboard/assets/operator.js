// ADR-016 §2 operator views (issue #107). The four /api/v1/operator/*
// endpoints have existed and been tested since #76; nothing rendered
// them, so an operator had to reach them with curl and a bearer key.
//
// IIFE-scoped for the reason documented at the top of auth.js: classic
// scripts share one global lexical environment, and a top-level
// declaration here would collide with app.js's.
(() => {
const $ = id => document.getElementById(id);
// row()/warn(): shared with tenant.js via auth.js's window.openinfraDashboard
// (see that file for why they live there) -- no longer declared here, so
// a future edit to either can't drift between the two panels silently.
const { row, warn } = window.openinfraDashboard;

// Roles that may see this panel, mirroring userauth.roleRank's ordering
// (internal/userauth/userauth.go). This is a *rendering* decision only:
// every endpoint below stays gated server-side by requireRole, so a
// tampered client gets 403s, not data. Keep in sync if a tier is added.
const OPERATOR_ROLES = ['operator_readonly', 'operator_admin'];

const AUDIT_PAGE_SIZE = 25;
let auditOffset = 0;

function timestamp(value) {
  return value ? new Date(value).toLocaleString() : '—';
}

// Every section reports its own failure rather than letting one dead
// dependency blank the whole panel, and an unreadable section says so
// instead of rendering an empty table -- an empty table reads as "nothing
// wrong here", which is the false-green this dashboard exists to avoid
// (#14).
async function loadSection(path, warningID, unavailableMessage, render) {
  const key = window.openinfraSession.key();
  if (!key) return;
  try {
    // ADR-037 §2: routed through openinfraApiUrl (config.js) -- see
    // tenant.js's authedFetch for why.
    const response = await fetch(window.openinfraApiUrl(path), { headers: { authorization: 'Bearer ' + key } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    warn(warningID, unavailableMessage);
  }
}

function renderHealth(data) {
  const dependencies = $('operator-dependencies');
  dependencies.replaceChildren();
  const labels = { ok: 'ok', degraded: 'dégradé', unavailable: 'indisponible' };
  for (const dependency of data.dependencies || []) {
    dependencies.append(row([
      dependency.name,
      labels[dependency.status] || dependency.status,
      // Sub-millisecond probes against same-host containers are the norm
      // here, which is why the API reports microseconds (see
      // operatorhealth.go) -- rendering them as ms would show 0 for all.
      `${dependency.latency_us} µs`,
      dependency.detail || '—',
    ]));
  }

  const alerts = $('operator-alerts');
  alerts.replaceChildren();
  const severities = { critical: 'critique', warning: 'avertissement', info: 'info' };
  for (const alert of data.alerts || []) {
    alerts.append(row([
      severities[alert.severity] || alert.severity,
      alert.summary,
      alert.count || '—',
      alert.source,
    ]));
  }
  // alerts_partial means a check could not run. Saying nothing here would
  // let an empty alert list read as "everything verified healthy" when
  // some of it was never verified at all.
  if (data.alerts_partial) {
    warn('operator-health-warning', 'Certaines vérifications n\'ont pas pu s\'exécuter : cette liste d\'alertes est incomplète, pas une confirmation que tout va bien.');
  } else if ((data.alerts || []).length === 0) {
    warn('operator-health-warning', '');
    alerts.append(row(['—', 'Aucune alerte active (toutes les vérifications ont tourné).', '—', '—']));
  } else {
    warn('operator-health-warning', '');
  }
}

function renderQueue(data) {
  warn('operator-queue-warning', '');
  const states = $('operator-queue');
  states.replaceChildren();
  for (const state of data.states || []) {
    states.append(row([state.state, state.count, timestamp(state.oldest_next_retry_at)]));
  }
  const buckets = data.attempt_count_buckets || {};
  $('operator-attempts').textContent = ['0', '1-2', '3-5', '6+']
    .map(bucket => `${bucket} : ${buckets[bucket] || 0}`)
    .join(' · ');
}

function renderWorkers(data) {
  warn('operator-workers-warning', '');
  const workers = $('operator-workers');
  workers.replaceChildren();
  const claims = data.workers || [];
  for (const worker of claims) {
    const tr = row([
      worker.worker_id,
      worker.claimed_workloads,
      timestamp(worker.lease_until),
      worker.lease_expired ? 'bail expiré' : 'actif',
    ]);
    // A worker still holding rows past its lease is a stuck claim -- the
    // exact thing this table exists to surface, so it is marked, not just
    // listed among the healthy ones.
    if (worker.lease_expired) tr.classList.add('row-alert');
    workers.append(tr);
  }
  // No claims at all is normal on an idle Control Plane, but it is not
  // the same statement as "workers are healthy", so it is spelled out.
  if (claims.length === 0) {
    workers.append(row(['—', 'Aucun claim en cours (file au repos).', '—', '—']));
  }
}

function renderAudit(data) {
  warn('operator-audit-warning', '');
  const events = $('operator-audit');
  events.replaceChildren();
  for (const event of data.events || []) {
    events.append(row([
      timestamp(event.occurred_at),
      event.actor_user_id,
      event.actor_role,
      event.action,
      `${event.target_type} ${event.target_id}`,
      event.outcome,
    ]));
  }
  const shown = (data.events || []).length;
  const start = shown === 0 ? 0 : data.offset + 1;
  $('operator-audit-range').textContent = `${start}–${data.offset + shown} sur ${data.total}`;
  $('operator-audit-prev').disabled = data.offset <= 0;
  $('operator-audit-next').disabled = data.offset + shown >= data.total;
}

function loadAll() {
  loadSection('/api/v1/operator/health', 'operator-health-warning',
    'État des dépendances illisible — ne pas en conclure que les dépendances vont bien.', renderHealth);
  loadSection('/api/v1/operator/queue', 'operator-queue-warning',
    'File de workloads illisible — les compteurs ci-dessous ne sont pas à jour.', renderQueue);
  loadSection('/api/v1/operator/workers', 'operator-workers-warning',
    'Claims des workers illisibles — un claim bloqué ne serait pas visible ici.', renderWorkers);
  loadSection(`/api/v1/operator/audit?limit=${AUDIT_PAGE_SIZE}&offset=${auditOffset}`, 'operator-audit-warning',
    'Journal d\'audit illisible — cette absence d\'événements n\'est pas une absence d\'activité.', renderAudit);
}

// syncPanel is the one place that decides whether this panel exists on
// the page. It re-asks the server on every session change rather than
// caching a role: a grant made through cmd/controlplane-admin then takes
// effect on the next login instead of waiting out the session.
async function syncPanel() {
  const panel = $('operator-panel');
  const key = window.openinfraSession.key();
  if (!key) {
    panel.hidden = true;
    return;
  }
  let identity;
  try {
    const response = await fetch(window.openinfraApiUrl('/api/v1/me'), { headers: { authorization: 'Bearer ' + key } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    identity = await response.json();
  } catch (error) {
    // Not knowing our own role is not evidence of being an operator, so
    // the panel stays hidden. A tenant is the overwhelmingly common case
    // and must not be shown an operator panel full of failed sections.
    panel.hidden = true;
    return;
  }
  if (!OPERATOR_ROLES.includes(identity.role)) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  auditOffset = 0;
  loadAll();
}

$('operator-refresh').addEventListener('click', loadAll);
$('operator-audit-prev').addEventListener('click', () => {
  auditOffset = Math.max(0, auditOffset - AUDIT_PAGE_SIZE);
  loadAll();
});
$('operator-audit-next').addEventListener('click', () => {
  auditOffset += AUDIT_PAGE_SIZE;
  loadAll();
});
window.openinfraSession.onChange(syncPanel);
syncPanel();
})();
