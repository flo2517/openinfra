// ADR-016 §2 tenant views: the caller's own workloads
// (GET /api/v1/my/workloads), a form to submit a new one
// (POST /api/v1/my/workloads), and a stop action per row
// (POST /api/v1/my/workloads/{id}/stop). All three have existed and been
// tested server-side since #92/#101; nothing rendered any of them, so a
// tenant had to reach them with curl and a bearer key -- the same gap
// operator.js closed for the operator tier (#107).
//
// IIFE-scoped for the reason documented at the top of auth.js: classic
// scripts share one global lexical environment, and a top-level
// declaration here would collide with app.js's/operator.js's.
(() => {
const $ = id => document.getElementById(id);
// row()/warn(): shared with operator.js via auth.js's window.openinfraDashboard
// (see that file for why they live there) -- no longer declared here, so
// a future edit to either can't drift between the two panels silently.
const { row, warn } = window.openinfraDashboard;

// Terminal or already-in-flight states: the stop button is disabled, not
// removed, so the row's layout doesn't jump as a workload progresses.
const NON_STOPPABLE_STATES = new Set(['STOPPING', 'STOPPED', 'COMPLETED', 'FAILED']);

function authedFetch(path, options = {}) {
  const key = window.openinfraSession.key();
  const headers = Object.assign({}, options.headers, { authorization: 'Bearer ' + key });
  // ADR-037 §2: every credentialed call routes through
  // openinfraApiUrl(path) (config.js) instead of a hard-coded
  // same-origin-relative path, so it targets config.json's api_origin
  // once this bundle is served from a content-addressed gateway.
  return fetch(window.openinfraApiUrl(path), Object.assign({}, options, { headers }));
}

// cpuCell/ramCell/storageCell read Requirements the same way app.js's
// storageCell/bandwidthCell read Provider fields: Requirements is null
// (not a zeroed struct) when the stored definition could not be decoded,
// so that is shown as "—", never as "0" (see tenantviews.go's
// decodeRequirements doc comment).
function cpuCell(w) { return w.requirements ? w.requirements.cpu_cores : '—'; }
function ramCell(w) { return w.requirements ? `${w.requirements.ram_mb} Mo` : '—'; }
function storageCell(w) { return w.requirements ? `${w.requirements.storage_gb} Go` : '—'; }

async function stopWorkload(workloadID, button) {
  button.disabled = true;
  try {
    const response = await authedFetch(`/api/v1/my/workloads/${encodeURIComponent(workloadID)}/stop`, { method: 'POST' });
    if (!response.ok && response.status !== 409) throw new Error(`HTTP ${response.status}`);
    await loadWorkloads();
  } catch (error) {
    warn('tenant-workloads-warning', 'Impossible d\'arrêter ce workload -- réessayez.');
    button.disabled = false;
  }
}

function renderWorkloads(data) {
  warn('tenant-workloads-warning', '');
  const body = $('tenant-workloads');
  body.replaceChildren();
  const workloads = data.workloads || [];
  if (workloads.length === 0) {
    body.append(row(['—', 'Aucun workload soumis pour le moment.', '—', '—', '—', '—', '—', '—']));
    return;
  }
  for (const workload of workloads) {
    const tr = row([
      workload.workload_id,
      workload.state,
      workload.image,
      cpuCell(workload),
      ramCell(workload),
      storageCell(workload),
      workload.error_code ? `${workload.error_code} : ${workload.last_error || ''}` : '—',
    ]);
    const actionCell = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Arrêter';
    button.disabled = NON_STOPPABLE_STATES.has(workload.state);
    button.addEventListener('click', () => stopWorkload(workload.workload_id, button));
    actionCell.append(button);
    tr.append(actionCell);
    body.append(tr);
  }
}

async function loadWorkloads() {
  try {
    const response = await authedFetch('/api/v1/my/workloads');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderWorkloads(await response.json());
  } catch (error) {
    warn('tenant-workloads-warning', 'Liste de mes workloads illisible -- les données affichées peuvent être obsolètes.');
  }
}

// submitWorkload posts the form's five fields as-is; every real validation
// (image pinned by digest, positive CPU/RAM, bounded duration, ...) is
// internal/workloadapi's validateSubmission, run server-side through the
// exact SubmitWorkload path a gRPC caller would hit -- this function's own
// checks are a UX nicety (fail fast, keep the network round trip for
// mistakes worth reporting precisely), never the actual authority on what
// is accepted.
async function submitWorkload(event) {
  event.preventDefault();
  const submitButton = $('tenant-submit');
  const image = $('tenant-image').value.trim();
  const cpu = Number($('tenant-cpu').value);
  const ram = Number($('tenant-ram').value);
  const storage = Number($('tenant-storage').value);
  const duration = Number($('tenant-duration').value);

  warn('tenant-submit-warning', '');
  $('tenant-submit-status').hidden = true;

  if (!image) { warn('tenant-submit-warning', 'L\'image est requise.'); return; }
  if (!(cpu > 0)) { warn('tenant-submit-warning', 'Le nombre de cœurs CPU doit être positif.'); return; }
  if (!(ram > 0)) { warn('tenant-submit-warning', 'La RAM (Mo) doit être positive.'); return; }
  if (storage < 0) { warn('tenant-submit-warning', 'Le stockage (Go) ne peut pas être négatif.'); return; }
  if (!(duration > 0)) { warn('tenant-submit-warning', 'La durée (secondes) doit être positive.'); return; }

  submitButton.disabled = true;
  try {
    const response = await authedFetch('/api/v1/my/workloads', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        image,
        cpu_cores: cpu,
        ram_mb: ram,
        storage_gb: storage,
        duration_seconds: duration,
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      warn('tenant-submit-warning', payload.error || `Échec de la soumission (HTTP ${response.status}).`);
      return;
    }
    const status = $('tenant-submit-status');
    status.hidden = false;
    status.textContent = `Workload soumis : ${payload.workload_id} (${payload.state}).`;
    await loadWorkloads();
  } catch (error) {
    warn('tenant-submit-warning', 'La soumission a échoué -- vérifiez votre connexion et réessayez.');
  } finally {
    submitButton.disabled = false;
  }
}

// syncPanel is the one place that decides whether this panel exists on
// the page, mirroring operator.js's syncPanel -- but every authenticated
// role satisfies the tenant tier (userauth.RoleSatisfies), so unlike the
// operator panel this one only needs a session to exist, not a specific
// role. It re-checks on every session change rather than caching whether
// one exists, so logging out hides the panel immediately.
function syncPanel() {
  const panel = $('tenant-panel');
  if (!window.openinfraSession.key()) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  loadWorkloads();
}

$('tenant-refresh').addEventListener('click', loadWorkloads);
$('tenant-submit-form').addEventListener('submit', submitWorkload);
window.openinfraSession.onChange(syncPanel);
syncPanel();
})();
