// Drives assets/operator.js through one scenario and reports what it did,
// so the panel's visibility rule is covered by a test instead of by
// reading the code and hoping.
//
// The rule matters: the operator panel must appear for an operator, stay
// hidden for a tenant, and stay hidden when the role cannot be
// determined at all. The last case is the one worth pinning -- "we could
// not ask" must not fall through to "show it", and a failed /api/v1/me
// must not leave a tenant staring at a panel of failed sections.
//
// This is a rendering rule, not an authorization boundary: the server
// gates every /api/v1/operator/* route with requireRole regardless (see
// TestMeDoesNotGrantAccessToOperatorRoutes). What is asserted here is
// that the client does not *ask* for operator data it has no business
// showing, and does not paint a panel it should not paint.
//
// Usage: node operator_panel_harness.js <assets-dir> <scenario>
// Prints one JSON object on stdout.
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const [assetsDir, scenario] = process.argv.slice(2);
if (!assetsDir || !scenario) {
  console.error('usage: node operator_panel_harness.js <assets-dir> <scenario>');
  process.exit(2);
}

// A deliberately small DOM: only what operator.js actually touches, so a
// passing run means the script drove real element state rather than a
// permissive proxy that swallows everything.
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      id,
      hidden: false,
      textContent: '',
      disabled: false,
      children: [],
      classList: { names: [], add(name) { this.names.push(name); } },
      replaceChildren() { this.children = []; },
      append(...nodes) { this.children.push(...nodes); },
      addEventListener() {},
    });
  }
  return elements.get(id);
}

const requests = [];
const scenarios = {
  'no-session': { session: null },
  tenant: { session: 'session-key', role: 'tenant' },
  operator_readonly: { session: 'session-key', role: 'operator_readonly' },
  operator_admin: { session: 'session-key', role: 'operator_admin' },
  'me-fails': { session: 'session-key', meStatus: 503 },
  'unknown-role': { session: 'session-key', role: 'something_new' },
};
const config = scenarios[scenario];
if (!config) {
  console.error(`unknown scenario ${scenario}; known: ${Object.keys(scenarios).join(', ')}`);
  process.exit(2);
}

function jsonResponse(body, status = 200) {
  return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) });
}

const context = vm.createContext({
  console,
  Promise,
  JSON,
  Date,
  Math,
  Object,
  Array,
  Error,
  document: {
    getElementById: element,
    createElement: () => ({
      children: [],
      textContent: '',
      classList: { names: [], add(name) { this.names.push(name); } },
      append(...nodes) { this.children.push(...nodes); },
    }),
  },
  window: {
    openinfraSession: {
      key: () => config.session,
      onChange: () => {},
    },
    // operator.js now reads row()/warn() from here instead of declaring
    // its own copies (see auth.js's window.openinfraDashboard) -- this
    // harness never loads auth.js (only operator.js, in isolation, like
    // the rest of this mock window), so it stubs the same shape by hand,
    // matching openinfraSession's own mock just above.
    openinfraDashboard: {
      row(values) {
        const tr = { children: [], textContent: '', classList: { names: [], add(name) { this.names.push(name); } }, append(...nodes) { this.children.push(...nodes); } };
        for (const value of values) {
          const td = { textContent: value };
          tr.append(td);
        }
        return tr;
      },
      warn(id, message) {
        const el = element(id);
        el.hidden = !message;
        el.textContent = message || '';
      },
    },
  },
  fetch: (url, options) => {
    requests.push({ url, authorization: (options && options.headers && options.headers.authorization) || null });
    if (url === '/api/v1/me') {
      if (config.meStatus) return jsonResponse({ error: 'unavailable' }, config.meStatus);
      return jsonResponse({ user_id: 'user-1', role: config.role });
    }
    if (url.startsWith('/api/v1/operator/health')) {
      return jsonResponse({ dependencies: [{ name: 'postgres', status: 'ok', latency_us: 412 }], alerts: [] });
    }
    if (url.startsWith('/api/v1/operator/queue')) {
      return jsonResponse({ states: [{ state: 'RUNNING', count: 2 }], attempt_count_buckets: { '0': 2 } });
    }
    if (url.startsWith('/api/v1/operator/workers')) {
      return jsonResponse({ workers: [{ worker_id: 'w1', claimed_workloads: 1, lease_until: '2026-01-01T00:00:00Z', lease_expired: true }] });
    }
    if (url.startsWith('/api/v1/operator/audit')) {
      return jsonResponse({ events: [], total: 0, limit: 25, offset: 0 });
    }
    return jsonResponse({ error: 'unexpected url' }, 404);
  },
});
context.globalThis = context;
context.window.window = context.window;

let failure = null;
process.on('unhandledRejection', reason => {
  failure = `unhandled rejection: ${reason && reason.stack ? reason.stack : reason}`;
});

const source = fs.readFileSync(path.join(assetsDir, 'operator.js'), 'utf8');
try {
  new vm.Script(source, { filename: 'operator.js' }).runInContext(context);
} catch (error) {
  console.error(`operator.js: ${error.constructor.name}: ${error.message}`);
  process.exit(1);
}

// operator.js's entry point is async (it awaits /api/v1/me before
// deciding anything), and each section then awaits its own fetch. Drain
// the microtask queue across a few macrotask turns so those settle before
// the state is reported.
let turns = 0;
(function settle() {
  if (turns++ < 10) {
    setImmediate(settle);
    return;
  }
  if (failure) {
    console.error(failure);
    process.exit(1);
  }
  const workerRows = element('operator-workers').children;
  process.stdout.write(JSON.stringify({
    panel_hidden: element('operator-panel').hidden,
    requested: requests.map(request => request.url.split('?')[0]),
    unauthenticated_requests: requests.filter(request => !request.authorization).map(request => request.url),
    expired_lease_rows_marked: workerRows.filter(child => child.classList && child.classList.names.includes('row-alert')).length,
  }));
})();
