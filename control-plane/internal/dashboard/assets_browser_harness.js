// Executes the dashboard's <script> assets the way a browser does, so a
// mistake that kills the page is a failing test rather than a blank
// dashboard nobody notices.
//
// Why this exists: every classic (non-module) <script> on a page shares
// ONE global lexical environment. Two scripts that each declare the same
// top-level `let`/`const`/`class` are a redeclaration SyntaxError, and
// the second script then never runs at all. That is not hypothetical --
// it is exactly what happened when auth.js was added alongside app.js
// (both declared `const $`), which silently took the entire main
// dashboard offline while every Go test stayed green, because Go tests
// serve these files without ever evaluating them.
//
// Node's `vm` module models this precisely: one context, several
// vm.Scripts run against it, same global lexical environment, same
// redeclaration rules.
//
// The scripts and their order are read out of index.html rather than
// hard-coded, so the harness always covers exactly what the page loads.
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const assetsDir = process.argv[2];
if (!assetsDir) {
  console.error('usage: node assets_browser_harness.js <assets-dir>');
  process.exit(2);
}

const html = fs.readFileSync(path.join(assetsDir, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"[^>]*>/g)].map(match => match[1]);
if (scripts.length === 0) {
  console.error('no <script src> found in index.html -- the harness would vacuously pass');
  process.exit(2);
}
for (const match of html.matchAll(/<script\b([^>]*)>/g)) {
  if (/\btype="module"/.test(match[1])) {
    console.error('index.html now loads a module script; this harness models classic-script scoping only and must be updated');
    process.exit(2);
  }
}

// A permissive auto-stub: any property access returns something callable,
// constructible, and further-accessible. That keeps the harness focused
// on "does this page's script set load and run" instead of turning into a
// DOM reimplementation that needs a change every time the UI touches a
// new property.
const anything = new Proxy(function () {}, {
  get(target, property) {
    if (property === Symbol.toPrimitive) return () => '';
    if (property === 'toString' || property === 'valueOf') return () => '';
    if (property === Symbol.iterator) return function* () {};
    if (property === 'then') return undefined; // never look like a thenable
    return anything;
  },
  set: () => true,
  has: () => true,
  apply: () => anything,
  construct: () => anything,
});

const context = vm.createContext({
  document: anything,
  window: anything,
  navigator: anything,
  localStorage: anything,
  sessionStorage: anything,
  crypto: anything,
  console,
  TextEncoder,
  TextDecoder,
  AbortController,
  Promise,
  JSON,
  Date,
  Number,
  Math,
  Object,
  Array,
  Error,
  URL,
  URLSearchParams,
  encodeURIComponent,
  // Network and timers must never actually fire: this harness asserts the
  // scripts load, not that they talk to a Control Plane.
  fetch: () => new Promise(() => {}),
  setInterval: () => 0,
  clearInterval: () => {},
  setTimeout: () => 0,
  clearTimeout: () => {},
});
context.globalThis = context;

// An unhandled rejection from an async init path is a real failure the
// browser would log too, so surface it rather than exiting 0 quietly.
let failure = null;
process.on('unhandledRejection', reason => {
  failure = failure || `unhandled rejection: ${reason && reason.stack ? reason.stack : reason}`;
});

for (const script of scripts) {
  const file = path.join(assetsDir, script);
  let source;
  try {
    source = fs.readFileSync(file, 'utf8');
  } catch (error) {
    console.error(`${script}: index.html loads this file but it does not exist (${error.message})`);
    process.exit(1);
  }
  try {
    new vm.Script(source, { filename: script }).runInContext(context);
  } catch (error) {
    console.error(`${script}: ${error.constructor.name}: ${error.message}`);
    if (error instanceof SyntaxError && /already been declared/.test(error.message)) {
      console.error(
        '  This is the shared-global-lexical-environment trap: another script already\n' +
        '  declared this top-level binding, so this one does not run AT ALL. Wrap each\n' +
        '  asset script in an IIFE so its declarations stay local to the file.');
    }
    process.exit(1);
  }
}

// Give any microtask queued by the scripts' own init() a chance to reject.
setImmediate(() => {
  if (failure) {
    console.error(failure);
    process.exit(1);
  }
  console.log(`ok: ${scripts.length} script(s) loaded and ran in one shared context (${scripts.join(', ')})`);
});
