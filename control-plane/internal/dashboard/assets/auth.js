// ADR-014: wallet-based dashboard login, local-key fallback (slice 1 --
// no browser wallet extension integration yet, see the ADR's "Client-side
// signing" decision). The "wallet" here is an Ed25519 keypair generated
// and held entirely in this browser via the native WebCrypto API -- no
// vendored crypto library, consistent with this dashboard's
// self-hosted-only, no-CDN asset pattern (script-src 'self').
//
// Key custody note, matching the ADR: a browser-local key has no hardware
// backing and is only as safe as this browser profile. It proves the
// same protocol end to end; it is not presented as equivalent to a real
// wallet extension or hardware key.
//
// Everything below is wrapped in an IIFE because classic <script>s share
// one global lexical environment: a top-level `const` here collides with
// the same name in app.js, and a collision is not a warning -- it is a
// redeclaration SyntaxError that stops the *other* script from running at
// all. That outage happened (this file's `$` versus app.js's) and was
// invisible to every server-side test. Function scope makes it
// impossible; assets_browser_harness.js keeps it that way.
(() => {
const $ = id => document.getElementById(id);

const LOCAL_KEY_STORAGE = 'openinfra_wallet_key';
const SESSION_KEY_STORAGE = 'openinfra_session_key';
const SESSION_EXPIRY_STORAGE = 'openinfra_session_expiry';
const LOGIN_DOMAIN = new TextEncoder().encode('openinfra-dashboard-login-v1\0');

function toHex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hexString) {
  const out = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hexString.substr(i * 2, 2), 16);
  return out;
}

// getOrCreateLocalKey persists the private key as a JWK in localStorage
// (survives across sessions -- this key *is* the user's identity, not a
// transient credential like the session key below) and derives the
// public key fresh each time rather than also storing it, so there is
// only one source of truth for what the key actually is.
async function getOrCreateLocalKey() {
  const stored = localStorage.getItem(LOCAL_KEY_STORAGE);
  if (stored) {
    const jwk = JSON.parse(stored);
    const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, true, ['sign']);
    const publicJwk = { ...jwk, key_ops: ['verify'] };
    delete publicJwk.d;
    const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'Ed25519' }, true, ['verify']);
    const rawPublic = await crypto.subtle.exportKey('raw', publicKey);
    return { privateKey, publicKeyHex: toHex(rawPublic) };
  }
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  localStorage.setItem(LOCAL_KEY_STORAGE, JSON.stringify(jwk));
  const rawPublic = await crypto.subtle.exportKey('raw', pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyHex: toHex(rawPublic) };
}

function renderLoggedIn(account, expiresAt) {
  $('auth-logged-out').hidden = true;
  $('auth-logged-in').hidden = false;
  $('auth-connected-account').textContent = account;
  $('auth-session-expiry').textContent = new Date(expiresAt).toLocaleString();
  $('auth-issued-key').hidden = true;
}

function renderLoggedOut() {
  $('auth-logged-out').hidden = false;
  $('auth-logged-in').hidden = true;
}

function showAuthMessage(text) {
  const el = $('auth-issued-key');
  el.hidden = false;
  el.textContent = text;
}

async function login() {
  const key = await getOrCreateLocalKey();

  const challengeResponse = await fetch('/api/v1/auth/challenge', { method: 'POST' });
  if (!challengeResponse.ok) throw new Error(`challenge request failed: HTTP ${challengeResponse.status}`);
  const challenge = await challengeResponse.json();
  const nonce = fromHex(challenge.nonce);
  const message = new Uint8Array(LOGIN_DOMAIN.length + nonce.length);
  message.set(LOGIN_DOMAIN, 0);
  message.set(nonce, LOGIN_DOMAIN.length);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, message);

  const loginResponse = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_id: challenge.challenge_id,
      account: key.publicKeyHex,
      scheme: 0, // Ed25519 -- Sr25519 (1) is not yet supported client- or server-side
      signature: toHex(signature),
    }),
  });
  if (!loginResponse.ok) throw new Error(`login failed: HTTP ${loginResponse.status}`);
  const session = await loginResponse.json();
  sessionStorage.setItem(SESSION_KEY_STORAGE, session.session_key);
  sessionStorage.setItem(SESSION_EXPIRY_STORAGE, session.expires_at);
  renderLoggedIn(key.publicKeyHex, session.expires_at);
}

function logout() {
  sessionStorage.removeItem(SESSION_KEY_STORAGE);
  sessionStorage.removeItem(SESSION_EXPIRY_STORAGE);
  renderLoggedOut();
}

async function issueAPIKey() {
  const sessionKey = sessionStorage.getItem(SESSION_KEY_STORAGE);
  if (!sessionKey) return;
  const response = await fetch('/api/v1/auth/api-keys', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + sessionKey },
  });
  if (!response.ok) {
    showAuthMessage(`Échec de la génération de la clé (HTTP ${response.status}).`);
    return;
  }
  const issued = await response.json();
  showAuthMessage('Nouvelle clé API (affichée une seule fois -- copiez-la maintenant) : ' + issued.api_key);
}

async function init() {
  if (!(window.crypto && crypto.subtle && crypto.subtle.generateKey)) {
    $('auth-unsupported').hidden = false;
    $('auth-logged-out').hidden = true;
    return;
  }
  let key;
  try {
    key = await getOrCreateLocalKey();
  } catch (error) {
    // A browser that exposes crypto.subtle but not the Ed25519 algorithm
    // (an older shipped version) fails here, not at the feature-detect
    // check above -- same fallback UI either way.
    $('auth-unsupported').hidden = false;
    $('auth-logged-out').hidden = true;
    return;
  }
  $('auth-account').textContent = key.publicKeyHex;

  const existingSession = sessionStorage.getItem(SESSION_KEY_STORAGE);
  const existingExpiry = sessionStorage.getItem(SESSION_EXPIRY_STORAGE);
  if (existingSession && existingExpiry && new Date(existingExpiry) > new Date()) {
    renderLoggedIn(key.publicKeyHex, existingExpiry);
  }

  $('auth-connect').addEventListener('click', () => {
    login().catch(error => showAuthMessage('La connexion a échoué : ' + error.message));
  });
  $('auth-logout').addEventListener('click', logout);
  $('auth-issue-key').addEventListener('click', () => {
    issueAPIKey().catch(error => showAuthMessage('Erreur : ' + error.message));
  });
}

init();
})();
