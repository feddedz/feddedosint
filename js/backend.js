// Client for the feddedosint Worker. GitHub sign-in; AI is gated to approved pro users.

import { setSetting, getSession, setSession, authToken, currentUser } from './store.js';

// The one shared Worker every visitor uses. Not configurable per browser.
export const BACKEND = 'https://feddedosint-api.bptiktok6.workers.dev';
export const backendURL = () => BACKEND;
export const backendConfigured = () => true;

let healthCache = null;
export const clearHealthCache = () => { healthCache = null; };

export async function api(path, { method = 'GET', body, auth = false, timeout = 30000 } = {}) {
  const base = backendURL();
  if (!base) return { ok: false, status: 0, data: { error: 'no backend configured' } };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(auth && authToken() ? { Authorization: 'Bearer ' + authToken() } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (res.status === 401 && auth) setSession(null);
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.name === 'AbortError' ? 'request timed out' : 'could not reach the backend' } };
  } finally {
    clearTimeout(timer);
  }
}

export async function health(force) {
  if (healthCache && !force) return healthCache;
  const r = await api('/health');
  healthCache = r.ok ? r.data : null;
  return healthCache;
}

// ---------- auth ----------

export const isLoggedIn = () => !!getSession();
export const user = () => currentUser();
export const isAdmin = () => !!currentUser()?.admin;
export const isApproved = () => { const u = currentUser(); return !!u && (u.admin || u.status === 'approved'); };
export const isPro = () => { const u = currentUser(); return !!u && (u.admin || (u.status === 'approved' && u.pro)); };

// Start the GitHub OAuth flow by sending the browser to the Worker.
export function loginWithGitHub() {
  if (!backendConfigured()) return;
  location.href = backendURL() + '/auth/github/start';
}

// Called on page load: if the Worker redirected back with #auth=<token>, store it.
// Returns 'ok' | 'error' | null.
export async function consumeAuthRedirect() {
  const m = location.hash.match(/^#auth=([^&]+)/);
  if (!m) return null;
  const val = decodeURIComponent(m[1]);
  history.replaceState(null, '', location.pathname + location.search + '#account');
  if (val.startsWith('error:')) return 'error';
  setSession({ token: val, user: null });
  const r = await refreshMe();
  return r.ok ? 'ok' : 'error';
}

export async function refreshMe() {
  const r = await api('/auth/me', { auth: true });
  if (r.ok) setSession({ token: authToken(), user: r.data.user });
  return r;
}

export async function logout() {
  await api('/auth/logout', { method: 'POST', auth: true });
  setSession(null);
}

// ---------- admin ----------
export const adminUsers = () => api('/admin/users', { auth: true });
export const adminSetUser = (login, patch) => api('/admin/user', { method: 'POST', auth: true, body: { login, ...patch } });

// ---------- AI + fetch ----------
export const aiChat = payload => api('/ai/chat', { method: 'POST', auth: true, body: payload, timeout: 60000 });

// Streaming chat. Calls onThought(delta) and onText(delta, full) as tokens arrive.
// Returns the full answer. Pass an AbortSignal to stop it.
export async function aiStream(payload, { onThought, onText, signal } = {}) {
  const base = backendURL();
  if (!base) throw new Error('no backend configured');
  const res = await fetch(base + '/ai/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(authToken() ? { Authorization: 'Bearer ' + authToken() } : {}) },
    body: JSON.stringify(payload),
    signal,
  });
  const ct = res.headers.get('content-type') || '';
  if (!res.ok || !ct.includes('text/event-stream')) {
    let data = {};
    try { data = await res.json(); } catch {}
    if (res.status === 401) setSession(null);
    throw new Error(data.error || `AI error ${res.status}`);
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '', answer = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const line = buf.slice(0, i).split('\n').find(l => l.startsWith('data:'));
      buf = buf.slice(i + 2);
      if (!line) continue;
      const raw = line.slice(5).trim();
      if (!raw || raw === '[DONE]') continue;
      let obj; try { obj = JSON.parse(raw); } catch { continue; }
      for (const p of obj.candidates?.[0]?.content?.parts || []) {
        if (!p.text) continue;
        if (p.thought) onThought?.(p.text);
        else { answer += p.text; onText?.(p.text, answer); }
      }
    }
  }
  return answer;
}
export const fetchUrl = url => api('/fetch', { method: 'POST', auth: true, body: { url }, timeout: 20000 });

// Same existence logic the Worker's /check uses, run on a status code + body (for the /fetch fallback).
function classify(spec, status, body) {
  const eCode = spec.e || 200;
  const has = s => s && body.includes(s);
  if (status === eCode && (!spec.es || has(spec.es))) return 'found';
  if ((spec.mc && status === spec.mc) || has(spec.ms)) return 'none';
  if ((status === 404 || status === 410) && !spec.es) return 'none';
  if (status === eCode && spec.es) return 'none';
  return 'unknown';
}
const siteURL = (spec, username) => spec.u.replace(/\{u\}/g, encodeURIComponent(username));

// One existence check via the already-deployed /fetch endpoint (client-side classify).
async function checkViaFetch(spec, username) {
  const url = siteURL(spec, username);
  const r = await api('/fetch', { method: 'POST', auth: true, body: { url }, timeout: 15000 });
  if (r.status === 429) return { state: 'unknown', error: 'rate limited', url };
  if (!r.ok || !r.data) return { state: 'unknown', error: r.data?.error || 'failed', url };
  return { state: classify(spec, r.data.status, r.data.body || ''), status: r.data.status, url: r.data.finalUrl || url };
}

// Deep username scan. Prefers the batched /check endpoint (fast, whole list). If the deployed
// Worker doesn't have it yet, falls back to per-site /fetch (slower, so capped). Calls
// onMode(mode[, error]) once the mode is known and onBatch(sites[], results[]) as results arrive.
// Pass an AbortSignal to stop early.
export async function deepScan(username, sites, { onMode, onBatch, signal, batchSize = 40, concurrency = 5, fetchCap = 150 } = {}) {
  const batches = [];
  for (let i = 0; i < sites.length; i += batchSize) batches.push(sites.slice(i, i + batchSize));

  // Probe /check with the first batch to learn the mode.
  let mode = 'check', probe = null;
  const first = batches[0] || [];
  if (first.length) {
    const r = await api('/check', { method: 'POST', auth: true, body: { username, sites: first }, timeout: 30000 });
    if (r.status === 404) mode = 'fetch';                                   // endpoint not deployed yet
    else if (r.status === 401 || r.status === 403) { onMode?.('blocked', r.data?.error); return { mode: 'blocked', error: r.data?.error }; }
    else probe = r.ok && Array.isArray(r.data?.results) ? r.data.results : first.map(() => ({ state: 'unknown' }));
  }
  onMode?.(mode);
  if (signal?.aborted) return { mode };

  if (mode === 'check') {
    if (probe) onBatch?.(first, probe);
    let next = 1;
    const run = async () => {
      while (next < batches.length) {
        if (signal?.aborted) return;
        const batch = batches[next++];
        const r = await api('/check', { method: 'POST', auth: true, body: { username, sites: batch }, timeout: 30000 });
        if (signal?.aborted) return;
        onBatch?.(batch, r.ok && Array.isArray(r.data?.results) ? r.data.results : batch.map(() => ({ state: 'unknown', error: r.data?.error || 'error' })));
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, batches.length - 1)) }, run));
    return { mode, scanned: sites.length };
  }

  // Fallback: per-site /fetch, capped to respect the tighter rate limit.
  const set = sites.slice(0, fetchCap);
  let idx = 0;
  const run = async () => {
    while (idx < set.length) {
      if (signal?.aborted) return;
      const spec = set[idx++];
      const res = await checkViaFetch(spec, username).catch(() => ({ state: 'unknown', error: 'failed' }));
      if (signal?.aborted) return;
      onBatch?.([spec], [res]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, set.length) }, run));
  return { mode, scanned: set.length, partial: sites.length > set.length };
}
export const aiAvailable = async () => backendConfigured() && !!(await health())?.ai;

export { setSetting };
