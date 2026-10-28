// Client for the feddedosint Worker. GitHub sign-in; AI is gated to approved pro users.

import { settings, setSetting, getSession, setSession, authToken, currentUser } from './store.js';

export const backendURL = () => (settings().backendUrl || '').replace(/\/+$/, '');
export const backendConfigured = () => !!backendURL();

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
export const aiAvailable = async () => backendConfigured() && !!(await health())?.ai;

export { setSetting };
