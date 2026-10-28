// Client for the feddedosint Cloudflare Worker. When no backend URL is set in
// Settings, backendConfigured() is false and callers fall back to static behaviour.

import { settings, setSetting, getSession, setSession, authToken } from './store.js';

export const backendURL = () => (settings().backendUrl || '').replace(/\/+$/, '');
export const backendConfigured = () => !!backendURL();

let healthCache = null;
export function clearHealthCache() { healthCache = null; }

// Low-level call. Returns { ok, status, data }.
export async function api(path, { method = 'GET', body, auth = false, timeout = 30000 } = {}) {
  const base = backendURL();
  if (!base) return { ok: false, status: 0, data: { error: 'no backend configured' } };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(auth && authToken() ? { Authorization: 'Bearer ' + authToken() } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (res.status === 401 && auth) setSession(null); // stale session
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

export async function signup(username, password, code) {
  const r = await api('/auth/signup', { method: 'POST', body: { username, password, code } });
  if (r.ok) setSession({ token: r.data.token, user: r.data.user });
  return r;
}

export async function login(username, password, totp) {
  const r = await api('/auth/login', { method: 'POST', body: { username, password, totp } });
  if (r.ok && r.data.token) setSession({ token: r.data.token, user: r.data.user });
  return r;
}

export async function logout() {
  await api('/auth/logout', { method: 'POST', auth: true });
  setSession(null);
}

export async function refreshMe() {
  const r = await api('/auth/me', { auth: true });
  if (r.ok) { const s = getSession(); setSession({ ...s, user: r.data.user }); }
  return r;
}

export const setup2FA = () => api('/auth/2fa/setup', { method: 'POST', auth: true });
export async function enable2FA(totp) {
  const r = await api('/auth/2fa/enable', { method: 'POST', auth: true, body: { totp } });
  if (r.ok) { const s = getSession(); setSession({ ...s, user: r.data.user }); }
  return r;
}
export async function disable2FA(password, totp) {
  const r = await api('/auth/2fa/disable', { method: 'POST', auth: true, body: { password, totp } });
  if (r.ok) { const s = getSession(); setSession({ ...s, user: r.data.user }); }
  return r;
}
export const adminUsers = () => api('/admin/users', { auth: true });

// ---------- AI + fetch ----------

export const aiChat = payload => api('/ai/chat', { method: 'POST', auth: true, body: payload, timeout: 60000 });
export const fetchUrl = url => api('/fetch', { method: 'POST', auth: true, body: { url }, timeout: 20000 });

export const aiAvailable = async () => backendConfigured() && !!(await health())?.ai;

export { setSetting };
