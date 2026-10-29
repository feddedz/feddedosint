// feddedosint backend — one Cloudflare Worker, shared by all visitors.
//
// - Sign in with GitHub (OAuth). No passwords handled here.
// - New users are "pending" until the admin approves them.
// - Pro users may use the AI (chat + autonomous engine). The Gemini key is a
//   server-side secret and never reaches any browser.
// - Admin (GITHUB login == ADMIN_USER) approves/denies users and grants pro.
//
// KV (binding USERS) keys:  user:<login>  session:<token>  oauth:<state>  rl:<bucket>
//
// Config — [vars]: AI_MODEL, ALLOWED_ORIGINS, ADMIN_USER, SITE_URL, GITHUB_CLIENT_ID
//          secrets: GEMINI_KEY, GITHUB_CLIENT_SECRET

const SESSION_TTL = 60 * 60 * 24 * 30;

const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = n => b64url(crypto.getRandomValues(new Uint8Array(n)));

// ---------- http helpers ----------

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = allowed.includes(origin) || allowed.includes('*');
  return {
    'Access-Control-Allow-Origin': ok ? origin : (allowed[0] || ''),
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
const json = (data, status, request, env) => new Response(JSON.stringify(data), {
  status: status || 200, headers: { 'Content-Type': 'application/json', ...corsHeaders(request, env) },
});
const err = (msg, status, request, env) => json({ error: msg }, status || 400, request, env);
const redirect = loc => new Response(null, { status: 302, headers: { Location: loc } });

async function rateLimit(env, bucket, limit, windowSec) {
  const key = `rl:${bucket}:${Math.floor(Date.now() / 1000 / windowSec)}`;
  const n = Number(await env.USERS.get(key)) || 0;
  if (n >= limit) return false;
  await env.USERS.put(key, String(n + 1), { expirationTtl: windowSec + 5 });
  return true;
}
const clientIP = request => request.headers.get('CF-Connecting-IP') || 'unknown';

// ---------- users & sessions ----------

const isAdmin = (login, env) => login.toLowerCase() === (env.ADMIN_USER || '').toLowerCase();
const publicUser = u => ({ login: u.login, name: u.name, avatar: u.avatar, status: u.status, pro: !!u.pro, admin: !!u.admin, created: u.created, lastLogin: u.lastLogin || null });

async function sessionUser(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  const s = await env.USERS.get(`session:${token}`, 'json');
  if (!s) return null;
  const user = await env.USERS.get(`user:${s.login}`, 'json');
  return user ? { ...user, token } : null;
}

// Returns null if allowed, else a reason string.
function gate(user, needPro) {
  if (!user) return 'auth';
  if (user.admin) return null;
  if (user.status === 'denied') return 'denied';
  if (user.status !== 'approved') return 'pending';
  if (needPro && !user.pro) return 'pro';
  return null;
}
const GATE_MSG = {
  auth: 'sign in with GitHub to use this',
  pending: 'your account is awaiting approval',
  denied: 'this account has been denied access',
  pro: 'this is a pro feature — ask the admin for access',
};

// ---------- GitHub OAuth ----------

async function ghStart(request, env) {
  if (!env.GITHUB_CLIENT_ID) return err('github login is not configured', 503, request, env);
  const url = new URL(request.url);
  const state = rand(16);
  await env.USERS.put(`oauth:${state}`, '1', { expirationTtl: 600 });
  const redirectUri = `${url.origin}/auth/github/callback`;
  const auth = new URL('https://github.com/login/oauth/authorize');
  auth.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  auth.searchParams.set('redirect_uri', redirectUri);
  auth.searchParams.set('scope', 'read:user');
  auth.searchParams.set('state', state);
  auth.searchParams.set('allow_signup', 'true');
  return redirect(auth.href);
}

async function ghCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code'), state = url.searchParams.get('state');
  const site = env.SITE_URL || (env.ALLOWED_ORIGINS || '').split(',')[0] || '/';
  const back = reason => redirect(`${site}#auth=error:${reason}`);
  if (!code || !state || !(await env.USERS.get(`oauth:${state}`))) return back('badstate');
  await env.USERS.delete(`oauth:${state}`);

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: `${url.origin}/auth/github/callback` }),
  }).then(r => r.json()).catch(() => null);
  if (!tokenRes?.access_token) return back('notoken');

  const gh = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${tokenRes.access_token}`, 'User-Agent': 'feddedosint', Accept: 'application/vnd.github+json' },
  }).then(r => r.json()).catch(() => null);
  if (!gh?.login) return back('nouser');

  const login = gh.login.toLowerCase();
  const admin = isAdmin(login, env);
  const existing = await env.USERS.get(`user:${login}`, 'json');
  const user = existing || { login, created: Date.now(), status: admin ? 'approved' : 'pending', pro: admin };
  user.name = gh.name || gh.login;
  user.avatar = gh.avatar_url || '';
  user.admin = admin;
  if (admin) { user.status = 'approved'; user.pro = true; }
  user.lastLogin = Date.now();
  await env.USERS.put(`user:${login}`, JSON.stringify(user));

  const token = rand(32);
  await env.USERS.put(`session:${token}`, JSON.stringify({ login }), { expirationTtl: SESSION_TTL });
  return redirect(`${site}#auth=${token}`);
}

// ---------- admin ----------

async function adminUsers(request, env, user) {
  if (!user.admin) return err('admin only', 403, request, env);
  const list = await env.USERS.list({ prefix: 'user:' });
  const users = [];
  for (const k of list.keys) { const u = await env.USERS.get(k.name, 'json'); if (u) users.push(publicUser(u)); }
  const rank = { pending: 0, approved: 1, denied: 2 };
  users.sort((a, b) => (rank[a.status] - rank[b.status]) || (b.created - a.created));
  return json({ count: users.length, users }, 200, request, env);
}

async function adminSetUser(request, env, user) {
  if (!user.admin) return err('admin only', 403, request, env);
  const { login, status, pro } = await request.json().catch(() => ({}));
  const target = login && await env.USERS.get(`user:${String(login).toLowerCase()}`, 'json');
  if (!target) return err('no such user', 404, request, env);
  if (target.admin) return err('cannot modify the admin account', 400, request, env);
  if (status && ['pending', 'approved', 'denied'].includes(status)) target.status = status;
  if (typeof pro === 'boolean') target.pro = pro;
  await env.USERS.put(`user:${target.login}`, JSON.stringify(target));
  return json({ ok: true, user: publicUser(target) }, 200, request, env);
}

// ---------- AI proxy ----------

async function handleAI(request, env, user) {
  const g = gate(user, true);
  if (g) return err(GATE_MSG[g], g === 'auth' ? 401 : 403, request, env);
  if (!await rateLimit(env, `ai:${user.login}`, 60, 60)) return err('rate limit reached — wait a minute', 429, request, env);
  if (!env.GEMINI_KEY) return err('the AI backend is not configured', 503, request, env);

  const body = await request.json().catch(() => ({}));
  const generationConfig = {
    temperature: body.temperature ?? 0.4,
    maxOutputTokens: Math.min(body.maxOutputTokens || 2048, 8192),
    ...(body.json ? { responseMimeType: 'application/json' } : {}),
  };
  // Current flash/pro models "think" by default, which is slow and can consume the whole
  // output budget before any answer. Disable it (AI_THINKING unset or "0") unless a budget is set.
  const budget = env.AI_THINKING === undefined ? 0 : Number(env.AI_THINKING);
  if (Number.isFinite(budget)) generationConfig.thinkingConfig = { thinkingBudget: budget };

  const payload = {
    contents: Array.isArray(body.contents) ? body.contents : [{ role: 'user', parts: [{ text: String(body.prompt || '') }] }],
    generationConfig,
    ...(body.system ? { systemInstruction: { parts: [{ text: String(body.system) }] } } : {}),
  };

  // AI_MODEL = "BESTMODEL" tries the best model first and falls back down a chain whenever
  // one is overloaded, rate-limited or unavailable. Otherwise the single configured model is used.
  const DEFAULT_CHAIN = 'gemini-3.8-flash,gemini-3.7-flash,gemini-3.6-flash,gemini-3.5-flash,gemini-2.5-flash,gemini-flash-latest,gemini-2.5-flash-lite';
  const configured = (env.AI_MODEL || 'gemini-2.5-flash').trim();
  const models = configured.toUpperCase() === 'BESTMODEL'
    ? (env.BESTMODEL_CHAIN || DEFAULT_CHAIN).split(',').map(s => s.trim()).filter(Boolean)
    : [configured];

  const deadline = Date.now() + 55000;
  let lastErr = 'no model responded';
  for (const model of models) {
    if (Date.now() > deadline) break;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 25000);
    let upstream;
    try {
      upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_KEY }, body: JSON.stringify(payload), signal: ctrl.signal,
      });
    } catch (e) {
      lastErr = e.name === 'AbortError' ? 'the AI timed out' : 'could not reach the AI service';
      clearTimeout(timer);
      continue; // try the next model
    }
    clearTimeout(timer);
    const data = await upstream.json().catch(() => ({}));
    if (upstream.ok) {
      const cand = data.candidates?.[0];
      const text = (cand?.content?.parts || []).map(p => p.text || '').join('');
      if (text) return json({ text, usage: data.usageMetadata, model }, 200, request, env);
      lastErr = `no text (finishReason: ${cand?.finishReason || '?'})`;
      continue; // empty output — try the next model
    }
    const msg = data?.error?.message || `AI error ${upstream.status}`;
    lastErr = msg;
    const retriable = [429, 500, 503, 404].includes(upstream.status) || /overload|high demand|unavailable|exhausted|try again|quota/i.test(msg);
    if (models.length > 1 && retriable) continue; // fall back to the next model
    return json({ error: msg }, 200, request, env);
  }
  return json({ error: models.length > 1 ? `all models are busy right now — ${lastErr}` : lastErr }, 200, request, env);
}

// The model list for BESTMODEL fallback, or the single configured model.
function modelList(env) {
  const DEFAULT_CHAIN = 'gemini-3.8-flash,gemini-3.7-flash,gemini-3.6-flash,gemini-3.5-flash,gemini-2.5-flash,gemini-flash-latest,gemini-2.5-flash-lite';
  const configured = (env.AI_MODEL || 'gemini-2.5-flash').trim();
  return configured.toUpperCase() === 'BESTMODEL'
    ? (env.BESTMODEL_CHAIN || DEFAULT_CHAIN).split(',').map(s => s.trim()).filter(Boolean)
    : [configured];
}

// ---------- AI streaming (chat): live tokens + visible thinking ----------

async function handleAIStream(request, env, user) {
  const g = gate(user, true);
  if (g) return err(GATE_MSG[g], g === 'auth' ? 401 : 403, request, env);
  if (!await rateLimit(env, `ai:${user.login}`, 60, 60)) return err('rate limit reached — wait a minute', 429, request, env);
  if (!env.GEMINI_KEY) return err('the AI backend is not configured', 503, request, env);

  const body = await request.json().catch(() => ({}));
  const generationConfig = {
    temperature: body.temperature ?? 0.5,
    maxOutputTokens: Math.min(body.maxOutputTokens || 2048, 8192),
    // Stream the model's reasoning as well as its answer.
    thinkingConfig: { includeThoughts: true, ...(Number.isFinite(Number(env.AI_THINKING)) ? { thinkingBudget: Number(env.AI_THINKING) } : {}) },
  };
  const payload = {
    contents: Array.isArray(body.contents) ? body.contents : [{ role: 'user', parts: [{ text: String(body.prompt || '') }] }],
    generationConfig,
    ...(body.system ? { systemInstruction: { parts: [{ text: String(body.system) }] } } : {}),
  };

  const models = modelList(env);
  let lastErr = 'no model responded';
  for (const model of models) {
    let upstream;
    try {
      upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_KEY }, body: JSON.stringify(payload),
      });
    } catch {
      lastErr = 'could not reach the AI service';
      continue;
    }
    if (upstream.ok && upstream.body) {
      // Pipe the SSE straight through to the browser.
      return new Response(upstream.body, {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Model': model, ...corsHeaders(request, env) },
      });
    }
    const data = await upstream.json().catch(() => ({}));
    lastErr = data?.error?.message || `AI error ${upstream.status}`;
    const retriable = [429, 500, 503, 404].includes(upstream.status) || /overload|high demand|unavailable|exhausted|try again|quota/i.test(lastErr);
    if (models.length > 1 && retriable) continue;
    return json({ error: lastErr }, 200, request, env);
  }
  return json({ error: `all models are busy right now — ${lastErr}` }, 200, request, env);
}

// ---------- SSRF-guarded fetch (approved users) ----------

const BLOCKED_HOST = /^(localhost|.*\.local|.*\.internal|metadata.*)$/i;
const BLOCKED_IP = /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1|fe80|fc|fd)/i;

const safeHost = h => h && !BLOCKED_HOST.test(h) && !BLOCKED_IP.test(h);

// ---------- deep username scan (approved users) ----------
//
// The client sends a batch of site specs (from the WhatsMyName dataset) plus a username.
// We run each existence check server-side — no browser CORS limits, real status codes and
// bodies — and return found / none / unknown per site. The client paginates batches so a
// single request never exceeds the platform's subrequest budget.

const CHECK_BATCH = 40;

function classifyCheck(spec, status, body) {
  const eCode = spec.e || 200;
  const es = spec.es, ms = spec.ms, mc = spec.mc;
  const has = s => s && body.includes(s);
  // Existence first: the expected code (plus the proof string, when the site provides one).
  if (status === eCode && (!es || has(es))) return 'found';
  // Explicit absence signals.
  if ((mc && status === mc) || has(ms)) return 'none';
  // A hard 404/410 with no contrary signal means the handle is free.
  if ((status === 404 || status === 410) && !es) return 'none';
  // If the site defines a proof string and we got the success code without it, it's taken by
  // something else / a soft page — treat as not found rather than a false positive.
  if (status === eCode && es) return 'none';
  return 'unknown';
}

async function checkOne(spec, username) {
  const target = String(spec.u || '').replace(/\{u\}/g, encodeURIComponent(username));
  let u;
  try { u = new URL(target); } catch { return { state: 'unknown', error: 'bad url' }; }
  if (u.protocol !== 'https:' || !safeHost(u.hostname)) return { state: 'unknown', error: 'blocked' };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 9000);
  try {
    const res = await fetch(u.href, {
      method: spec.rm || 'GET',
      redirect: 'manual',
      signal: ctrl.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; feddedosint/1.0)', Accept: 'text/html,application/json,*/*', ...(spec.h || {}) },
      ...(spec.pb ? { body: String(spec.pb).replace(/\{u\}/g, username) } : {}),
    });
    let body = '';
    if (spec.es || spec.ms) {
      const buf = new Uint8Array(await res.arrayBuffer());
      body = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, 96 * 1024));
    }
    return { state: classifyCheck(spec, res.status, body), status: res.status, url: u.href };
  } catch (e) {
    return { state: 'unknown', error: e.name === 'AbortError' ? 'timeout' : 'failed', url: u.href };
  } finally { clearTimeout(timer); }
}

async function handleCheck(request, env, user) {
  const g = gate(user, false);
  if (g) return err(GATE_MSG[g], g === 'auth' ? 401 : 403, request, env);
  if (!await rateLimit(env, `check:${user.login}`, 40, 60)) return err('rate limit reached — slow down', 429, request, env);
  const body = await request.json().catch(() => ({}));
  const username = String(body.username || '').trim();
  const sites = Array.isArray(body.sites) ? body.sites.slice(0, CHECK_BATCH) : [];
  if (!username || !sites.length) return err('username and sites[] required', 400, request, env);
  const results = await Promise.all(sites.map(s => checkOne(s, username).catch(() => ({ state: 'unknown', error: 'failed' }))));
  return json({ results }, 200, request, env);
}

async function handleFetch(request, env, user) {
  const g = gate(user, false);
  if (g) return err(GATE_MSG[g], g === 'auth' ? 401 : 403, request, env);
  if (!await rateLimit(env, `fetch:${user.login}`, 150, 60)) return err('rate limit reached', 429, request, env);
  const { url } = await request.json().catch(() => ({}));
  let u;
  try { u = new URL(url); } catch { return err('invalid url', 400, request, env); }
  if (!/^https?:$/.test(u.protocol)) return err('only http(s) urls allowed', 400, request, env);
  if (u.port && !['', '80', '443', '8080', '8443'].includes(u.port)) return err('port not allowed', 400, request, env);
  if (BLOCKED_HOST.test(u.hostname) || BLOCKED_IP.test(u.hostname)) return err('host not allowed', 400, request, env);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(u.href, { redirect: 'follow', signal: ctrl.signal, headers: { 'User-Agent': 'feddedosint/1.0', Accept: 'text/html,application/json,*/*' } });
    const buf = new Uint8Array(await res.arrayBuffer());
    const CAP = 512 * 1024;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, CAP));
    return json({ status: res.status, finalUrl: res.url, contentType: res.headers.get('content-type') || '', truncated: buf.length > CAP, body: text }, 200, request, env);
  } catch (e) {
    return err(e.name === 'AbortError' ? 'the site timed out' : 'fetch failed', 502, request, env);
  } finally { clearTimeout(timer); }
}

// ---------- router ----------

const ROUTES = {
  'GET /health': (req, env) => json({ ok: true, ai: !!env.GEMINI_KEY, model: env.AI_MODEL || 'gemini-2.5-flash', github: !!env.GITHUB_CLIENT_ID }, 200, req, env),
  'GET /auth/github/start': ghStart,
  'GET /auth/github/callback': ghCallback,
  'GET /auth/me': { auth: true, fn: (req, env, user) => json({ user: publicUser(user) }, 200, req, env) },
  'POST /auth/logout': { auth: true, fn: async (req, env, user) => { await env.USERS.delete(`session:${user.token}`); return json({ ok: true }, 200, req, env); } },
  'GET /admin/users': { auth: true, fn: adminUsers },
  'POST /admin/user': { auth: true, fn: adminSetUser },
  'POST /ai/chat': { open: true, fn: handleAI },
  'POST /ai/stream': { open: true, fn: handleAIStream },
  'POST /check': { open: true, fn: handleCheck },
  'POST /fetch': { open: true, fn: handleFetch },
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    const url = new URL(request.url);
    const route = ROUTES[`${request.method} ${url.pathname}`];
    if (!route) return err('not found', 404, request, env);
    try {
      if (typeof route === 'function') return await route(request, env);
      const user = await sessionUser(env, request);
      if (route.auth && !user) return err('authentication required', 401, request, env);
      return await route.fn(request, env, user);
    } catch {
      return err('server error', 500, request, env);
    }
  },
};
