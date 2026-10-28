// feddedosint backend — a single Cloudflare Worker.
//
// It does three jobs the static site cannot do on its own:
//   1. Hold the owner's Gemini API key as a secret and relay AI requests, so every
//      visitor uses that key without it ever reaching the browser.
//   2. Provide real accounts: signup / login, PBKDF2-hashed passwords (never stored
//      or returned in readable form), and TOTP 2FA (Authy / Google Authenticator).
//   3. Widen reach: a rate-limited, SSRF-guarded URL fetcher for OSINT lookups.
//
// Storage is a single KV namespace (binding: USERS) with key prefixes:
//   user:<name>  session:<token>  rl:<bucket>  pending2fa:<name>
//
// Config (wrangler.toml [vars] + secrets):
//   GEMINI_KEY       (secret)  the owner's Gemini API key
//   AI_MODEL         (var)     exact Gemini model id, e.g. "gemini-2.5-flash"
//   ALLOWED_ORIGINS  (var)     comma-separated, e.g. "https://feddedz.github.io"
//   ADMIN_USER       (var)     username allowed to list accounts
//   SIGNUP_CODE      (secret, optional)  if set, required to create an account
//   AI_REQUIRE_AUTH  (var)     "true" (default) = only logged-in users may use AI
//   SIGNUP_ENABLED   (var)     "true" (default) = allow new signups

const te = new TextEncoder();
const SESSION_TTL = 60 * 60 * 24 * 14;   // 14 days
const PBKDF2_ITERS = 210000;

// ---------- encoding helpers ----------

const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(bytes) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function unbase32(s) {
  s = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0, val = 0; const out = [];
  for (const c of s) {
    const idx = B32.indexOf(c);
    if (idx < 0) continue;
    val = (val << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

// Constant-time string compare.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- password hashing (PBKDF2-SHA256) ----------

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? fromB64url(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, key, 256);
  return { salt: b64url(salt), hash: b64url(bits) };
}
async function verifyPassword(password, record) {
  const { hash } = await hashPassword(password, record.salt);
  return timingSafeEqual(hash, record.hash);
}

// ---------- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ----------

async function hotp(secretBytes, counter) {
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(4, counter >>> 0);
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = mac[mac.length - 1] & 0xf;
  const code = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(code % 1_000_000).padStart(6, '0');
}
async function verifyTOTP(secretB32, token, window = 1) {
  token = String(token || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(token)) return false;
  const secret = unbase32(secretB32);
  const step = Math.floor(Date.now() / 1000 / 30);
  for (let w = -window; w <= window; w++) {
    if (timingSafeEqual(await hotp(secret, step + w), token)) return true;
  }
  return false;
}

// ---------- HTTP helpers ----------

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
  status: status || 200,
  headers: { 'Content-Type': 'application/json', ...corsHeaders(request, env) },
});
const err = (msg, status, request, env) => json({ error: msg }, status || 400, request, env);

// ---------- rate limiting (best-effort, KV) ----------

async function rateLimit(env, bucket, limit, windowSec) {
  const key = `rl:${bucket}:${Math.floor(Date.now() / 1000 / windowSec)}`;
  const n = Number(await env.USERS.get(key)) || 0;
  if (n >= limit) return false;
  await env.USERS.put(key, String(n + 1), { expirationTtl: windowSec + 5 });
  return true;
}
const clientIP = request => request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

// ---------- sessions ----------

async function createSession(env, username) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  await env.USERS.put(`session:${token}`, JSON.stringify({ username, created: Date.now() }), { expirationTtl: SESSION_TTL });
  return token;
}
async function sessionUser(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  const s = await env.USERS.get(`session:${token}`, 'json');
  if (!s) return null;
  const user = await env.USERS.get(`user:${s.username}`, 'json');
  return user ? { ...user, token } : null;
}

const validName = s => typeof s === 'string' && /^[a-z0-9][a-z0-9._-]{2,31}$/i.test(s);
const publicUser = u => ({ username: u.username, created: u.created, twofa: !!u.twofaEnabled, admin: !!u.admin, lastLogin: u.lastLogin || null });

// ---------- auth handlers ----------

async function handleSignup(request, env) {
  if ((env.SIGNUP_ENABLED ?? 'true') !== 'true') return err('signups are disabled', 403, request, env);
  if (!await rateLimit(env, `signup:${clientIP(request)}`, 5, 3600)) return err('too many signups from this address — try later', 429, request, env);
  const { username, password, code } = await request.json().catch(() => ({}));
  if (env.SIGNUP_CODE && code !== env.SIGNUP_CODE) return err('invalid or missing invite code', 403, request, env);
  if (!validName(username)) return err('username must be 3–32 chars: letters, digits, . _ -', 400, request, env);
  if (typeof password !== 'string' || password.length < 8) return err('password must be at least 8 characters', 400, request, env);
  if (await env.USERS.get(`user:${username.toLowerCase()}`)) return err('that username is taken', 409, request, env);
  const { salt, hash } = await hashPassword(password);
  const user = { username: username.toLowerCase(), salt, hash, created: Date.now(), admin: username.toLowerCase() === (env.ADMIN_USER || '').toLowerCase() };
  await env.USERS.put(`user:${user.username}`, JSON.stringify(user));
  const token = await createSession(env, user.username);
  return json({ token, user: publicUser(user) }, 200, request, env);
}

async function handleLogin(request, env) {
  if (!await rateLimit(env, `login:${clientIP(request)}`, 10, 300)) return err('too many attempts — wait a few minutes', 429, request, env);
  const { username, password, totp } = await request.json().catch(() => ({}));
  const user = validName(username) ? await env.USERS.get(`user:${username.toLowerCase()}`, 'json') : null;
  // Always run a hash to blunt username enumeration via timing.
  const ok = user ? await verifyPassword(password || '', user) : await hashPassword(password || '').then(() => false);
  if (!user || !ok) return err('wrong username or password', 401, request, env);
  if (user.twofaEnabled) {
    if (!totp) return json({ need_totp: true }, 200, request, env);
    if (!await verifyTOTP(user.twofaSecret, totp)) return err('invalid 2FA code', 401, request, env);
  }
  user.lastLogin = Date.now();
  await env.USERS.put(`user:${user.username}`, JSON.stringify(user));
  const token = await createSession(env, user.username);
  return json({ token, user: publicUser(user) }, 200, request, env);
}

async function handleLogout(request, env, user) {
  await env.USERS.delete(`session:${user.token}`);
  return json({ ok: true }, 200, request, env);
}

async function handle2faSetup(request, env, user) {
  const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
  await env.USERS.put(`pending2fa:${user.username}`, secret, { expirationTtl: 600 });
  const issuer = 'feddedosint';
  const uri = `otpauth://totp/${issuer}:${encodeURIComponent(user.username)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  return json({ secret, uri }, 200, request, env);
}

async function handle2faEnable(request, env, user) {
  const { totp } = await request.json().catch(() => ({}));
  const secret = await env.USERS.get(`pending2fa:${user.username}`);
  if (!secret) return err('no pending 2FA setup — start again', 400, request, env);
  if (!await verifyTOTP(secret, totp)) return err('that code did not match — check your authenticator', 400, request, env);
  user.twofaEnabled = true;
  user.twofaSecret = secret;
  await env.USERS.put(`user:${user.username}`, JSON.stringify(user));
  await env.USERS.delete(`pending2fa:${user.username}`);
  return json({ ok: true, user: publicUser(user) }, 200, request, env);
}

async function handle2faDisable(request, env, user) {
  const { password, totp } = await request.json().catch(() => ({}));
  if (!await verifyPassword(password || '', user)) return err('wrong password', 401, request, env);
  if (user.twofaEnabled && !await verifyTOTP(user.twofaSecret, totp)) return err('invalid 2FA code', 401, request, env);
  delete user.twofaEnabled; delete user.twofaSecret;
  await env.USERS.put(`user:${user.username}`, JSON.stringify(user));
  return json({ ok: true, user: publicUser(user) }, 200, request, env);
}

async function handleAdminUsers(request, env, user) {
  if (!user.admin) return err('admin only', 403, request, env);
  const list = await env.USERS.list({ prefix: 'user:' });
  const users = [];
  for (const k of list.keys) {
    const u = await env.USERS.get(k.name, 'json');
    if (u) users.push(publicUser(u));
  }
  users.sort((a, b) => b.created - a.created);
  return json({ count: users.length, users }, 200, request, env);
}

// ---------- AI proxy (Gemini) ----------

async function handleAI(request, env, user) {
  if ((env.AI_REQUIRE_AUTH ?? 'true') === 'true' && !user) return err('sign in to use the AI', 401, request, env);
  const bucket = user ? `ai:user:${user.username}` : `ai:ip:${clientIP(request)}`;
  if (!await rateLimit(env, bucket, user ? 60 : 15, 60)) return err('AI rate limit reached — wait a minute', 429, request, env);
  if (!env.GEMINI_KEY) return err('the AI backend is not configured (no key set)', 503, request, env);

  const body = await request.json().catch(() => ({}));
  const model = env.AI_MODEL || 'gemini-2.5-flash';
  const payload = {
    contents: Array.isArray(body.contents) ? body.contents : [{ role: 'user', parts: [{ text: String(body.prompt || '') }] }],
    generationConfig: {
      temperature: body.temperature ?? 0.4,
      maxOutputTokens: Math.min(body.maxOutputTokens || 2048, 8192),
      ...(body.json ? { responseMimeType: 'application/json' } : {}),
    },
    ...(body.system ? { systemInstruction: { parts: [{ text: String(body.system) }] } } : {}),
  };
  const upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_KEY },
    body: JSON.stringify(payload),
  }).catch(() => null);
  if (!upstream) return err('could not reach the AI service', 502, request, env);
  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) return json({ error: data?.error?.message || `AI error ${upstream.status}`, status: upstream.status }, 200, request, env);
  const text = (data.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('');
  return json({ text, finishReason: data.candidates?.[0]?.finishReason, usage: data.usageMetadata, model }, 200, request, env);
}

// ---------- SSRF-guarded URL fetch ----------

const BLOCKED_HOST = /^(localhost|.*\.local|.*\.internal|metadata.*)$/i;
const BLOCKED_IP = /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1|fe80|fc|fd)/i;

async function handleFetch(request, env, user) {
  if (!user) return err('sign in to use the fetcher', 401, request, env);
  if (!await rateLimit(env, `fetch:user:${user.username}`, 40, 60)) return err('fetch rate limit reached', 429, request, env);
  const { url } = await request.json().catch(() => ({}));
  let u;
  try { u = new URL(url); } catch { return err('invalid url', 400, request, env); }
  if (!/^https?:$/.test(u.protocol)) return err('only http(s) urls are allowed', 400, request, env);
  if (u.port && !['', '80', '443', '8080', '8443'].includes(u.port)) return err('port not allowed', 400, request, env);
  if (BLOCKED_HOST.test(u.hostname) || BLOCKED_IP.test(u.hostname)) return err('that host is not allowed', 400, request, env);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(u.href, {
      redirect: 'follow', signal: ctrl.signal,
      headers: { 'User-Agent': 'feddedosint/1.0 (+https://github.com/feddedz/feddedosint)', Accept: 'text/html,application/json,*/*' },
      cf: { cacheTtl: 60 },
    });
    const reader = res.body?.getReader();
    const chunks = []; let size = 0;
    const CAP = 512 * 1024;
    if (reader) for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > CAP) { chunks.push(value.subarray(0, value.length - (size - CAP))); break; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let off = 0; for (const c of chunks) { bytes.set(c, off); off += c.length; }
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return json({ status: res.status, finalUrl: res.url, contentType: res.headers.get('content-type') || '', truncated: size > CAP, body: text }, 200, request, env);
  } catch (e) {
    return err(e.name === 'AbortError' ? 'the site timed out' : 'fetch failed', 502, request, env);
  } finally {
    clearTimeout(timer);
  }
}

// ---------- router ----------

const ROUTES = {
  'GET /health': (req, env) => json({ ok: true, ai: !!env.GEMINI_KEY, model: env.AI_MODEL || 'gemini-2.5-flash', signup: (env.SIGNUP_ENABLED ?? 'true') === 'true', inviteRequired: !!env.SIGNUP_CODE }, 200, req, env),
  'POST /auth/signup': handleSignup,
  'POST /auth/login': handleLogin,
  'POST /auth/logout': { auth: true, fn: handleLogout },
  'GET /auth/me': { auth: true, fn: (req, env, user) => json({ user: publicUser(user) }, 200, req, env) },
  'POST /auth/2fa/setup': { auth: true, fn: handle2faSetup },
  'POST /auth/2fa/enable': { auth: true, fn: handle2faEnable },
  'POST /auth/2fa/disable': { auth: true, fn: handle2faDisable },
  'GET /admin/users': { auth: true, fn: handleAdminUsers },
  'POST /ai/chat': { auth: false, fn: handleAI },
  'POST /fetch': { auth: true, fn: handleFetch },
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    const url = new URL(request.url);
    const route = ROUTES[`${request.method} ${url.pathname}`];
    if (!route) return err('not found', 404, request, env);
    try {
      if (typeof route === 'function') return await route(request, env);
      let user = null;
      if (route.auth || route.fn === handleAI) user = await sessionUser(env, request);
      if (route.auth && !user) return err('authentication required', 401, request, env);
      return await route.fn(request, env, user);
    } catch (e) {
      return err('server error', 500, request, env);
    }
  },
};
