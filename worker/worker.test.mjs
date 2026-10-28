// Logic tests for the Worker: GitHub OAuth, approval, pro gating, admin, CORS.
// Run: node worker.test.mjs   (Node 18+, needs global fetch/Request/Response/crypto)
import worker from './worker.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('FAIL:', m); } };

function makeKV() {
  const m = new Map();
  return {
    async get(k, t) { const e = m.get(k); if (!e || (e.exp && e.exp < Date.now())) { m.delete(k); return null; } return t === 'json' ? JSON.parse(e.v) : e.v; },
    async put(k, v, o) { m.set(k, { v, exp: o?.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }); },
    async delete(k) { m.delete(k); },
    async list({ prefix }) { return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) }; },
  };
}
const ORIGIN = 'https://feddedz.github.io';
const SITE = 'https://feddedz.github.io/feddedosint/';
const baseEnv = () => ({ USERS: makeKV(), ALLOWED_ORIGINS: ORIGIN, ADMIN_USER: 'feddedz', AI_MODEL: 'gemini-2.5-flash', GEMINI_KEY: 'SECRET-KEY', GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'csecret', SITE_URL: SITE });
const req = (method, path, body, token) => new Request('https://w.workers.dev' + path, {
  method, headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
  body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
});
const call = async (env, ...a) => { const r = await worker.fetch(req(...a), env); let d = null; try { d = await r.clone().json(); } catch {} return { status: r.status, data: d, loc: r.headers.get('Location'), cors: r.headers.get('Access-Control-Allow-Origin') }; };

// Stub GitHub + Gemini upstreams.
let STUB_LOGIN = 'alice';
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  url = String(url);
  if (url.includes('github.com/login/oauth/access_token')) return new Response(JSON.stringify({ access_token: 'gho_x' }), { status: 200 });
  if (url.includes('api.github.com/user')) return new Response(JSON.stringify({ login: STUB_LOGIN, name: STUB_LOGIN + ' Name', avatar_url: 'https://x/a.png' }), { status: 200 });
  if (url.includes('generativelanguage.googleapis.com')) return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'AI OK' }] } }], usageMetadata: {} }), { status: 200 });
  return realFetch(url, opts);
};

async function loginAs(env, login) {
  STUB_LOGIN = login;
  const start = await worker.fetch(req('GET', '/auth/github/start'), env);
  const state = new URL(start.headers.get('Location')).searchParams.get('state');
  const cb = await worker.fetch(req('GET', `/auth/github/callback?code=abc&state=${state}`), env);
  return decodeURIComponent((cb.headers.get('Location').match(/#auth=([^&]+)/) || [])[1] || '');
}

// --- health ---
{
  const env = baseEnv();
  const h = await call(env, 'GET', '/health');
  ok(h.data.ok && h.data.ai && h.data.github, 'health reports ai + github');
}

// --- OAuth start ---
{
  const env = baseEnv();
  const s = await worker.fetch(req('GET', '/auth/github/start'), env);
  const loc = s.headers.get('Location');
  ok(s.status === 302 && loc.startsWith('https://github.com/login/oauth/authorize'), 'start redirects to github');
  ok(/client_id=cid/.test(loc) && /scope=read%3Auser/.test(loc), 'start carries client_id + scope');
}

// --- new non-admin user is pending; admin is approved+pro ---
{
  const env = baseEnv();
  const tok = await loginAs(env, 'alice');
  ok(tok && tok !== 'undefined', 'callback issued a session token');
  const me = await call(env, 'GET', '/auth/me', null, tok);
  ok(me.data.user.login === 'alice' && me.data.user.status === 'pending' && me.data.user.pro === false && me.data.user.admin === false, 'new user pending, not pro');
  ok(!JSON.stringify(me.data).includes('access_token') && !JSON.stringify(me.data).includes('gho_'), 'no github token leaked');

  const adminTok = await loginAs(env, 'feddedz');
  const adminMe = await call(env, 'GET', '/auth/me', null, adminTok);
  ok(adminMe.data.user.admin && adminMe.data.user.status === 'approved' && adminMe.data.user.pro, 'admin auto approved + pro');
}

// --- callback rejects bad state ---
{
  const env = baseEnv();
  const cb = await worker.fetch(req('GET', '/auth/github/callback?code=x&state=forged'), env);
  ok(cb.headers.get('Location').includes('#auth=error:badstate'), 'bad state rejected');
}

// --- AI gating across states ---
{
  const env = baseEnv();
  const aliceTok = await loginAs(env, 'alice');          // pending
  ok((await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, aliceTok)).status === 403, 'pending user blocked from AI');
  ok((await call(env, 'POST', '/ai/chat', { prompt: 'hi' })).status === 401, 'anonymous blocked from AI');

  const adminTok = await loginAs(env, 'feddedz');
  // admin approves alice but not pro yet
  ok((await call(env, 'POST', '/admin/user', { login: 'alice', status: 'approved' }, adminTok)).status === 200, 'admin approves');
  ok((await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, aliceTok)).status === 403, 'approved non-pro still blocked from AI');
  // grant pro
  await call(env, 'POST', '/admin/user', { login: 'alice', pro: true }, adminTok);
  const aiOk = await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, aliceTok);
  ok(aiOk.status === 200 && aiOk.data.text === 'AI OK', 'approved + pro user can use AI');
  ok(!JSON.stringify(aiOk.data).includes('SECRET-KEY'), 'gemini key not in response');

  // admin always can
  ok((await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, adminTok)).status === 200, 'admin can use AI');
}

// --- admin controls ---
{
  const env = baseEnv();
  const adminTok = await loginAs(env, 'feddedz');
  const aliceTok = await loginAs(env, 'alice');
  const list = await call(env, 'GET', '/admin/users', null, adminTok);
  ok(list.data.count === 2 && list.data.users.every(u => !('token' in u)), 'admin lists users');
  ok((await call(env, 'GET', '/admin/users', null, aliceTok)).status === 403, 'non-admin cannot list');
  ok((await call(env, 'POST', '/admin/user', { login: 'feddedz', status: 'denied' }, adminTok)).status === 400, 'cannot modify admin account');
  // deny alice -> blocked even from fetch
  await call(env, 'POST', '/admin/user', { login: 'alice', status: 'denied' }, adminTok);
  ok((await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, aliceTok)).status === 403, 'denied user blocked');
}

// --- CORS ---
{
  const env = baseEnv();
  const pre = await worker.fetch(req('OPTIONS', '/ai/chat'), env);
  ok(pre.status === 204 && pre.headers.get('Access-Control-Allow-Origin') === ORIGIN, 'preflight CORS');
  const evil = new Request('https://w.workers.dev/health', { headers: { Origin: 'https://evil.example' } });
  ok((await worker.fetch(evil, env)).headers.get('Access-Control-Allow-Origin') !== 'https://evil.example', 'bad origin not reflected');
}

globalThis.fetch = realFetch;
console.log(fail ? `\n${fail} FAILURES` : '\nALL WORKER TESTS PASSED');
process.exit(fail ? 1 : 0);
