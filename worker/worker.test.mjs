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
let OVERLOADED = new Set();
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  url = String(url);
  if (url.includes('github.com/login/oauth/access_token')) return new Response(JSON.stringify({ access_token: 'gho_x' }), { status: 200 });
  if (url.includes('api.github.com/user')) return new Response(JSON.stringify({ login: STUB_LOGIN, name: STUB_LOGIN + ' Name', avatar_url: 'https://x/a.png' }), { status: 200 });
  if (url.includes('streamGenerateContent')) {
    const m = url.match(/models\/([^:]+):/)?.[1] || '';
    if (OVERLOADED.has(m)) return new Response(JSON.stringify({ error: { message: 'high demand' } }), { status: 503 });
    return new Response('data: {"candidates":[{"content":{"parts":[{"text":"reasoning here","thought":true}]}}]}\n\ndata: {"candidates":[{"content":{"parts":[{"text":"Hi there"}]}}]}\n\n', { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }
  if (url.includes('scan.test/')) {
    // Fake sites for the deep-scan (/check) tests.
    if (url.includes('/found/')) return new Response('<html>PROOF profile exists</html>', { status: 200 });
    if (url.includes('/proofmiss/')) return new Response('<html>some soft landing page</html>', { status: 200 });
    if (url.includes('/gone/')) return new Response('nope', { status: 404 });
    if (url.includes('/codeonly/')) return new Response('whatever', { status: 200 });
    return new Response('x', { status: 500 });
  }
  if (url.includes('generativelanguage.googleapis.com')) {
    const m = url.match(/models\/([^:]+):/)?.[1] || '';
    if (OVERLOADED.has(m)) return new Response(JSON.stringify({ error: { message: 'This model is currently experiencing high demand.' } }), { status: 503 });
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'AI OK' }] } }], usageMetadata: {} }), { status: 200 });
  }
  if (url.includes('favicon.test/favicon.ico')) return new Response(new Uint8Array([1,2,3,4,5]).buffer, { status: 200, headers: { 'content-type': 'image/x-icon' } });
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

// --- BESTMODEL fallback ---
{
  const env = baseEnv(); env.AI_MODEL = 'BESTMODEL';
  const adminTok = await loginAs(env, 'feddedz');
  OVERLOADED = new Set(['gemini-3.8-flash', 'gemini-3.7-flash']);
  const r = await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, adminTok);
  ok(r.status === 200 && r.data.text === 'AI OK', 'BESTMODEL falls back to a working model');
  ok(r.data.model === 'gemini-3.6-flash', 'BESTMODEL picked the next available model (' + r.data.model + ')');
  OVERLOADED = new Set(['gemini-3.8-flash', 'gemini-3.7-flash', 'gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-2.5-flash', 'gemini-flash-latest', 'gemini-2.5-flash-lite']);
  const all = await call(env, 'POST', '/ai/chat', { prompt: 'hi' }, adminTok);
  ok(all.data.error && /all models are busy/i.test(all.data.error), 'BESTMODEL reports when everything is busy');
  OVERLOADED = new Set();
}

// --- streaming ---
{
  const env = baseEnv();
  const adminTok = await loginAs(env, 'feddedz');
  const r = await worker.fetch(req('POST', '/ai/stream', { prompt: 'hi' }, adminTok), env);
  ok(r.status === 200 && (r.headers.get('content-type') || '').includes('text/event-stream'), 'stream returns SSE');
  ok(!!r.headers.get('x-model'), 'stream reports model');
  const text = await r.text();
  ok(text.includes('thought') && text.includes('Hi there'), 'stream passes SSE body through (thoughts + answer)');
  const aliceTok = await loginAs(env, 'alice');
  ok((await worker.fetch(req('POST', '/ai/stream', { prompt: 'hi' }, aliceTok), env)).status === 403, 'stream gated for pending user');
}

// --- streaming BESTMODEL fallback ---
{
  const env = baseEnv(); env.AI_MODEL = 'BESTMODEL';
  const adminTok = await loginAs(env, 'feddedz');
  OVERLOADED = new Set(['gemini-3.8-flash']);
  const r = await worker.fetch(req('POST', '/ai/stream', { prompt: 'hi' }, adminTok), env);
  ok(r.status === 200 && r.headers.get('x-model') === 'gemini-3.7-flash', 'stream falls back past an overloaded model (' + r.headers.get('x-model') + ')');
  OVERLOADED = new Set();
}

// --- deep scan (/check) ---
{
  const env = baseEnv();
  const adminTok = await loginAs(env, 'feddedz');
  const sites = [
    { n: 'Found', u: 'https://scan.test/found/{u}', es: 'PROOF' },
    { n: 'ProofMiss', u: 'https://scan.test/proofmiss/{u}', es: 'PROOF' },   // 200 but no proof -> none
    { n: 'Gone', u: 'https://scan.test/gone/{u}', mc: 404 },
    { n: 'CodeOnly', u: 'https://scan.test/codeonly/{u}' },                   // 200, no proof string -> found
    { n: 'Blocked', u: 'http://localhost/{u}' },                             // SSRF guard -> unknown
  ];
  const r = await call(env, 'POST', '/check', { username: 'bob', sites }, adminTok);
  ok(r.status === 200 && Array.isArray(r.data.results), 'check returns results array');
  const st = r.data.results.map(x => x.state);
  ok(st[0] === 'found', 'proof string present -> found');
  ok(st[1] === 'none', 'success code without proof string -> none');
  ok(st[2] === 'none', 'missing code -> none');
  ok(st[3] === 'found', 'bare success code -> found');
  ok(st[4] === 'unknown' && r.data.results[4].error === 'blocked', 'SSRF-blocked host -> unknown');

  const aliceTok = await loginAs(env, 'alice'); // pending
  ok((await call(env, 'POST', '/check', { username: 'bob', sites }, aliceTok)).status === 403, 'check gated for pending user');
  ok((await call(env, 'POST', '/check', {}, adminTok)).status === 400, 'check needs username + sites');
}

// --- /fetch byte mode (favicon) ---
{
  const env = baseEnv();
  const adminTok = await loginAs(env, 'feddedz');
  const r = await call(env, 'POST', '/fetch', { url: 'https://favicon.test/favicon.ico', bytes: true }, adminTok);
  ok(r.status === 200 && r.data.b64 === btoa(String.fromCharCode(1,2,3,4,5)), 'fetch byte mode returns base64 of raw bytes');
  const r2 = await call(env, 'POST', '/fetch', { url: 'http://localhost/favicon.ico', bytes: true }, adminTok);
  ok(r2.status === 400, 'fetch byte mode still SSRF-guarded');
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
