import worker from './worker.js';
import { createHmac } from 'node:crypto';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('FAIL:', m); } };

// --- in-memory KV stub ---
function makeKV() {
  const m = new Map();
  return {
    async get(k, t) { const e = m.get(k); if (!e || (e.exp && e.exp < Date.now())) { m.delete(k); return null; } return t === 'json' ? JSON.parse(e.v) : e.v; },
    async put(k, v, o) { m.set(k, { v, exp: o?.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }); },
    async delete(k) { m.delete(k); },
    async list({ prefix }) { return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) }; },
    _dump: m,
  };
}
const ORIGIN = 'https://feddedz.github.io';
const baseEnv = () => ({ USERS: makeKV(), ALLOWED_ORIGINS: ORIGIN, ADMIN_USER: 'owner', AI_MODEL: 'gemini-2.5-flash', GEMINI_KEY: 'SECRET-KEY-XYZ' });
const req = (method, path, body, token) => new Request('https://w.example.dev' + path, {
  method, headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});
const call = async (env, ...a) => { const r = await worker.fetch(req(...a), env); let d = null; try { d = await r.clone().json(); } catch {} return { status: r.status, data: d, cors: r.headers.get('Access-Control-Allow-Origin') }; };

// independent TOTP oracle (RFC 6238 SHA1 6-digit) from base32 secret
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function unb32(s){let bits=0,val=0;const o=[];for(const c of s.toUpperCase()){const i=B32.indexOf(c);if(i<0)continue;val=(val<<5)|i;bits+=5;if(bits>=8){o.push((val>>>(bits-8))&255);bits-=8;}}return Buffer.from(o);}
function totp(secretB32, t = Date.now()){const step=Math.floor(t/1000/30);const b=Buffer.alloc(8);b.writeUInt32BE(step,4);const mac=createHmac('sha1',unb32(secretB32)).update(b).digest();const off=mac[19]&0xf;const code=((mac[off]&0x7f)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3];return String(code%1e6).padStart(6,'0');}

// --- RFC 4226 HOTP vectors (secret ASCII "12345678901234567890") ---
{
  const secret = base32FromAscii('12345678901234567890');
  const expect = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let c = 0; c < 10; c++) ok(totp(secret, c * 30 * 1000 + 1000) === expect[c], `HOTP vector ${c}`);
}
function base32FromAscii(s){const bytes=Buffer.from(s,'ascii');let bits=0,val=0,out='';for(const b of bytes){val=(val<<8)|b;bits+=8;while(bits>=5){out+=B32[(val>>>(bits-5))&31];bits-=5;}}if(bits>0)out+=B32[(val<<(5-bits))&31];return out;}

// --- full auth flow ---
{
  const env = baseEnv();
  ok((await call(env, 'GET', '/health')).data.ai === true, 'health ai');
  // signup validation
  ok((await call(env, 'POST', '/auth/signup', { username: 'ab', password: 'longenough' })).status === 400, 'reject short username');
  ok((await call(env, 'POST', '/auth/signup', { username: 'alice', password: 'short' })).status === 400, 'reject short password');
  const su = await call(env, 'POST', '/auth/signup', { username: 'Alice', password: 'correcthorse' });
  ok(su.status === 200 && su.data.token, 'signup ok');
  ok(su.data.user.username === 'alice' && su.data.user.twofa === false && su.data.user.admin === false, 'signup user shape');
  ok(JSON.stringify(su.data).includes('correcthorse') === false && JSON.stringify(su.data).includes('hash') === false, 'no secret leaked in signup');
  ok((await call(env, 'POST', '/auth/signup', { username: 'alice', password: 'another12' })).status === 409, 'dup username');
  // me
  ok((await call(env, 'GET', '/auth/me', null, su.data.token)).data.user.username === 'alice', 'me');
  ok((await call(env, 'GET', '/auth/me', null, 'badtoken')).status === 401, 'me bad token');
  // wrong password
  ok((await call(env, 'POST', '/auth/login', { username: 'alice', password: 'wrong' })).status === 401, 'login wrong pw');
  const li = await call(env, 'POST', '/auth/login', { username: 'alice', password: 'correcthorse' });
  ok(li.status === 200 && li.data.token, 'login ok');
  // 2FA setup + enable
  const setup = await call(env, 'POST', '/auth/2fa/setup', null, su.data.token);
  ok(setup.data.secret && setup.data.uri.startsWith('otpauth://totp/'), '2fa setup');
  ok((await call(env, 'POST', '/auth/2fa/enable', { totp: '000000' }, su.data.token)).status === 400, 'enable rejects wrong code');
  const en = await call(env, 'POST', '/auth/2fa/enable', { totp: totp(setup.data.secret) }, su.data.token);
  ok(en.status === 200 && en.data.user.twofa === true, '2fa enabled');
  // login now needs totp
  const need = await call(env, 'POST', '/auth/login', { username: 'alice', password: 'correcthorse' });
  ok(need.status === 200 && need.data.need_totp === true && !need.data.token, 'login needs totp');
  ok((await call(env, 'POST', '/auth/login', { username: 'alice', password: 'correcthorse', totp: '111111' })).status === 401, 'login wrong totp');
  const full = await call(env, 'POST', '/auth/login', { username: 'alice', password: 'correcthorse', totp: totp(setup.data.secret) });
  ok(full.status === 200 && full.data.token, 'login with totp');
  // logout invalidates
  await call(env, 'POST', '/auth/logout', null, full.data.token);
  ok((await call(env, 'GET', '/auth/me', null, full.data.token)).status === 401, 'logout kills session');
}

// --- invite code ---
{
  const env = baseEnv(); env.SIGNUP_CODE = 'LETMEIN';
  ok((await call(env, 'POST', '/auth/signup', { username: 'bob', password: 'password1' })).status === 403, 'invite required');
  ok((await call(env, 'POST', '/auth/signup', { username: 'bob', password: 'password1', code: 'LETMEIN' })).status === 200, 'invite accepted');
}

// --- admin ---
{
  const env = baseEnv();
  const owner = await call(env, 'POST', '/auth/signup', { username: 'owner', password: 'ownerpass1' });
  ok(owner.data.user.admin === true, 'owner is admin');
  await call(env, 'POST', '/auth/signup', { username: 'user2', password: 'user2pass' });
  const list = await call(env, 'GET', '/admin/users', null, owner.data.token);
  ok(list.data.count === 2 && list.data.users.every(u => !('hash' in u) && !('salt' in u) && !('twofaSecret' in u)), 'admin list has no secrets');
  const u2login = await call(env, 'POST', '/auth/login', { username: 'user2', password: 'user2pass' });
  ok((await call(env, 'GET', '/admin/users', null, u2login.data.token)).status === 403, 'non-admin blocked');
}

// --- AI proxy: key stays server-side, rate limit ---
{
  const env = baseEnv();
  const owner = await call(env, 'POST', '/auth/signup', { username: 'owner', password: 'ownerpass1' });
  let captured = null;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    captured = { url: String(url), headers: opts.headers, body: JSON.parse(opts.body) };
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'hello from AI' }] }, finishReason: 'STOP' }], usageMetadata: { totalTokenCount: 5 } }), { status: 200 });
  };
  const anon = await call(env, 'POST', '/ai/chat', { prompt: 'hi' });
  ok(anon.status === 401, 'AI requires auth by default');
  const r = await call(env, 'POST', '/ai/chat', { prompt: 'hi', system: 'be brief' }, owner.data.token);
  ok(r.status === 200 && r.data.text === 'hello from AI', 'AI returns text');
  ok(captured.headers['x-goog-api-key'] === 'SECRET-KEY-XYZ', 'key sent upstream in header');
  ok(captured.url.includes('gemini-2.5-flash'), 'model in url');
  ok(captured.body.systemInstruction.parts[0].text === 'be brief', 'system instruction passed');
  ok(!JSON.stringify(r.data).includes('SECRET-KEY-XYZ'), 'key NOT in client response');
  // rate limit (limit 60/min for user) — hammer
  let limited = false;
  for (let i = 0; i < 65; i++) { const x = await call(env, 'POST', '/ai/chat', { prompt: 'x' }, owner.data.token); if (x.status === 429) { limited = true; break; } }
  ok(limited, 'AI rate limited');
  globalThis.fetch = realFetch;
}

// --- SSRF guard ---
{
  const env = baseEnv();
  const owner = await call(env, 'POST', '/auth/signup', { username: 'owner', password: 'ownerpass1' });
  for (const bad of ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'http://192.168.1.1/', 'http://localhost/', 'file:///etc/passwd', 'http://10.0.0.5:22/'])
    ok((await call(env, 'POST', '/fetch', { url: bad }, owner.data.token)).status === 400, 'SSRF blocks ' + bad);
}

// --- CORS ---
{
  const env = baseEnv();
  const pre = await worker.fetch(req('OPTIONS', '/auth/login'), env);
  ok(pre.status === 204 && pre.headers.get('Access-Control-Allow-Origin') === ORIGIN, 'preflight CORS');
  const other = new Request('https://w.example.dev/health', { headers: { Origin: 'https://evil.example' } });
  const r = await worker.fetch(other, env);
  ok(r.headers.get('Access-Control-Allow-Origin') !== 'https://evil.example', 'disallowed origin not reflected');
}

console.log(fail ? `\n${fail} FAILURES` : '\nALL WORKER TESTS PASSED');
process.exit(fail ? 1 : 0);
