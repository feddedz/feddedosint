import { h, card, kv, copyBtn, muted, badge } from '../util.js';

const rot13 = s => s.replace(/[a-z]/gi, c => {
  const base = c <= 'Z' ? 65 : 97;
  return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
});

// Everything here runs fully offline in the browser — nothing is sent anywhere.

const td = new TextEncoder(), fromB = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function hash(algo, text) {
  return toHex(await crypto.subtle.digest(algo, td.encode(text)));
}

function b64(text, dir) {
  try {
    return dir === 'encode'
      ? btoa(String.fromCharCode(...td.encode(text)))
      : new TextDecoder().decode(fromB(text.trim().replace(/\s+/g, '')));
  } catch { return '— invalid input —'; }
}

function decodeJWT(token) {
  const parts = token.trim().split('.');
  if (parts.length < 2) return null;
  const dec = p => JSON.parse(new TextDecoder().decode(fromB(p.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(p.length / 4) * 4, '='))));
  try { return { header: dec(parts[0]), payload: dec(parts[1]) }; } catch { return null; }
}

// Defang / refang indicators of compromise, the way analysts share them safely.
const defang = s => s.replace(/\./g, '[.]').replace(/:\/\//g, '[://]').replace(/^http/i, 'hxxp').replace(/@/g, '[@]');
const refang = s => s.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\/\/\]|\(:\/\/\)/g, '://').replace(/hxxp/gi, 'http').replace(/\[@\]|\(@\)/g, '@');

function result(label, value) {
  const out = h('code', { class: 'query wrap' }, value || '—');
  return h('div', { class: 'util-out' }, h('div', { class: 'util-head' }, h('span', { class: 'muted' }, label), copyBtn(() => value, 'copy')), out);
}

export default {
  id: 'utils',
  label: 'decoders',
  placeholder: 'paste text, a token, a timestamp or an indicator',
  intro: 'Offline encoders, hashes, timestamp and JWT decoders, and IOC defang/refang — nothing you paste leaves the browser.',
  examples: [],
  allowEmpty: true,

  async run(raw) {
    const text = raw;
    const out = h('div', { class: 'grid' });

    const render = async () => {
      const t = text;
      const cards = [];

      // --- encodings ---
      cards.push(card('base64', {}, result('encode', b64(t, 'encode')), result('decode', b64(t, 'decode'))));
      cards.push(card('url', {}, result('encode', encodeURIComponent(t)),
        result('decode', (() => { try { return decodeURIComponent(t); } catch { return '— invalid —'; } })())));
      cards.push(card('hex / binary', {},
        result('to hex', [...td.encode(t)].map(b => b.toString(16).padStart(2, '0')).join(' ')),
        result('to binary', [...td.encode(t)].map(b => b.toString(2).padStart(8, '0')).join(' '))));
      cards.push(card('case & reverse', {},
        result('UPPER', t.toUpperCase()), result('lower', t.toLowerCase()),
        result('reversed', [...t].reverse().join('')), result('rot13', rot13(t))));

      // --- hashes ---
      const [s1, s256, s384, s512] = await Promise.all(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].map(a => hash(a, t)));
      cards.push(card('hashes', { wide: true }, kv([
        ['sha-1', h('code', { class: 'wrap small' }, s1)], ['sha-256', h('code', { class: 'wrap small' }, s256)],
        ['sha-384', h('code', { class: 'wrap small' }, s384)], ['sha-512', h('code', { class: 'wrap small' }, s512)],
      ])));

      // --- IOC defang ---
      cards.push(card('indicators (ioc)', {}, result('defang (safe to share)', defang(t)), result('refang', refang(t))));

      // --- timestamp ---
      cards.push(card('timestamp', {}, (() => {
        const n = Number(t.trim());
        const rows = [];
        if (Number.isFinite(n) && t.trim() !== '') {
          const ms = n > 1e12 ? n : n * 1000;
          const d = new Date(ms);
          if (!isNaN(d)) rows.push(['as date (utc)', d.toISOString()], ['as date (local)', d.toString().replace(/ \(.*\)$/, '')]);
        }
        const parsed = Date.parse(t);
        if (!isNaN(parsed)) rows.push(['→ unix (s)', Math.floor(parsed / 1000)], ['→ unix (ms)', parsed]);
        rows.push(['now (unix s)', Math.floor(Date.now() / 1000)]);
        return kv(rows);
      })()));

      // --- JWT ---
      const jwt = decodeJWT(t);
      if (jwt) cards.push(card('jwt', { wide: true },
        note('Decoded locally. The signature is NOT verified — never trust a token by its contents alone.'),
        kv([['header', h('pre', { class: 'json' }, JSON.stringify(jwt.header, null, 2))],
          ['payload', h('pre', { class: 'json' }, JSON.stringify(jwt.payload, null, 2))],
          jwt.payload.exp ? ['expires', new Date(jwt.payload.exp * 1000).toISOString() + (jwt.payload.exp * 1000 < Date.now() ? '  ⚠ expired' : '')] : null,
        ])));

      out.replaceChildren(...cards);
    };

    if (text.trim()) await render();
    else out.replaceChildren(card('offline toolkit', { wide: true },
      muted('Paste anything above to get base64 / url / hex / binary, SHA hashes, case & rot13, IOC defang/refang, timestamp conversion and JWT decoding — all computed in your browser.'),
      h('div', { class: 'tags' }, ['base64', 'url', 'hex', 'binary', 'rot13', 'sha-1/256/384/512', 'defang ioc', 'unix time', 'jwt'].map(x => badge(x)))));

    return out;
  },
};

const note = t => h('p', { class: 'muted small' }, t);
