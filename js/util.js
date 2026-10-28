// Shared helpers: DOM building, fetching, DNS-over-HTTPS and common UI blocks.

import { iconEl } from './icons.js';

// h('a', {href, class, onclick}, ...children) — children may be strings, nodes, arrays or null.
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export async function getJSON(url, { timeout = 15000, headers } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal, referrerPolicy: 'no-referrer' });
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    return { ok: res.ok, status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

export async function getText(url, { timeout = 15000, headers } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal, referrerPolicy: 'no-referrer' });
    return { ok: res.ok, status: res.status, text: await res.text().catch(() => '') };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- DNS over HTTPS ----------

const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

function unquoteTxt(s) {
  const parts = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : s;
}

export async function dns(name, type) {
  const q = `?name=${encodeURIComponent(name)}&type=${type}`;
  let r = null;
  try {
    r = await getJSON(`https://cloudflare-dns.com/dns-query${q}`, { headers: { accept: 'application/dns-json' } });
  } catch { /* fall through to Google */ }
  if (!r?.ok || !r.data) r = await getJSON(`https://dns.google/resolve${q}`);
  if (!r.ok || !r.data) throw new Error('DNS lookup failed');
  return (r.data.Answer || [])
    .filter(a => a.type === RR[type])
    .map(a => ({ ttl: a.TTL, data: type === 'TXT' ? unquoteTxt(a.data) : a.data.replace(/\.$/, '') }));
}

// ---------- RDAP (structured WHOIS) ----------

export function vcard(entity) {
  const out = {};
  for (const [name, , , value] of entity?.vcardArray?.[1] || []) {
    if (['fn', 'org', 'email', 'tel', 'adr'].includes(name) && value && !out[name]) {
      out[name] = Array.isArray(value) ? value.flat().filter(Boolean).join(', ') : String(value);
    }
  }
  return out;
}

// Depth-first search through nested RDAP entities for a role.
export function rdapEntity(entities, role) {
  for (const e of entities || []) {
    if (e.roles?.includes(role)) return e;
    const nested = rdapEntity(e.entities, role);
    if (nested) return nested;
  }
  return null;
}

export const rdapEvent = (data, action) => data.events?.find(e => e.eventAction === action)?.eventDate;

// ---------- validation / normalisation ----------

export function normDomain(input) {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  if (!/^[a-z]+:\/\//.test(s)) s = 'http://' + s;
  try {
    const host = new URL(s).hostname.replace(/\.$/, '');
    return /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/.test(host) && !isIP(host) ? host : null;
  } catch {
    return null;
  }
}

export const isIPv4 = s => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s);

export function expandIPv6(s) {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return null;
  // Embedded IPv4 tail (e.g. ::ffff:1.2.3.4) becomes two hex groups.
  const v4 = s.match(/:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    if (!isIPv4(v4[1])) return null;
    const o = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  if (s.includes('.')) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const full = [...head, ...Array(missing).fill('0'), ...tail];
  if (full.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return full.map(g => g.toLowerCase().padStart(4, '0')).join(':');
}

export const isIPv6 = s => expandIPv6(s) !== null;
export const isIP = s => isIPv4(s) || isIPv6(s);

export function reverseName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  return expandIPv6(ip).replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
}

export async function sha256(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function flag(cc) {
  if (!cc || !/^[a-z]{2}$/i.test(cc)) return '';
  return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1f1a5 + c.charCodeAt(0)));
}

export function countryName(cc) {
  try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(cc.toUpperCase()); } catch { return cc; }
}

export const fmtDate = d => {
  const t = new Date(d);
  return isNaN(t) ? String(d) : t.toISOString().slice(0, 10);
};

export const fmtNum = n => (typeof n === 'number' ? n.toLocaleString('en-US') : n);

// ---------- lazy script / style loading (pinned + SRI) ----------

const loaded = {};
export function loadScript(src, integrity) {
  loaded[src] ||= new Promise((resolve, reject) => {
    const s = h('script', { src, integrity, crossorigin: 'anonymous' });
    s.onload = resolve;
    s.onerror = () => { delete loaded[src]; reject(new Error('could not load ' + src)); };
    document.head.append(s);
  });
  return loaded[src];
}

export function loadStyle(href, integrity) {
  loaded[href] ||= new Promise((resolve, reject) => {
    const l = h('link', { rel: 'stylesheet', href, integrity, crossorigin: 'anonymous' });
    l.onload = resolve;
    l.onerror = () => { delete loaded[href]; reject(new Error('could not load ' + href)); };
    document.head.append(l);
  });
  return loaded[href];
}

// ---------- indicators ----------

// Defang / refang indicators of compromise, the way analysts share them safely.
export const defang = s => s.replace(/\./g, '[.]').replace(/:\/\//g, '[://]').replace(/^http/i, 'hxxp').replace(/@/g, '[@]');
export const refang = s => s
  .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
  .replace(/\[:\/\/\]|\(:\/\/\)|\[:\]\/\//g, '://')
  .replace(/\bhxxp/gi, 'http')
  .replace(/\[@\]|\(@\)|\[at\]|\(at\)/gi, '@');

// Approximate registrable domain (eTLD+1) without shipping the full public-suffix list.
const SECOND_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au',
  'edu.au', 'gov.au', 'co.nz', 'org.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'net.br', 'org.br', 'com.cn', 'net.cn', 'org.cn',
  'co.in', 'net.in', 'org.in', 'com.mx', 'com.tr', 'com.sg', 'com.hk', 'co.za', 'co.kr', 'com.ar', 'com.tw', 'co.il', 'com.my',
  'com.ph', 'com.pk', 'com.ng', 'com.eg', 'com.sa', 'co.id', 'co.th', 'com.vn', 'com.ua', 'com.pl', 'github.io', 'gitlab.io',
  'pages.dev', 'netlify.app', 'vercel.app', 'herokuapp.com', 'blogspot.com', 'appspot.com', 'web.app', 'firebaseapp.com']);
export function registrable(host) {
  const parts = host.toLowerCase().split('.');
  if (parts.length <= 2) return host.toLowerCase();
  const last2 = parts.slice(-2).join('.');
  return SECOND_LEVEL.has(last2) ? parts.slice(-3).join('.') : last2;
}

// ---------- UI blocks ----------

export function copyBtn(getText, label = 'copy') {
  const b = h('button', { class: 'mini', type: 'button' }, label);
  b.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(typeof getText === 'function' ? getText() : getText);
      b.textContent = 'copied';
    } catch {
      b.textContent = 'failed';
    }
    setTimeout(() => (b.textContent = label), 1200);
  });
  return b;
}

export const ext = (href, ...children) =>
  h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, ...(children.length ? children : [href]));

// Internal link that re-runs another tool on a value (pivoting).
// dataset lets the router record a graph edge from the current entity to this one.
export const pivot = (tool, value, label = value) =>
  h('a', {
    href: `#${tool}/${encodeURIComponent(value)}`, class: 'pivot', title: `${tool} lookup`,
    dataset: { pivotTool: tool, pivotValue: value },
  }, label);

// Small inline badge. tone: 'ok' | 'warn' | 'bad' | 'muted'
export const badge = (text, tone = 'muted') => h('span', { class: `badge ${tone}` }, text);

// Confidence / provenance marker shown next to a derived conclusion.
export const confidence = level => {
  const tone = { high: 'ok', medium: 'warn', low: 'bad' }[level] || 'muted';
  return badge(level + ' confidence', tone);
};

// A short note line used as a card caption.
export const note = text => h('p', { class: 'muted small' }, text);

// Every card can be collapsed by clicking its title.
export function card(title, { wide = false, actions, collapsed = false } = {}, ...body) {
  const el = h('article', { class: 'card' + (wide ? ' wide' : '') + (collapsed ? ' collapsed' : '') });
  const toggle = h('button', { class: 'cardtoggle', type: 'button', 'aria-expanded': String(!collapsed) },
    iconEl('chevron', 'chev'), h('span', {}, title));
  toggle.addEventListener('click', () => {
    const shut = el.classList.toggle('collapsed');
    toggle.setAttribute('aria-expanded', String(!shut));
  });
  el.append(
    h('header', {}, h('h3', {}, toggle), actions ? h('div', { class: 'actions' }, actions) : null),
    h('div', { class: 'body' }, ...body));
  return el;
}

// A card that shows a spinner until `fn()` resolves to its body content.
export function asyncCard(title, fn, opts = {}) {
  const body = h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'querying…');
  const el = card(title, opts, body);
  const slot = el.querySelector('.body');
  Promise.resolve()
    .then(fn)
    .then(content => { slot.replaceChildren(...[content].flat().filter(Boolean)); })
    .catch(err => {
      slot.replaceChildren(h('p', { class: 'muted' }, 'unavailable — ', err?.message || 'request failed',
        ' (the service may be down, rate-limited or blocking browser requests).'));
    });
  return el;
}

// Key/value table. Rows with empty values are dropped.
export function kv(rows) {
  const kept = rows.filter(r => r && r[1] != null && r[1] !== '' && !(Array.isArray(r[1]) && !r[1].length));
  if (!kept.length) return h('p', { class: 'muted' }, 'nothing found');
  return h('dl', { class: 'kv' }, kept.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
}

export const muted = text => h('p', { class: 'muted' }, text);

// A collapsed <details> holding the raw, unmodified API response — nothing hidden or reformatted away.
export function rawJSON(obj, label = 'raw response') {
  const text = (() => { try { return JSON.stringify(obj, null, 2); } catch { return String(obj); } })();
  const pre = h('pre', { class: 'json' }, text);
  return h('details', { class: 'rawbox' },
    h('summary', {}, label, ' ', copyBtn(text, 'copy')),
    pre);
}

// Grouped grid of external links: [{group, items: [[name, url], ...]}]
export function linkGroups(groups) {
  return groups.map(g => h('div', { class: 'linkgroup' },
    g.group ? h('h4', {}, g.group) : null,
    h('div', { class: 'links' }, g.items.map(([name, url]) => ext(url, name)))));
}

export function grid(...cards) {
  return h('div', { class: 'grid' }, ...cards);
}

// Minimal, safe Markdown → DOM. Builds nodes only (never innerHTML of model/page text),
// so nothing in the input can inject markup. Supports headings, bold, italic, inline
// code, links (http/https only), bullet and numbered lists, and paragraphs.
export function mdLite(src) {
  const root = h('div', { class: 'md' });
  const lines = String(src || '').replace(/\r/g, '').split('\n');
  let list = null, para = [];
  const flushPara = () => { if (para.length) { root.append(h('p', {}, ...inline(para.join(' ')))); para = []; } };
  const flushList = () => { if (list) { root.append(list.el); list = null; } };
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    let m;
    if (!line.trim()) { flushPara(); flushList(); continue; }
    if ((m = line.match(/^(#{1,4})\s+(.*)$/))) { flushPara(); flushList(); root.append(h('h' + (m[1].length + 2), {}, ...inline(m[2]))); continue; }
    if ((m = line.match(/^\s*[-*]\s+(.*)$/))) { flushPara(); if (!list || list.ord) { flushList(); list = { el: h('ul'), ord: false }; } list.el.append(h('li', {}, ...inline(m[1]))); continue; }
    if ((m = line.match(/^\s*\d+[.)]\s+(.*)$/))) { flushPara(); if (!list || !list.ord) { flushList(); list = { el: h('ol'), ord: true }; } list.el.append(h('li', {}, ...inline(m[1]))); continue; }
    flushList(); para.push(line.trim());
  }
  flushPara(); flushList();
  return root;
}

function inline(text) {
  const out = [];
  // tokens: `code`  **bold**  *italic*  [label](url)
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*|\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1] != null) out.push(h('code', {}, m[1]));
    else if (m[2] != null) out.push(h('strong', {}, m[2]));
    else if (m[3] != null) out.push(h('em', {}, m[3]));
    else if (m[4] != null) out.push(ext(m[5], m[4]));
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
