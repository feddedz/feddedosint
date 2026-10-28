import './snow.js';
import { h, isIP, normDomain } from './util.js';
import username from './tools/username.js';
import domain from './tools/domain.js';
import ip from './tools/ip.js';
import email from './tools/email.js';
import phone from './tools/phone.js';
import image from './tools/image.js';
import dorks from './tools/dorks.js';

const TOOLS = [username, domain, ip, email, phone, image, dorks];
const byId = Object.fromEntries(TOOLS.map(t => [t.id, t]));
// Tools whose empty state is itself useful (drop zone, query builder).
const SHOW_ON_IDLE = new Set(['image', 'dorks']);

const $ = s => document.querySelector(s);
const tabs = $('#tabs'), form = $('#search'), input = $('#q'), out = $('#out');
const hint = $('#hint'), recent = $('#recent');

let current = TOOLS[0];
let runId = 0;

// ---------- recent searches (per-browser convenience only) ----------

const KEY = 'feddedosint.recent';
const loadRecent = () => { try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch { return []; } };
const saveRecent = list => { try { localStorage.setItem(KEY, JSON.stringify(list)); } catch { /* storage blocked */ } };

function remember(t, q) {
  saveRecent([{ t, q }, ...loadRecent().filter(r => !(r.t === t && r.q === q))].slice(0, 40));
  renderRecent();
}

function renderRecent() {
  const items = loadRecent().filter(r => r.t === current.id).slice(0, 6);
  recent.replaceChildren(...(items.length ? [
    h('span', { class: 'muted' }, 'recent'),
    ...items.map(r => h('a', { class: 'chip', href: `#${r.t}/${encodeURIComponent(r.q)}` }, r.q)),
    h('button', { class: 'mini ghost', type: 'button', onclick: () => {
      saveRecent(loadRecent().filter(r => r.t !== current.id));
      renderRecent();
    } }, 'clear'),
  ] : []));
}

// ---------- input type detection ----------

function detect(v) {
  v = v.trim();
  if (!v) return null;
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) return 'email';
  if (isIP(v.replace(/^\[|\]$/g, ''))) return 'ip';
  if (/^\+?[\d\s().-]{7,}$/.test(v) && v.replace(/\D/g, '').length >= 7) return 'phone';
  if (/^https?:\/\/\S+\.(jpe?g|png|gif|webp|heic|tiff?)(\?.*)?$/i.test(v)) return 'image';
  if (/^https?:\/\//i.test(v) || (/\.[a-z]{2,}$/i.test(v) && normDomain(v))) return 'domain';
  return null;
}

function updateHint() {
  const type = detect(input.value);
  if (!type || type === current.id || current.id === 'dorks') return hint.replaceChildren();
  // a dotted handle like "john.doe" is still a plausible username
  if (current.id === 'username' && type === 'domain' && !/^https?:/i.test(input.value)) return hint.replaceChildren();
  hint.replaceChildren('looks like ', type === 'ip' ? 'an ip' : type === 'email' ? 'an email' : `a ${type}`, ' → ',
    h('a', { href: `#${type}/${encodeURIComponent(input.value.trim())}` }, `search ${byId[type].label}`));
}

// ---------- routing ----------

function parseHash() {
  const raw = location.hash.slice(1);
  const i = raw.indexOf('/');
  const tool = byId[i < 0 ? raw : raw.slice(0, i)] || TOOLS[0];
  let q = '';
  try { q = i < 0 ? '' : decodeURIComponent(raw.slice(i + 1)); } catch { q = raw.slice(i + 1); }
  return { tool, q, hasQuery: i >= 0 };
}

function select(tool) {
  current = tool;
  for (const b of tabs.children) b.setAttribute('aria-selected', String(b.dataset.tool === tool.id));
  input.placeholder = tool.placeholder;
  document.title = `${tool.label} · feddedosint`;
  renderRecent();
}

function intro(tool) {
  return h('div', { class: 'intro' },
    h('p', {}, tool.intro),
    tool.examples.length ? h('p', { class: 'examples' }, h('span', { class: 'muted' }, 'try '),
      tool.examples.map(e => h('a', { class: 'chip', href: `#${tool.id}/${encodeURIComponent(e)}` }, e))) : null);
}

async function run(tool, q, { idle = false } = {}) {
  const id = ++runId;
  out.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'working…'));
  try {
    const result = await tool.run(q);
    if (id !== runId) return;
    out.replaceChildren(...(idle ? [intro(tool)] : []), ...[result].flat().filter(Boolean));
    if (q) remember(tool.id, q);
  } catch (e) {
    if (id !== runId) return;
    out.replaceChildren(h('p', { class: 'error' }, e?.message || String(e)), intro(tool));
  }
}

function route() {
  const { tool, q, hasQuery } = parseHash();
  select(tool);
  if (hasQuery) input.value = q;
  updateHint();
  if (hasQuery && (q || tool.allowEmpty)) run(tool, q);
  else if (SHOW_ON_IDLE.has(tool.id)) run(tool, '', { idle: true });
  else out.replaceChildren(intro(tool));
}

// ---------- wiring ----------

for (const t of TOOLS) {
  tabs.append(h('button', {
    type: 'button', role: 'tab', dataset: { tool: t.id },
    onclick: () => { location.hash = t.id; input.focus(); },
  }, t.label));
}

form.addEventListener('submit', e => {
  e.preventDefault();
  const target = `#${current.id}/${encodeURIComponent(input.value.trim())}`;
  if (location.hash === target) route();
  else location.hash = target;
});

input.addEventListener('input', updateHint);
addEventListener('hashchange', route);
addEventListener('keydown', e => {
  if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) {
    e.preventDefault();
    input.focus();
    input.select();
  }
});

route();
