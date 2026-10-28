import './snow.js';
import { h } from './util.js';
import { icon } from './icons.js';
import { applyTheme, remember, recentFor, clearRecent, trackNode, trackEdge } from './store.js';

import overview from './tools/overview.js';
import username from './tools/username.js';
import email from './tools/email.js';
import phone from './tools/phone.js';
import breach from './tools/breach.js';
import domain from './tools/domain.js';
import ip from './tools/ip.js';
import asn from './tools/asn.js';
import crypto from './tools/crypto.js';
import image from './tools/image.js';
import cve from './tools/cve.js';
import records from './tools/records.js';
import dorks from './tools/dorks.js';
import utils from './tools/utils.js';
import graph from './tools/graph.js';
import settings from './tools/settings.js';
import { classify } from './tools/overview.js';

// Navigation is grouped so a large toolset stays easy to scan.
const GROUPS = [
  { label: '', tools: [overview] },
  { label: 'identity', tools: [username, email, phone, breach] },
  { label: 'network', tools: [domain, ip, asn] },
  { label: 'assets', tools: [crypto, image] },
  { label: 'threat', tools: [cve] },
  { label: 'research', tools: [records, dorks] },
  { label: 'tools', tools: [utils] },
  { label: '', tools: [graph, settings] },
];
const TOOLS = GROUPS.flatMap(g => g.tools);
const byId = Object.fromEntries(TOOLS.map(t => [t.id, t]));
// Tools whose empty state is itself useful (no query needed to be worth showing).
const SHOW_ON_IDLE = new Set(['image', 'dorks', 'breach', 'utils']);

const $ = s => document.querySelector(s);
const tabs = $('#tabs'), form = $('#search'), input = $('#q'), out = $('#out');
const hint = $('#hint'), recent = $('#recent'), panel = $('.panel');

let current = overview;
let currentValue = '';
let runId = 0;

applyTheme();

// ---------- recent searches ----------

function renderRecent() {
  const items = recentFor(current.id).slice(0, 6);
  recent.replaceChildren(...(items.length ? [
    h('span', { class: 'muted' }, 'recent'),
    ...items.map(r => h('a', { class: 'chip', href: `#${r.t}/${encodeURIComponent(r.q)}` }, r.q)),
    h('button', { class: 'mini ghost', type: 'button', onclick: () => { clearRecent(current.id); renderRecent(); } }, 'clear'),
  ] : []));
}

// ---------- input hint ----------

function updateHint() {
  const v = input.value.trim();
  if (!v || current.id === 'overview' || current.id === 'dorks' || current.noInput) return hint.replaceChildren();
  const types = classify(v).filter(t => t !== current.id && byId[t]);
  if (!types.length) return hint.replaceChildren();
  hint.replaceChildren(h('span', { class: 'muted' }, 'also: '),
    ...types.slice(0, 3).map(t => h('a', { href: `#${t}/${encodeURIComponent(v)}` }, byId[t].label)));
}

// ---------- routing ----------

function parseHash() {
  const raw = location.hash.slice(1);
  const i = raw.indexOf('/');
  const tool = byId[i < 0 ? raw : raw.slice(0, i)] || overview;
  let q = '';
  try { q = i < 0 ? '' : decodeURIComponent(raw.slice(i + 1)); } catch { q = raw.slice(i + 1); }
  return { tool, q, hasQuery: i >= 0 };
}

function select(tool) {
  current = tool;
  for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-selected', String(b.dataset.tool === tool.id));
  input.placeholder = tool.placeholder;
  panel.style.display = tool.noInput ? 'none' : '';
  document.title = `${tool.label} · feddedosint`;
  renderRecent();
}

function intro(tool) {
  return h('div', { class: 'intro' },
    tool.intro ? h('p', {}, tool.intro) : null,
    tool.examples?.length ? h('p', { class: 'examples' }, h('span', { class: 'muted' }, 'try '),
      ...tool.examples.map(e => h('a', { class: 'chip', href: `#${tool.id}/${encodeURIComponent(e)}` }, e))) : null);
}

async function run(tool, q, { idle = false } = {}) {
  const id = ++runId;
  currentValue = q;
  if (q) trackNode(tool.id, q);
  out.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'working…'));
  try {
    const result = await tool.run(q);
    if (id !== runId) return;
    out.replaceChildren(...(idle ? [intro(tool)] : []), ...[result].flat().filter(Boolean));
    if (q) remember(tool.id, q);
    renderRecent();
  } catch (e) {
    if (id !== runId) return;
    out.replaceChildren(h('p', { class: 'error' }, e?.message || String(e)), intro(tool));
  }
}

function route() {
  const { tool, q, hasQuery } = parseHash();
  select(tool);
  if (!tool.noInput && hasQuery) input.value = q;
  updateHint();
  if (tool.noInput) run(tool, '');
  else if (hasQuery && (q || tool.allowEmpty)) run(tool, q);
  else if (SHOW_ON_IDLE.has(tool.id)) run(tool, '', { idle: true });
  else { currentValue = ''; out.replaceChildren(intro(tool)); }
}

// ---------- graph edge tracking ----------
// Any internal link clicked inside a result draws an edge from the current entity.
out.addEventListener('click', e => {
  const a = e.target.closest('a[href^="#"]');
  if (!a || !currentValue) return;
  const raw = a.getAttribute('href').slice(1);
  const i = raw.indexOf('/');
  if (i < 0) return;
  const toTool = raw.slice(0, i);
  let toVal = '';
  try { toVal = decodeURIComponent(raw.slice(i + 1)); } catch { return; }
  if (byId[toTool] && toVal) trackEdge(current.id, currentValue, toTool, toVal);
});

// ---------- build nav ----------

for (const g of GROUPS) {
  const group = h('div', { class: 'navgroup' }, g.label ? h('span', { class: 'navlabel' }, g.label) : null);
  for (const t of g.tools) {
    const btn = h('button', { type: 'button', role: 'tab', dataset: { tool: t.id }, title: t.label });
    btn.innerHTML = icon(t.id) + `<span>${t.label}</span>`;
    btn.addEventListener('click', () => { location.hash = t.id; if (!t.noInput) input.focus(); });
    group.append(btn);
  }
  tabs.append(group);
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
    e.preventDefault(); input.focus(); input.select();
  }
});

route();
