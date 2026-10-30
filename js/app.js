import './snow.js';
import { h } from './util.js';
import { icon, iconEl } from './icons.js';
import {
  applyTheme, remember, recentFor, recentAll, clearRecent, trackNode, trackEdge, settings, setSetting,
} from './store.js';
import * as be from './backend.js';
import { lockReason, renderLock } from './lock.js';

import overview, { classify } from './tools/overview.js';
import username from './tools/username.js';
import ogu from './tools/ogu.js';
import email from './tools/email.js';
import phone from './tools/phone.js';
import breach from './tools/breach.js';
import domain from './tools/domain.js';
import recon from './tools/recon.js';
import monitor from './tools/monitor.js';
import wayback from './tools/wayback.js';
import takeover from './tools/takeover.js';
import sweep from './tools/sweep.js';
import playbook from './tools/playbook.js';
import dossier from './tools/dossier.js';
import favicon from './tools/favicon.js';
import ip from './tools/ip.js';
import asn from './tools/asn.js';
import url from './tools/url.js';
import mac from './tools/mac.js';
import cidr from './tools/cidr.js';
import geo from './tools/geo.js';
import map from './tools/map.js';
import crypto from './tools/crypto.js';
import image from './tools/image.js';
import file from './tools/file.js';
import assess from './tools/assess.js';
import cve from './tools/cve.js';
import headers from './tools/headers.js';
import records from './tools/records.js';
import dorks from './tools/dorks.js';
import extract from './tools/extract.js';
import utils from './tools/utils.js';
import graph from './tools/graph.js';
import caseFile from './tools/case.js';
import account from './tools/account.js';
import engine from './tools/engine.js';
import chat from './tools/chat.js';
import settingsTool from './tools/settings.js';

// Sidebar groups. Every labelled group can be collapsed; collapsed groups still show the active tool.
const GROUPS = [
  { id: 'start', label: '', tools: [overview] },
  { id: 'intelligence', label: 'intelligence', tools: [engine, playbook, chat] },
  { id: 'identity', label: 'identity', tools: [username, ogu, email, phone, breach] },
  { id: 'network', label: 'network', tools: [recon, monitor, sweep, domain, ip, asn, url, mac, cidr, takeover, wayback, favicon] },
  { id: 'geo', label: 'geo', tools: [geo, map] },
  { id: 'assets', label: 'assets', tools: [crypto, image, file] },
  { id: 'threat', label: 'threat', tools: [assess, cve, headers] },
  { id: 'research', label: 'research', tools: [records, dorks] },
  { id: 'tools', label: 'tools', tools: [extract, utils] },
  { id: 'workspace', label: 'workspace', tools: [graph, caseFile, dossier, account, settingsTool] },
];
const TITLES = {
  overview: 'universal search', username: 'username intel', ogu: 'og username finder', email: 'email intel', phone: 'phone intel', breach: 'breach exposure',
  recon: 'attack surface recon', monitor: 'change monitoring', wayback: 'wayback endpoints', takeover: 'subdomain takeover', sweep: 'bulk exposure sweep', domain: 'domain intel', ip: 'ip intel', asn: 'asn explorer', url: 'url analyzer', mac: 'mac lookup', cidr: 'subnet calculator',
  geo: 'geolocation', map: 'infrastructure map', crypto: 'wallet lookup', image: 'image analysis', file: 'file triage',
  assess: 'vulnerability assessment', cve: 'vulnerability lookup', headers: 'email header analysis', records: 'records & news', dorks: 'search engines',
  extract: 'entity extractor', utils: 'decoders', graph: 'investigation graph', case: 'case file',
  account: 'account', settings: 'settings', dossier: 'dossier export', favicon: 'favicon hash', engine: 'autonomous engine', chat: 'ai assistant',
};
// One short line per tool for the launcher.
const BLURBS = {
  overview: 'detect & run anything', username: 'one handle, 90+ sites', ogu: 'hunt handles across sites & games', email: 'provider, security, gravatar',
  phone: 'validate & format any number', breach: 'is your data exposed?',
  recon: 'map a domain\'s whole attack surface', monitor: 'snapshot & alert on changes', wayback: 'archived urls & endpoints', takeover: 'dangling-CNAME audit', sweep: 'asn/cidr → exposure', domain: 'dns, whois, mail, subdomains',
  ip: 'location, ports, ownership', asn: 'networks & address space', url: 'dissect & vet a link', mac: 'device maker & formats',
  cidr: 'subnet math, v4 & v6', geo: 'coordinates → place & imagery', map: 'plot infrastructure worldwide',
  crypto: 'btc & eth wallet activity', image: 'reverse search & exif', file: 'static triage & hash lookup',
  assess: 'scan a site, scored report', cve: 'severity & exploit odds', headers: 'trace & vet an email', records: 'companies, courts, news',
  dorks: 'operator query builder', extract: 'pull iocs from any text', utils: 'encode, decode, hash',
  graph: 'your pivots, visualised', case: 'notes, timeline, reports',
  account: 'sign in with github', settings: 'backend, keys, theme',
  dossier: 'compile an infra report', favicon: 'favicon → shodan pivot',
  engine: 'investigate automatically', playbook: 'one-click audit workflow', chat: 'ask, plan, interpret',
};
const TOOLS = GROUPS.flatMap(g => g.tools);
const byId = Object.fromEntries(TOOLS.map(t => [t.id, t]));
const groupOf = Object.fromEntries(GROUPS.flatMap(g => g.tools.map(t => [t.id, g.label || 'start'])));
const title = t => TITLES[t.id] || t.label;
// Tools whose empty state is itself useful (no query needed to be worth showing).
const SHOW_ON_IDLE = new Set(['image', 'dorks', 'breach', 'utils', 'file', 'map', 'monitor']);

const $ = s => document.querySelector(s);
const nav = $('#tabs'), form = $('#search'), input = $('#q'), out = $('#out');
const hint = $('#hint'), recent = $('#recent'), panel = $('.panel'), head = $('#toolhead');
const body = document.body;
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

let current = overview;
let currentValue = '';
let runId = 0;

applyTheme();
if (settings().rail) body.classList.add('rail');

// ---------- sidebar ----------

function buildNav() {
  const closed = new Set(settings().closedGroups);
  for (const g of GROUPS) {
    const items = h('div', { class: 'groupitems' });
    for (const t of g.tools) {
      const a = h('a', { class: 'navitem', href: `#${t.id}`, dataset: { tool: t.id }, title: title(t) });
      a.innerHTML = icon(t.id) + `<span class="navtext">${t.label}</span>`;
      a.addEventListener('click', () => { body.classList.remove('drawer'); if (location.hash === `#${t.id}`) route(); });
      items.append(a);
    }
    const headBtn = g.label ? h('button', {
      class: 'grouphead', type: 'button', 'aria-expanded': String(!closed.has(g.id)),
      onclick: () => setGroup(g.id, nav.querySelector(`[data-group="${g.id}"]`).classList.contains('closed')),
    }, h('span', { class: 'navlabel' }, g.label), h('span', { class: 'groupcount' }, g.tools.length), iconEl('chevron', 'chev')) : null;
    nav.append(h('div', { class: 'navgroup' + (closed.has(g.id) ? ' closed' : ''), dataset: { group: g.id } }, headBtn, items));
  }
  syncGroupsToggle();
}

function setGroup(id, open) {
  const el = nav.querySelector(`[data-group="${id}"]`);
  el.classList.toggle('closed', !open);
  el.querySelector('.grouphead')?.setAttribute('aria-expanded', String(open));
  const closed = new Set(settings().closedGroups);
  open ? closed.delete(id) : closed.add(id);
  setSetting('closedGroups', [...closed]);
  syncGroupsToggle();
}

const collapsible = () => GROUPS.filter(g => g.label);
function syncGroupsToggle() {
  const anyOpen = collapsible().some(g => !nav.querySelector(`[data-group="${g.id}"]`)?.classList.contains('closed'));
  const b = $('#groupsToggle');
  b.innerHTML = icon(anyOpen ? 'collapse' : 'expand');
  b.title = anyOpen ? 'collapse all groups' : 'expand all groups';
  b.dataset.open = String(anyOpen);
}

$('#groupsToggle').addEventListener('click', e => {
  const open = e.currentTarget.dataset.open !== 'true';
  for (const g of collapsible()) setGroup(g.id, open);
});

$('#railToggle').innerHTML = icon('sidebar');
$('#railToggle').addEventListener('click', () => {
  const on = body.classList.toggle('rail');
  setSetting('rail', on);
});

$('#menuBtn').innerHTML = icon('menu');
$('#menuBtn').addEventListener('click', () => body.classList.toggle('drawer'));
$('#scrim').addEventListener('click', () => body.classList.remove('drawer'));

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
    ...types.slice(0, 3).flatMap((t, i) => [i ? ' · ' : '', h('a', { href: `#${t}/${encodeURIComponent(v)}` }, title(byId[t]))]));
}

// ---------- tool header ----------

function renderHead(tool) {
  const toggleCards = h('button', { class: 'mini ghost', type: 'button', title: 'collapse or expand every card' }, 'collapse all');
  toggleCards.onclick = () => {
    const cards = [...out.querySelectorAll('.card')];
    const shut = cards.some(c => !c.classList.contains('collapsed'));
    cards.forEach(c => { c.classList.toggle('collapsed', shut); c.querySelector('.cardtoggle')?.setAttribute('aria-expanded', String(!shut)); });
    toggleCards.textContent = shut ? 'expand all' : 'collapse all';
  };
  const share = h('button', { class: 'mini ghost', type: 'button', title: 'copy a link to this view' }, 'copy link');
  share.onclick = async () => {
    try { await navigator.clipboard.writeText(location.href); share.textContent = 'copied'; } catch { share.textContent = 'failed'; }
    setTimeout(() => (share.textContent = 'copy link'), 1200);
  };
  const ic = h('div', { class: 'th-icon' });
  ic.innerHTML = icon(tool.id);
  head.replaceChildren(ic,
    h('div', { class: 'th-text' },
      h('div', { class: 'th-crumb muted small' }, groupOf[tool.id]),
      h('h2', {}, title(tool)),
      tool.intro ? h('p', { class: 'muted' }, tool.intro) : null),
    h('div', { class: 'th-actions' }, toggleCards, share));
}

// ---------- home launcher ----------

function launcher() {
  return h('div', { class: 'launcher' }, GROUPS.filter(g => g.label).map(g => h('div', { class: 'lgroup' },
    h('h4', {}, g.label),
    g.tools.map(t => {
      const a = h('a', { class: 'ltool', href: `#${t.id}` });
      const ic = h('span', { class: 'lt-icon' });
      ic.innerHTML = icon(t.id);
      a.append(ic, h('span', { class: 'lt-text' }, h('strong', {}, title(t)), h('span', { class: 'muted small' }, BLURBS[t.id] || '')));
      return a;
    }))));
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
  for (const a of nav.querySelectorAll('.navitem')) {
    if (a.dataset.tool === tool.id) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  input.placeholder = tool.placeholder;
  panel.hidden = !!tool.noInput;
  document.title = `${title(tool)} · feddedosint`;
  renderHead(tool);
  renderRecent();
}

function examples(tool) {
  return tool.examples?.length ? h('p', { class: 'examples' }, h('span', { class: 'muted' }, 'try '),
    ...tool.examples.map(e => h('a', { class: 'chip', href: `#${tool.id}/${encodeURIComponent(e)}` }, e))) : null;
}

// The graph records what an entity IS: universal searches are filed under the detected type.
const entityTool = (tool, q) => (tool.id === 'overview' ? classify(q).find(t => byId[t]) || 'overview' : tool.id);

async function run(tool, q, { idle = false } = {}) {
  const id = ++runId;
  currentValue = q;
  if (q && !tool.noTrack) trackNode(entityTool(tool, q), q);
  out.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'working…'));
  try {
    const result = await tool.run(q);
    if (id !== runId) return;
    out.replaceChildren(...(idle ? [examples(tool)] : []), ...[result].flat().filter(Boolean));
    if (q) remember(tool.id, q);
    renderRecent();
  } catch (e) {
    if (id !== runId) return;
    out.replaceChildren(h('p', { class: 'error' }, e?.message || String(e)), examples(tool));
  }
}

// ---------- sign-in wall ----------
// Until the visitor is signed in and approved, only the lock screen is shown.
const lockEl = $('#lock');
let authError = '';

function locked() {
  const reason = lockReason();
  body.classList.toggle('locked', !!reason);
  lockEl.hidden = !reason;
  if (reason) renderLock(lockEl, reason, { error: authError, onRetry: recheck });
  return !!reason;
}

async function recheck() {
  authError = '';
  if (be.isLoggedIn()) await be.refreshMe().catch(() => {});
  route();
}

function route() {
  if (locked()) return;
  const { tool, q, hasQuery } = parseHash();
  select(tool);
  if (!tool.noInput && hasQuery) input.value = q;
  else if (!hasQuery) input.value = '';
  updateHint();
  if (tool.noInput) run(tool, '');
  else if (hasQuery && (q || tool.allowEmpty)) run(tool, q);
  else if (SHOW_ON_IDLE.has(tool.id)) run(tool, '', { idle: true });
  else {
    currentValue = '';
    out.replaceChildren(...[examples(tool), tool.id === 'overview' ? launcher() : null].filter(Boolean));
  }
  window.scrollTo({ top: 0 });
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
  if (byId[toTool] && toVal && !current.noTrack) trackEdge(entityTool(current, currentValue), currentValue, toTool, toVal);
});

// ---------- command palette (Ctrl/Cmd + K) ----------

const pal = $('#palette'), palInput = $('#palinput'), palList = $('#pallist');
let palItems = [], palIdx = 0;

function paletteItems(q) {
  const ql = q.toLowerCase(), items = [];
  if (q) for (const t of classify(q).filter(x => byId[x]).slice(0, 3)) {
    items.push({ icon: t, label: `${title(byId[t])}`, sub: q, hint: 'search', href: `#${t}/${encodeURIComponent(q)}` });
  }
  for (const t of TOOLS) {
    if (!ql || title(t).includes(ql) || t.label.includes(ql) || groupOf[t.id].includes(ql)) {
      items.push({ icon: t.id, label: title(t), sub: '', hint: groupOf[t.id], href: `#${t.id}` });
    }
  }
  for (const r of recentAll().filter(r => byId[r.t] && (!ql || r.q.toLowerCase().includes(ql))).slice(0, 6)) {
    items.push({ icon: r.t, label: r.q, sub: '', hint: `recent · ${byId[r.t].label}`, href: `#${r.t}/${encodeURIComponent(r.q)}` });
  }
  return items.slice(0, 14);
}

function renderPalette() {
  palItems = paletteItems(palInput.value.trim());
  palIdx = Math.min(palIdx, Math.max(0, palItems.length - 1));
  palList.replaceChildren(...palItems.map((it, i) => {
    const row = h('a', { class: 'palitem' + (i === palIdx ? ' on' : ''), href: it.href });
    const ic = h('span', { class: 'pi-icon' });
    ic.innerHTML = icon(it.icon);
    row.append(ic, h('span', { class: 'pi-label' }, it.label, it.sub ? h('span', { class: 'muted' }, ` ${it.sub}`) : null),
      h('span', { class: 'pi-hint muted small' }, it.hint));
    row.addEventListener('click', closePalette);
    row.addEventListener('mousemove', () => { if (palIdx !== i) { palIdx = i; mark(); } });
    return row;
  }));
  if (!palItems.length) palList.append(h('p', { class: 'muted small pal-empty' }, 'no matches'));
}
const mark = () => [...palList.children].forEach((c, i) => c.classList.toggle('on', i === palIdx));

function openPalette() {
  pal.hidden = false;
  palInput.value = '';
  palIdx = 0;
  renderPalette();
  requestAnimationFrame(() => palInput.focus());
}
function closePalette() { pal.hidden = true; }

palInput.addEventListener('input', () => { palIdx = 0; renderPalette(); });
palInput.addEventListener('keydown', e => {
  if (e.key === 'ArrowDown') { e.preventDefault(); palIdx = (palIdx + 1) % Math.max(1, palItems.length); mark(); palList.children[palIdx]?.scrollIntoView({ block: 'nearest' }); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); palIdx = (palIdx - 1 + palItems.length) % Math.max(1, palItems.length); mark(); palList.children[palIdx]?.scrollIntoView({ block: 'nearest' }); }
  else if (e.key === 'Enter') { e.preventDefault(); const it = palItems[palIdx]; if (it) { closePalette(); location.hash = it.href; } }
});
pal.addEventListener('click', e => { if (e.target === pal) closePalette(); });
for (const id of ['#paletteBtn', '#paletteBtnM']) $(id).addEventListener('click', openPalette);
$('#paletteBtn .ico').innerHTML = icon('overview');
$('#paletteBtnM').innerHTML = icon('overview');
$('#paletteBtn kbd').textContent = isMac ? '⌘K' : 'Ctrl K';

// ---------- wiring ----------

buildNav();

form.addEventListener('submit', e => {
  e.preventDefault();
  const target = `#${current.id}/${encodeURIComponent(input.value.trim())}`;
  if (location.hash === target) route();
  else location.hash = target;
});

input.addEventListener('input', updateHint);
addEventListener('hashchange', route);
addEventListener('keydown', e => {
  if (body.classList.contains('locked')) return;
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.hidden ? openPalette() : closePalette(); }
  else if (e.key === 'Escape') { if (!pal.hidden) closePalette(); body.classList.remove('drawer'); }
  else if (e.key === '/' && !typing && pal.hidden) {
    e.preventDefault();
    if (current.noInput) openPalette(); else { input.focus(); input.select(); }
  }
});

// Pick up a GitHub OAuth redirect (#auth=…) and refresh the signed-in user (so an approval
// takes effect on the next visit) before the first route, which decides whether to unlock.
(async () => {
  const res = await be.consumeAuthRedirect().catch(() => 'error');
  if (res === 'error') authError = 'GitHub sign-in didn\u2019t complete — please try again.';
  else if (!res && be.isLoggedIn()) await be.refreshMe().catch(() => {});
})().finally(route);
