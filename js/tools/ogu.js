import { h, card, grid, muted, badge, ext, pivot, copyBtn } from '../util.js';
import { SITES } from '../sites.js';
import * as be from '../backend.js';

// OGU — "OG username" finder. Two modes:
//  • a handle           → where it's taken vs free across popular sites and games
//  • a wildcard pattern → generates matching candidates and finds which are available (handle hunting)
// Uses the same server-side existence checks as the username deep-scan (public data). Availability
// checking only; it never touches account contents. For registering handles / your own research.

const CHARSET = 'abcdefghijklmnopqrstuvwxyz0123456789_';

// Curated big platforms (matched by name in the dataset) + every gaming site.
const POPULAR_NAMES = [
  'GitHub (Gists)', 'GitLab', 'Reddit', 'Twitch', 'Steam', 'Roblox', 'Chess.com', 'Instagram',
  'TikTok', 'Telegram', 'Spotify', 'Pinterest', 'Snapchat', 'YouTube Channel', 'MCUUID (Minecraft)',
  'Xbox Gamertag', 'Replit', 'npm', 'SoundCloud', 'Patreon', 'Medium',
];
const byName = Object.fromEntries(SITES.map(s => [s.n, s]));
const POPULAR = POPULAR_NAMES.map(n => byName[n]).filter(Boolean);
const GAMES = SITES.filter(s => s.c === 'gaming');
// Small, fast signal set for pattern mode (checking many candidates): a handful of high-signal sites.
const SIGNAL = ['GitHub (Gists)', 'Reddit', 'Steam', 'Twitch', 'Roblox', 'Instagram', 'TikTok', 'Chess.com']
  .map(n => byName[n]).filter(Boolean);

const uniqSites = arr => { const seen = new Set(), out = []; for (const s of arr) if (!seen.has(s.n)) { seen.add(s.n); out.push(s); } return out; };

// Run availability checks for one handle over a site list; resolves with a name→state map.
function checkHandle(handle, sites, signal) {
  return new Promise(resolve => {
    const states = {};
    be.deepScan(handle, sites, {
      batchSize: 40, concurrency: 4,
      onBatch: (batch, results) => batch.forEach((s, i) => { states[s.n] = results[i]?.state || 'unknown'; }),
    }).then(() => resolve(states)).catch(() => resolve(states));
  });
}

// Expand a wildcard pattern (? = one char, * = 1-2 chars) into up to `cap` candidate handles.
function expand(pattern, cap) {
  const p = pattern.toLowerCase();
  if (!/[?*]/.test(p)) return [p];
  const slots = []; // each wildcard: how many chars it contributes (1, or 1-2 for *)
  for (const ch of p) { if (ch === '?') slots.push([1]); else if (ch === '*') slots.push([1, 2]); }
  // Rough size estimate.
  let est = 1; for (const s of slots) est *= (s.length === 1 ? CHARSET.length : CHARSET.length + CHARSET.length * CHARSET.length);
  const fill = () => {
    let out = '';
    for (const ch of p) {
      if (ch === '?') out += CHARSET[Math.floor(Math.random() * CHARSET.length)];
      else if (ch === '*') { const len = 1 + Math.floor(Math.random() * 2); for (let k = 0; k < len; k++) out += CHARSET[Math.floor(Math.random() * CHARSET.length)]; }
      else out += ch;
    }
    return out;
  };
  const set = new Set();
  // Deterministic enumeration when small and only single-char wildcards.
  if (est <= cap && slots.every(s => s.length === 1)) {
    const idx = [...p].map((c, i) => c === '?' ? i : -1).filter(i => i >= 0);
    const rec = (pos, cur) => { if (pos === idx.length) { set.add(cur.join('')); return; } for (const c of CHARSET) { cur[idx[pos]] = c; rec(pos + 1, cur); } };
    rec(0, [...p]);
  } else {
    let tries = 0; while (set.size < cap && tries++ < cap * 40) set.add(fill());
  }
  return [...set].slice(0, cap);
}

const AVAIL = { none: 'available', found: 'taken', unknown: 'unknown' };
const foundSites = (states) => Object.entries(states).filter(([, st]) => st === 'found').map(([n]) => n);
const freeSites = (states) => Object.entries(states).filter(([, st]) => st === 'none').map(([n]) => n);

// Pick the site set for a scope: 'fast' = curated popular + games; 'all' = the whole dataset.
function siteSet(scope, adult) {
  const base = scope === 'all' ? SITES : [...POPULAR, ...GAMES];
  return uniqSites(base.filter(s => adult || s.c !== 'adult'));
}

async function singleHandle(handle, container, out, { scope, adult }) {
  const sites = siteSet(scope, adult);
  out.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), `checking ${handle} across ${sites.length} platforms…`));
  const states = await checkHandle(handle, sites);
  if (!container.isConnected) return;
  const taken = foundSites(states), free = freeSites(states);
  const unver = sites.length - taken.length - free.length;

  // Category breakdown (taken per category).
  const catTaken = {};
  for (const n of taken) { const c = byName[n]?.c || 'misc'; catTaken[c] = (catTaken[c] || 0) + 1; }
  const cats = Object.entries(catTaken).sort((a, b) => b[1] - a[1]);

  const sc = (n, l, tone) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' + (tone ? ' ' + tone : '') }, String(n)), h('div', { class: 'statlbl muted small' }, l));
  const takenCard = card(`taken (${taken.length})`, { wide: true },
    taken.length ? h('div', { class: 'chips' }, taken.map(n => {
      const s = byName[n]; const url = s.u.replace(/\{u\}/g, encodeURIComponent(handle));
      return h('span', { class: 'chip' }, ext(url, n));
    })) : muted('Not taken on any checked platform.'));
  const catCard = cats.length ? card('taken by category', {},
    h('table', { class: 'records' }, h('tbody', {}, cats.map(([c, n]) =>
      h('tr', {}, h('td', {}, badge(c, 'muted')), h('td', { class: 'muted small' }, `${n} platform${n === 1 ? '' : 's'}`)))))) : null;
  const freeCard = card(`available (${free.length})`, { wide: true, collapsed: free.length > 60 },
    muted('Handle appears free on these — verify by trying to register.'),
    h('div', { class: 'chips' }, free.map(n => h('span', { class: 'chip' }, n))));

  out.replaceChildren(grid(
    card('result', { wide: true, actions: copyBtn(() => `${handle}\nTAKEN: ${taken.join(', ')}\nFREE: ${free.join(', ')}`, 'copy') },
      h('p', {}, h('strong', { style: 'font-size:16px' }, handle), ' ', badge(scope === 'all' ? 'full dataset' : 'popular + games', 'muted')),
      h('div', { class: 'statrow' }, sc(taken.length, 'taken', 'warn'), sc(free.length, 'available', ''), sc(unver, 'unverified'), sc(sites.length, 'checked')),
      h('p', { class: 'muted small', style: 'margin-top:8px' }, 'also open the full ', pivot('username', handle, 'username deep-scan'), ' for profile detail (avatars, bios, join dates).')),
    takenCard, catCard, freeCard));
}

async function patternHunt(pattern, container, out, cap, { scope, adult } = { scope: 'fast', adult: false }) {
  // 'all' checks each candidate against a broader set (slower) but bounds the total ~checks.
  const sig = scope === 'all' ? siteSet('fast', adult) : SIGNAL;
  const effCap = scope === 'all' ? Math.min(cap, 16) : cap;
  const cands = expand(pattern, effCap);
  if (!cands.length) { out.replaceChildren(muted('no candidates from that pattern')); return; }
  out.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), `checking ${cands.length} candidate(s) across ${sig.length} platform(s)…`));
  const rows = [];
  for (const cand of cands) {
    if (!container.isConnected) return;
    const states = await checkHandle(cand, sig);
    const taken = foundSites(states), free = freeSites(states);
    rows.push({ cand, taken, free, score: free.length - taken.length, total: sig.length });
  }
  if (!container.isConnected) return;
  rows.sort((a, b) => b.score - a.score || a.cand.localeCompare(b.cand));
  const fullyFree = rows.filter(r => r.taken.length === 0);

  const table = h('table', { class: 'records' }, h('tbody', {}, rows.map(r => h('tr', {},
    h('td', {}, r.taken.length === 0 ? badge('all free', 'ok') : badge(`${r.free.length}/${r.total} free`, r.free.length ? 'warn' : 'muted')),
    h('td', {}, pivot('ogu', r.cand, r.cand)),
    h('td', { class: 'muted small' }, r.taken.length ? 'taken on ' + r.taken.join(', ') : 'no major platform has it')))));

  out.replaceChildren(grid(
    card('handle hunt', { wide: true, actions: copyBtn(() => fullyFree.map(r => r.cand).join('\n'), 'copy all-free') },
      muted(`Pattern “${pattern}” → ${rows.length} candidate(s), ranked by availability across ${sig.length} platform(s). “all free” = no checked platform has it.`),
      h('p', {}, h('strong', {}, `${fullyFree.length}`), ' candidate(s) free on every checked platform.'),
      table)));
}

export default {
  id: 'ogu',
  label: 'ogu',
  placeholder: 'a handle (e.g. zex) or a pattern (e.g. z?x, co*l) to hunt',
  intro: 'OG-username finder: check a handle across popular sites and games, or give a wildcard pattern (? = one char, * = 1–2 chars) to hunt for available handles.',
  examples: ['zex', 'z?x', 'co*l'],
  noTrack: true,

  run(raw) {
    const input = (raw || '').trim().toLowerCase();
    if (!input) throw new Error('enter a handle, or a pattern with ? / *');
    if (!/^[a-z0-9_?*]{1,20}$/.test(input)) throw new Error('handles/patterns use letters, digits, _ and the wildcards ? *');

    if (!(be.backendConfigured() && be.isApproved())) {
      return card('sign-in needed', { wide: true },
        muted('OGU runs its existence checks through the backend, so it needs an approved sign-in.'),
        h('p', {}, pivot('account', '', 'sign in')));
    }

    const isPattern = /[?*]/.test(input);
    const out = h('div', {});
    const container = h('div', {}, out);

    // Controls: scan scope + adult opt-in (single-handle), or candidate count (pattern).
    let scope = isPattern ? 'fast' : 'fast';
    let adult = false;
    let cap = 24;
    const start = () => {
      requestAnimationFrame(() => {
        (isPattern ? patternHunt(input, container, out, cap, { scope, adult }) : singleHandle(input, container, out, { scope, adult }))
          .catch(e => { if (container.isConnected) out.replaceChildren(h('p', { class: 'error' }, e?.message || 'failed')); });
      });
    };

    const seg = (label, on, onClick) => { const b = h('button', { class: 'seg' + (on ? ' on' : ''), type: 'button' }, label); b.onclick = onClick; return b; };
    const scopeSeg = h('div', { class: 'segset' });
    const rebuildScope = () => scopeSeg.replaceChildren(
      seg('popular + games', scope === 'fast', () => { scope = 'fast'; rebuildScope(); start(); }),
      seg(isPattern ? 'all (slower)' : `everything (~${SITES.length})`, scope === 'all', () => { scope = 'all'; rebuildScope(); start(); }));
    rebuildScope();
    const adultChk = h('label', { class: 'muted small', style: 'display:inline-flex;gap:5px;align-items:center;cursor:pointer' },
      Object.assign(h('input', { type: 'checkbox' }), { onchange: e => { adult = e.target.checked; start(); } }), 'include adult');

    const controls = card('scan', { wide: true },
      h('div', { class: 'row wrap', style: 'gap:12px;align-items:center' },
        h('span', { class: 'muted small' }, isPattern ? 'check candidates against' : 'scan'),
        scopeSeg, adultChk,
        isPattern ? h('span', { class: 'muted small' }, `pattern: ${input}`) : null));

    container.replaceChildren(controls, out);
    start();
    return container;
  },
};
