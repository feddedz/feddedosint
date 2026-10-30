import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, normDomain } from '../util.js';

// Brand-protection: generate lookalike/typosquat domains of a brand you own and check which are
// registered and which can send mail (phishing-capable). Public DNS only, client-side. For
// monitoring your own brand's impersonation surface.

const KEYBOARD = { a: 'qwsz', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wsdr', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', i: 'ujko', j: 'huikmn', k: 'jiolm', l: 'kop', m: 'njk', n: 'bhjm', o: 'iklp', p: 'ol', q: 'wa', r: 'edft', s: 'awedxz', t: 'rfgy', u: 'yhji', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu', z: 'asx' };
const HOMO = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], b: ['8'], g: ['9'], t: ['7'] };
const TLDS = ['com', 'net', 'org', 'co', 'io', 'xyz', 'app', 'online', 'site', 'info', 'biz', 'live', 'us', 'co.uk', 'de', 'ru', 'cn', 'top', 'shop', 'store'];
const WORDS = ['login', 'secure', 'account', 'support', 'help', 'verify', 'mail', 'auth', 'portal', 'pay', 'billing', 'app'];

// Split "brand.com" / "brand.co.uk" into [label, tld] (naive two-level suffix handling).
function split(domain) {
  const parts = domain.split('.');
  const twoLevel = ['co.uk', 'com.au', 'co.jp', 'com.br', 'co.in', 'org.uk', 'ac.uk'];
  const last2 = parts.slice(-2).join('.');
  if (twoLevel.includes(last2) && parts.length > 2) return [parts.slice(0, -2).join('.'), last2];
  return [parts.slice(0, -1).join('.'), parts.slice(-1)[0]];
}

function variants(label) {
  const set = new Set();
  const a = label.split('');
  // omission
  for (let i = 0; i < a.length; i++) set.add(label.slice(0, i) + label.slice(i + 1));
  // repetition
  for (let i = 0; i < a.length; i++) set.add(label.slice(0, i) + a[i] + label.slice(i));
  // transposition
  for (let i = 0; i < a.length - 1; i++) { const b = [...a]; [b[i], b[i + 1]] = [b[i + 1], b[i]]; set.add(b.join('')); }
  // replacement (adjacent keys)
  for (let i = 0; i < a.length; i++) for (const c of (KEYBOARD[a[i]] || '')) set.add(label.slice(0, i) + c + label.slice(i + 1));
  // homoglyph
  for (let i = 0; i < a.length; i++) for (const c of (HOMO[a[i]] || [])) set.add(label.slice(0, i) + c + label.slice(i + 1));
  // insertion (same char neighbours)
  for (let i = 0; i < a.length; i++) for (const c of (KEYBOARD[a[i]] || '').slice(0, 2)) set.add(label.slice(0, i) + c + label.slice(i));
  // hyphenation
  for (let i = 1; i < a.length; i++) set.add(label.slice(0, i) + '-' + label.slice(i));
  // rn -> m and m -> rn
  if (label.includes('m')) set.add(label.replace('m', 'rn'));
  if (label.includes('rn')) set.add(label.replace('rn', 'm'));
  set.delete(label);
  return [...set].filter(v => /^[a-z0-9-]{1,40}$/.test(v) && !v.startsWith('-') && !v.endsWith('-'));
}

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

async function probe(domain) {
  const [ns, a, mx] = await Promise.all([dns(domain, 'NS').catch(() => []), dns(domain, 'A').catch(() => []), dns(domain, 'MX').catch(() => [])]);
  const registered = ns.length > 0 || a.length > 0 || mx.length > 0;
  if (!registered) return { domain, state: 'free' };
  const mail = mx.length > 0, web = a.length > 0;
  const state = mail && web ? 'active' : web ? 'parked-web' : mail ? 'mail-only' : 'registered';
  return { domain, state, a: a.map(r => r.data), mx: mx.map(r => r.data.replace(/^\d+\s+/, '')) };
}

const STATE = {
  active: ['bad', 'active + mail'], 'mail-only': ['bad', 'mail capable'], 'parked-web': ['warn', 'resolves'],
  registered: ['warn', 'registered'], free: ['muted', 'unregistered'],
};
const ORDER = { active: 0, 'mail-only': 1, 'parked-web': 2, registered: 3, free: 4 };

export default {
  id: 'typosquat',
  label: 'typosquat',
  placeholder: 'yourbrand.com  (brand domain to protect)',
  intro: 'Brand protection: generates lookalike/typosquat domains of your brand and flags which are registered and which can send mail (phishing-capable). Public DNS only.',
  examples: ['example.com'],

  async run(raw) {
    const domain = normDomain(raw) || raw.trim().toLowerCase();
    if (!domain || !domain.includes('.')) throw new Error('enter a brand domain, e.g. yourbrand.com');
    const [label, tld] = split(domain);

    // Build candidate domains: label variants on the real TLD, plus brand on other TLDs,
    // plus combosquats (brand-word). Capped for a browser run.
    const cand = new Set();
    for (const v of variants(label)) cand.add(`${v}.${tld}`);
    for (const t of TLDS) if (t !== tld) cand.add(`${label}.${t}`);
    for (const w of WORDS) { cand.add(`${label}-${w}.${tld}`); cand.add(`${w}-${label}.${tld}`); }
    for (const t of HOMO[label[0]] || []) cand.add(`${t}${label.slice(1)}.${tld}`);
    cand.delete(domain);
    const list = [...cand].slice(0, 220);

    const results = [];
    await pool(list, 14, probe, (_, r) => r && results.push(r));
    results.sort((a, b) => (ORDER[a.state] - ORDER[b.state]) || a.domain.localeCompare(b.domain));

    const reg = results.filter(r => r.state !== 'free');
    const active = results.filter(r => r.state === 'active' || r.state === 'mail-only');
    const sc = (n, l, warn) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' + (warn && n ? ' warn' : '') }, String(n)), h('div', { class: 'statlbl muted small' }, l));

    const summary = card('typosquat scan', { wide: true, actions: badge(`${list.length} variants`, 'muted') },
      muted(`Checked ${list.length} lookalike domains of ${domain}. “active + mail” / “mail capable” can send convincing phishing as your brand — investigate those first.`),
      h('div', { class: 'statrow' },
        sc(active.length, 'phishing-capable', true),
        sc(reg.length, 'registered', true),
        sc(results.filter(r => r.state === 'parked-web').length, 'resolve'),
        sc(list.length - reg.length, 'unregistered'),
        sc(list.length, 'checked')),
      reg.length ? h('p', { class: 'row wrap', style: 'gap:6px;margin-top:8px' },
        copyBtn(() => reg.map(r => r.domain).join('\n'), 'copy registered'),
        active.length ? copyBtn(() => active.map(r => r.domain).join('\n'), 'copy phishing-capable') : null) : null);

    const regCard = reg.length ? card(`registered lookalikes (${reg.length})`, { wide: true },
      muted('Registered impersonation domains, most dangerous first. Consider monitoring or a takedown where one is actively abusing your brand.'),
      h('table', { class: 'records' }, h('tbody', {}, reg.map(r => {
        const [tone, lbl] = STATE[r.state];
        return h('tr', {},
          h('td', {}, badge(lbl, tone)),
          h('td', {}, pivot('recon', r.domain, r.domain)),
          h('td', { class: 'muted small' }, r.mx?.length ? `MX: ${r.mx.slice(0, 2).join(', ')}` : r.a?.length ? `A: ${r.a[0]}` : ''));
      })))) : null;

    const freeCard = card('unregistered (available to defensively register)', { wide: true, collapsed: true },
      h('div', { class: 'chips' }, results.filter(r => r.state === 'free').map(r => h('span', { class: 'chip' }, r.domain))));

    return grid(summary, regCard, freeCard);
  },
};
