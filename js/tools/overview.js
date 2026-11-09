import { h, card, muted, badge, isIP } from '../util.js';
import domain from './domain.js';
import recon from './recon.js';
import origin from './origin.js';
import crawl from './crawl.js';
import ip from './ip.js';
import email from './email.js';
import emailperm from './emailperm.js';
import username from './username.js';
import phone from './phone.js';
import crypto from './crypto.js';
import cve from './cve.js';
import breach from './breach.js';
import asn from './asn.js';
import url from './url.js';
import mac from './mac.js';
import cidr from './cidr.js';
import geo from './geo.js';
import file from './file.js';
import map from './map.js';
import dns from './dns.js';
import whois from './whois.js';
import cert from './cert.js';
import timeline from './timeline.js';
import reputation from './reputation.js';
import typosquat from './typosquat.js';
import hashid from './hashid.js';
import tech from './tech.js';

const TOOLS = { domain, recon, origin, crawl, ip, email, emailperm, username, phone, crypto, cve, breach, asn, url, mac, cidr, geo, file, map, dns, whois, cert, timeline, reputation, typosquat, hashid, tech };

// Decide the most likely entity types for an input, best guess first.
export function classify(v) {
  v = v.trim();
  const out = [];
  const bare = v.replace(/^\[|\]$/g, '');
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) out.push('cve');
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) out.push('email', 'breach');
  if (/^(bc1[0-9a-z]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40})$/.test(v)) out.push('crypto');
  if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i.test(v)) out.push('mac');
  if (/^[0-9a-f.:]+\/\d{1,3}$/i.test(v)) out.push('cidr', 'asn');
  if (isIP(bare)) out.push('ip', 'asn', 'reputation', 'map');
  if (/^-?\d{1,2}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?$/.test(v) || /°.*[NS].*°.*[EW]/i.test(v)) out.push('geo');
  if (/^(as)?\d{2,10}$/i.test(v) && !isIP(v)) out.push('asn');
  if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(v)) out.push('hashid', 'file');
  if (/^\+?[\d\s().-]{7,}$/.test(v) && v.replace(/\D/g, '').length >= 7 && !/^\d{1,10}$/.test(v.replace(/\D/g, ''))) out.push('phone');
  if (/^https?:\/\/[^/]+\/./i.test(v) || /^https?:\/\/[^/]+\/?\?/i.test(v)) out.push('url', 'crawl');
  if (!isIP(bare) && (/^https?:\/\//i.test(v) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v))) out.push('domain', 'dns', 'recon', 'origin', 'whois', 'cert', 'timeline', 'tech', 'typosquat', 'map');
  if (!out.length) out.push('username');
  return [...new Set(out)];
}

// Per entity type: which FAST tools to run and aggregate inline, and which heavy tools to offer
// as one-click deep dives. Keyed by the primary classification.
const PROFILE = {
  domain: { run: ['domain', 'cert', 'tech', 'reputation'], deep: ['recon', 'analyst', 'crawl', 'timeline', 'wayback', 'takeover', 'dns', 'whois', 'map', 'engine'] },
  ip: { run: ['ip', 'reputation'], deep: ['recon', 'sweep', 'map', 'analyst'] },
  email: { run: ['email', 'breach', 'emailperm'], deep: ['username'] },
  username: { run: ['username'], deep: ['ogu'] },
  url: { run: ['url', 'tech'], deep: ['crawl', 'wellknown'] },
  asn: { run: ['asn'], deep: ['sweep', 'map', 'analyst'] },
  cidr: { run: ['cidr'], deep: ['sweep'] },
  cve: { run: ['cve'], deep: [] },
  crypto: { run: ['crypto'], deep: [] },
  phone: { run: ['phone'], deep: [] },
  mac: { run: ['mac'], deep: [] },
  geo: { run: ['geo', 'map'], deep: [] },
  hashid: { run: ['hashid', 'file'], deep: [] },
};
// Readable labels for deep-dive buttons that aren't in TOOLS above.
const DEEP_LABEL = { recon: 'attack surface', analyst: 'analyst', crawl: 'live crawl', wayback: 'wayback', takeover: 'takeover', map: 'map', engine: 'auto-investigate', sweep: 'exposure sweep', wellknown: 'well-known', ogu: 'og usernames', username: 'username', dorks: 'search engines' };
const labelOf = id => TOOLS[id]?.label || DEEP_LABEL[id] || id;

export default {
  id: 'overview',
  label: 'search',
  placeholder: 'anything — email, domain, IP, username, phone, wallet, CVE…',
  intro: 'One box for everything. Detects what you typed and runs every relevant tool at once — a full picture on one screen — with one-click deep dives for the heavy stuff.',
  examples: ['github.com', '1.1.1.1', 'torvalds'],

  run(raw) {
    const v = raw.trim();
    if (!v) throw new Error('type anything to begin');
    const types = classify(v);
    const primary = types[0];
    const profile = PROFILE[primary] || { run: TOOLS[primary] ? [primary] : [], deep: [] };
    const enc = encodeURIComponent(v);

    // tools to run inline (dedup, keep only ones we actually have)
    const runIds = [...new Set(profile.run)].filter(id => TOOLS[id]);
    if (!runIds.length && TOOLS[primary]) runIds.push(primary);
    // deep dives + any other detected types not already in the run set
    const deepIds = [...new Set([...profile.deep, ...types.filter(t => !runIds.includes(t) && (TOOLS[t] || DEEP_LABEL[t]))])];

    const chip = (id, cls = 'chip') => h('a', { class: cls, href: `#${id}/${enc}` }, labelOf(id));
    const banner = h('div', { class: 'detect' },
      h('span', { class: 'muted small' }, 'detected as'), badge(TOOLS[primary]?.label || primary, 'ok'),
      h('span', { class: 'muted small' }, `· running ${runIds.length} tool${runIds.length > 1 ? 's' : ''}`));
    const deepbar = (deepIds.length || true) ? h('div', { class: 'deepbar' },
      h('span', { class: 'muted small' }, 'deep dive'),
      ...deepIds.map(id => chip(id, 'chip deep')),
      chip('dorks', 'chip deep')) : null;

    // Build a section per run-tool; fill each independently.
    const sections = runIds.map(id => {
      const tool = TOOLS[id];
      const body = h('div', { class: 'aggbody' }, h('div', { class: 'loading' }, h('span', { class: 'spin' }), `running ${tool.label}…`));
      const sec = h('section', { class: 'aggsection' },
        h('div', { class: 'agghead' }, h('h3', {}, tool.label), h('a', { class: 'chip', href: `#${id}/${enc}` }, 'open ↗')),
        body);
      // run + inject
      Promise.resolve().then(() => tool.run(v)).then(out => {
        body.replaceChildren(...[out].flat().filter(Boolean));
      }).catch(e => {
        body.replaceChildren(card(`could not run ${tool.label}`, { wide: true }, muted(e?.message || 'failed')));
      });
      return sec;
    });

    return [banner, deepbar, ...sections];
  },
};
