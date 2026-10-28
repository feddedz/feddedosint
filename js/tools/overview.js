import { h, card, muted, badge, isIP } from '../util.js';
import domain from './domain.js';
import ip from './ip.js';
import email from './email.js';
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

const TOOLS = { domain, ip, email, username, phone, crypto, cve, breach, asn, url, mac, cidr, geo, file, map };

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
  if (isIP(bare)) out.push('ip', 'asn', 'map');
  if (/^-?\d{1,2}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?$/.test(v) || /°.*[NS].*°.*[EW]/i.test(v)) out.push('geo');
  if (/^(as)?\d{2,10}$/i.test(v) && !isIP(v)) out.push('asn');
  if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(v)) out.push('file');
  if (/^\+?[\d\s().-]{7,}$/.test(v) && v.replace(/\D/g, '').length >= 7 && !/^\d{1,10}$/.test(v.replace(/\D/g, ''))) out.push('phone');
  if (/^https?:\/\/[^/]+\/./i.test(v) || /^https?:\/\/[^/]+\/?\?/i.test(v)) out.push('url');
  if (!isIP(bare) && (/^https?:\/\//i.test(v) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v))) out.push('domain', 'map');
  if (!out.length) out.push('username');
  return [...new Set(out)];
}

export default {
  id: 'overview',
  label: 'search',
  placeholder: 'anything — email, domain, IP, username, phone, wallet, CVE…',
  intro: 'One box for everything. Detects what you typed and runs the right tool, with one click to re-run it as another entity type.',
  examples: ['github.com', '1.1.1.1', 'torvalds'],

  async run(raw) {
    const v = raw.trim();
    if (!v) throw new Error('type anything to begin');
    const types = classify(v);
    const primary = types[0];
    const tool = TOOLS[primary];

    const banner = h('div', { class: 'detect' },
      h('span', { class: 'muted small' }, 'detected as'), badge(tool.label, 'ok'),
      types.length > 1 ? [h('span', { class: 'muted small' }, 'also try') ,
        ...types.slice(1).filter(t => TOOLS[t]).map(t => h('a', { class: 'chip', href: `#${t}/${encodeURIComponent(v)}` }, TOOLS[t].label))] : null,
      h('a', { class: 'chip', href: `#dorks/${encodeURIComponent(v)}` }, 'search engines'));

    try {
      const result = await tool.run(v);
      return [banner, ...[result].flat().filter(Boolean)];
    } catch (e) {
      return [banner, card('could not run ' + tool.label, { wide: true }, muted(e?.message || 'failed'))];
    }
  },
};
