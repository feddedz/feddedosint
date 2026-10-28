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

const TOOLS = { domain, ip, email, username, phone, crypto, cve, breach, asn };

// Decide the most likely entity types for an input, best guess first.
export function classify(v) {
  v = v.trim();
  const out = [];
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) out.push('cve');
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) out.push('email', 'breach');
  if (/^(bc1[0-9a-z]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40})$/.test(v)) out.push('crypto');
  if (isIP(v.replace(/^\[|\]$/g, ''))) out.push('ip', 'asn');
  if (/^(as)?\d{2,10}$/i.test(v) && !isIP(v)) out.push('asn');
  if (/^\+?[\d\s().-]{7,}$/.test(v) && v.replace(/\D/g, '').length >= 7 && !/^\d{1,10}$/.test(v.replace(/\D/g, ''))) out.push('phone');
  if (/^https?:\/\//i.test(v) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)) out.push('domain');
  if (/^@?[a-z0-9._-]{2,30}$/i.test(v) && !v.includes('.')) out.push('username');
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
        ...types.slice(1).map(t => h('a', { class: 'chip', href: `#${t}/${encodeURIComponent(v)}` }, TOOLS[t].label))] : null,
      h('a', { class: 'chip', href: `#dorks/${encodeURIComponent(v)}` }, 'search engines'));

    try {
      const result = await tool.run(v);
      return [banner, ...[result].flat().filter(Boolean)];
    } catch (e) {
      return [banner, card('could not run ' + tool.label, { wide: true }, muted(e?.message || 'failed'))];
    }
  },
};
