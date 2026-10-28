import { h, card, grid, muted, badge, copyBtn, pivot, refang, isIPv4, isIPv6 } from '../util.js';
import { trackNode } from '../store.js';

// File extensions that look like domains but almost never are.
const NOT_TLD = new Set(['txt', 'js', 'mjs', 'ts', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp',
  'css', 'json', 'xml', 'yml', 'yaml', 'exe', 'dll', 'sys', 'bin', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar',
  'gz', 'tar', 'log', 'md', 'py', 'sh', 'bat', 'ps1', 'csv', 'tmp', 'bak', 'ini', 'cfg', 'conf', 'jar', 'class', 'lnk', 'msi', 'iso',
  'mp3', 'mp4', 'mov', 'avi', 'wav', 'dat', 'db', 'sql', 'cpp', 'java', 'rb', 'go', 'rs', 'vbs', 'hta', 'eml', 'msg',
  // property-style tokens seen in headers and code (e.g. smtp.mailfrom, header.from, this.length)
  'from', 'mailfrom', 'helo', 'ehlo', 'prototype', 'length', 'value', 'push', 'then', 'catch', 'error', 'warn']);

// Each kind: how to find it, which tool it pivots to, and a display label.
export const KINDS = [
  { id: 'url', label: 'urls', tool: 'url', re: /\bhttps?:\/\/[^\s"'<>`]+/gi, clean: s => s.replace(/[)\].,;:!?'"]+$/, '') },
  { id: 'email', label: 'emails', tool: 'email', re: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi, clean: s => s.toLowerCase() },
  { id: 'domain', label: 'domains', tool: 'domain', re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
    clean: s => s.toLowerCase(), keep: s => !NOT_TLD.has(s.split('.').pop()) },
  { id: 'ipv4', label: 'ipv4', tool: 'ip', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, keep: isIPv4 },
  { id: 'ipv6', label: 'ipv6', tool: 'ip', re: /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b|\b(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4})?\b/gi,
    clean: s => s.toLowerCase(), keep: s => isIPv6(s) && s.replace(/[^:]/g, '').length >= 2 },
  { id: 'cve', label: 'cves', tool: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi, clean: s => s.toUpperCase() },
  { id: 'sha256', label: 'sha-256', tool: 'file', re: /\b[a-f0-9]{64}\b/gi, clean: s => s.toLowerCase() },
  { id: 'sha1', label: 'sha-1', tool: 'file', re: /\b[a-f0-9]{40}\b/gi, clean: s => s.toLowerCase() },
  { id: 'md5', label: 'md5', tool: 'file', re: /\b[a-f0-9]{32}\b/gi, clean: s => s.toLowerCase() },
  { id: 'btc', label: 'bitcoin', tool: 'crypto', re: /\b(?:bc1[02-9ac-hj-np-z]{25,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g },
  { id: 'eth', label: 'ethereum', tool: 'crypto', re: /\b0x[a-fA-F0-9]{40}\b/g },
  { id: 'mac', label: 'mac addresses', tool: 'mac', re: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, clean: s => s.toUpperCase().replace(/-/g, ':') },
  { id: 'phone', label: 'phones', tool: 'phone', re: /\+\d[\d\s().-]{6,18}\d/g, clean: s => s.replace(/[\s().-]/g, ''),
    keep: s => s.replace(/\D/g, '').length >= 8 && s.replace(/\D/g, '').length <= 15 },
  { id: 'handle', label: 'handles', tool: 'username', re: /(?:^|[\s(,])@([a-z0-9_]{2,30})\b/gi, group: 1 },
];

// Pull every indicator out of free text. Defanged forms (hxxp, [.]) are recognised.
export function extractEntities(text, limit = 2000) {
  const src = refang(text);
  const out = {};
  for (const k of KINDS) {
    const seen = new Set();
    for (const m of src.matchAll(k.re)) {
      let v = k.group ? m[k.group] : m[0];
      if (k.clean) v = k.clean(v);
      if (!v || (k.keep && !k.keep(v))) continue;
      seen.add(v);
      if (seen.size >= limit) break;
    }
    out[k.id] = [...seen];
  }
  // A domain that is only the host part of an email is still worth keeping; drop pure IP look-alikes.
  out.domain = out.domain.filter(d => !isIPv4(d));
  return out;
}

export const countAll = ents => Object.values(ents).reduce((n, a) => n + a.length, 0);

// Render extracted entities as pivotable cards. Shared with the header and file tools.
export function entityCards(ents, { title = 'extracted', wide = true } = {}) {
  const kinds = KINDS.filter(k => ents[k.id]?.length);
  if (!kinds.length) return [card(title, { wide }, muted('no indicators found.'))];
  return kinds.map(k => card(`${k.label} · ${ents[k.id].length}`, { wide, actions: copyBtn(() => ents[k.id].join('\n'), 'copy') },
    h('div', { class: 'sublist' }, ents[k.id].slice(0, 500).map(v => pivot(k.tool, v)))));
}

const SAMPLE = `Incident notes — phishing wave, 28 Oct
Lure sent from billing@invoice-portal.example.net (reply-to: support@paydesk.example.org)
Landing page: hxxps://login-secure[.]example[.]com/verify?session=8812
Payload dropped from 203.0.113.42 and 2001:db8::7 — sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Callback beacon to 198.51.100.17:8443, related: CVE-2023-4863, CVE-2021-44228
Ransom note wallet: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq — contact @helpdesk_bot or +1 (415) 555-0132
Device MAC on the log: 3C:22:FB:12:34:56`;

let lastText = '';

export default {
  id: 'extract',
  label: 'extract',
  placeholder: '',
  intro: 'Paste any text — a report, email, log or chat — and every indicator in it is pulled out and made pivotable.',
  examples: [],
  allowEmpty: true,
  noInput: true,

  run() {
    const ta = h('textarea', { class: 'bigtext', rows: 10, spellcheck: 'false', placeholder: 'paste text here…' });
    ta.value = lastText;
    const summary = h('div', { class: 'tags' });
    const results = h('div', { class: 'grid' });
    let ents = {};

    const exportCSV = () => KINDS.flatMap(k => (ents[k.id] || []).map(v => `${k.id},"${v.replace(/"/g, '""')}"`)).join('\n');
    const addGraph = h('button', { class: 'mini', type: 'button' }, 'add all to graph');
    addGraph.onclick = () => {
      for (const k of KINDS) for (const v of ents[k.id] || []) trackNode(k.tool, v);
      addGraph.textContent = 'added';
      setTimeout(() => (addGraph.textContent = 'add all to graph'), 1200);
    };
    const sample = h('button', { class: 'mini ghost', type: 'button' }, 'load sample');
    sample.onclick = () => { ta.value = SAMPLE; update(); };
    const clear = h('button', { class: 'mini ghost', type: 'button' }, 'clear');
    clear.onclick = () => { ta.value = ''; update(); };

    const update = () => {
      lastText = ta.value;
      ents = extractEntities(ta.value);
      const n = countAll(ents);
      summary.replaceChildren(...(n
        ? KINDS.filter(k => ents[k.id].length).map(k => badge(`${k.label} ${ents[k.id].length}`, 'ok'))
        : [badge('nothing yet')]));
      results.replaceChildren(...(n ? entityCards(ents) : []));
    };
    let t;
    ta.addEventListener('input', () => { clearTimeout(t); t = setTimeout(update, 200); });
    update();

    return [
      grid(card('text', {
        wide: true,
        actions: [sample, clear, copyBtn(exportCSV, 'csv'), copyBtn(() => JSON.stringify(ents, null, 2), 'json'), addGraph],
      }, ta, h('div', { class: 'row-between' }, summary,
        h('span', { class: 'muted small' }, 'defanged forms like hxxp:// and [.] are recognised')))),
      results,
    ];
  },
};
