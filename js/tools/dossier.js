import { h, card, grid, muted, badge, ext, pivot, copyBtn } from '../util.js';
import { graph, getCase } from '../store.js';

// Infrastructure dossier: compiles everything in your investigation graph and case file into one
// clean, exportable report — entities grouped by type, the relationships between them, and your
// notes. Infrastructure-focused (domains, IPs, ASNs, URLs, CVEs, orgs). Exports to Markdown, JSON
// or print/PDF. No new network calls — it reports on what you've already gathered.

const TYPE_LABEL = { domain: 'Domains', ip: 'IP addresses', asn: 'Autonomous systems', url: 'URLs', cve: 'Vulnerabilities', email: 'Email addresses', crypto: 'Wallets', username: 'Usernames', phone: 'Phone numbers', mac: 'MAC addresses' };
// Types that describe infrastructure/assets (the dossier's focus).
const INFRA = new Set(['domain', 'ip', 'asn', 'url', 'cve', 'email', 'crypto', 'mac']);

function grouped() {
  const g = graph();
  const nodes = Object.values(g.nodes);
  const byTool = {};
  for (const n of nodes) (byTool[n.tool] ||= []).push(n.value);
  for (const k of Object.keys(byTool)) byTool[k].sort();
  return { byTool, edges: g.edges, nodes };
}

function relationships() {
  const g = graph();
  const label = id => { const n = g.nodes[id]; return n ? `${n.value}` : id; };
  return g.edges.map(e => ({ from: label(e.from), to: label(e.to), at: e.at }));
}

function dossierMarkdown() {
  const c = getCase();
  const { byTool } = grouped();
  const rels = relationships();
  const lines = [
    `# Infrastructure dossier: ${c.title || 'investigation'}`, '',
    `_Compiled ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC from the investigation graph._`, '',
    '## Assets', '',
  ];
  for (const [t, vs] of Object.entries(byTool)) {
    if (!INFRA.has(t)) continue;
    lines.push(`### ${TYPE_LABEL[t] || t} (${vs.length})`, '', ...vs.map(v => `- ${v}`), '');
  }
  const other = Object.entries(byTool).filter(([t]) => !INFRA.has(t));
  if (other.length) {
    lines.push('## Other entities', '');
    for (const [t, vs] of other) lines.push(`### ${TYPE_LABEL[t] || t} (${vs.length})`, '', ...vs.map(v => `- ${v}`), '');
  }
  if (rels.length) {
    lines.push('## Relationships', '', ...rels.map(r => `- ${r.from} → ${r.to}`), '');
  }
  if (c.notes?.trim()) lines.push('## Notes', '', c.notes.trim(), '');
  return lines.join('\n');
}

export default {
  id: 'dossier',
  label: 'dossier',
  placeholder: '',
  intro: 'Compiles your investigation graph and case notes into one exportable infrastructure report. Markdown, JSON or print — built from what you’ve already collected.',
  examples: [],
  allowEmpty: true,
  noInput: true,
  noTrack: true,

  run() {
    const c = getCase();
    const { byTool, nodes } = grouped();
    const rels = relationships();

    if (!nodes.length) {
      return card('empty dossier', { wide: true },
        muted('Nothing to compile yet. Open some entities (domains, IPs, ASNs) or run the engine / a playbook — everything you look at is added to your '),
        h('p', {}, pivot('graph', '', 'investigation graph'), ', and this compiles it into a report.'));
    }

    const md = dossierMarkdown();
    const infraCount = Object.entries(byTool).filter(([t]) => INFRA.has(t)).reduce((n, [, vs]) => n + vs.length, 0);

    const printReport = () => {
      const w = window.open('', '_blank');
      if (!w) return;
      const esc = s => String(s).replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
      w.document.write(`<!doctype html><meta charset="utf-8"><title>${esc(c.title || 'dossier')}</title><style>body{font:14px/1.6 system-ui,sans-serif;max-width:800px;margin:40px auto;padding:0 20px;color:#111}h1{border-bottom:2px solid #111}h3{margin-top:22px}ul{margin:4px 0}code{background:#f2f2f2;padding:1px 4px}</style><pre style="white-space:pre-wrap;font:inherit">${esc(md)}</pre>`);
      w.document.close(); w.focus(); w.print();
    };

    const downloadJSON = () => {
      const data = { title: c.title, compiled: Date.now(), assets: byTool, relationships: rels, notes: c.notes || '' };
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = h('a', { href: URL.createObjectURL(blob), download: `dossier-${(c.title || 'investigation').replace(/\W+/g, '-').toLowerCase()}.json` });
      document.body.append(a); a.click(); a.remove();
    };

    const printBtn = h('button', { class: 'mini', type: 'button' }, 'print / PDF'); printBtn.onclick = printReport;
    const jsonBtn = h('button', { class: 'mini ghost', type: 'button' }, 'export JSON'); jsonBtn.onclick = downloadJSON;

    const sc = (n, l) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' }, String(n)), h('div', { class: 'statlbl muted small' }, l));

    const header = card('dossier', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, copyBtn(() => md, 'copy markdown'), printBtn, jsonBtn) },
      h('p', {}, h('strong', {}, c.title || 'investigation')),
      h('div', { class: 'statrow' },
        sc(infraCount, 'infrastructure assets'),
        sc(nodes.length, 'total entities'),
        sc(rels.length, 'relationships'),
        sc(Object.keys(byTool).filter(t => INFRA.has(t)).length, 'asset types')));

    const assetCards = Object.entries(byTool).filter(([t]) => INFRA.has(t)).map(([t, vs]) =>
      card(`${TYPE_LABEL[t] || t} (${vs.length})`, { collapsed: vs.length > 30 },
        h('div', { class: 'chips' }, vs.map(v => h('span', { class: 'chip' }, pivot(t, v, v))))));

    const relCard = rels.length ? card('relationships', { wide: true, collapsed: rels.length > 24 },
      muted('How the assets connect (from the pivots you made).'),
      h('table', { class: 'records' }, h('tbody', {}, rels.slice(0, 400).map(r =>
        h('tr', {}, h('td', { class: 'small' }, r.from), h('td', { class: 'muted' }, '→'), h('td', { class: 'small' }, r.to)))))) : null;

    const notesCard = c.notes?.trim() ? card('notes', { wide: true, collapsed: true }, h('pre', { class: 'notespre' }, c.notes.trim())) : null;

    return grid(header, ...assetCards, relCard, notesCard);
  },
};
