import { h, card, grid, muted, badge, pivot } from '../util.js';
import { graph, removeNode, importGraph, clearGraph, getCase, setCase } from '../store.js';

const when = t => new Date(t).toISOString().slice(0, 16).replace('T', ' ');

function download(name, text, type) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

function report() {
  const c = getCase(), g = graph();
  const nodes = Object.values(g.nodes).sort((a, b) => a.at - b.at);
  const byTool = nodes.reduce((m, n) => ((m[n.tool] ||= []).push(n), m), {});
  const lines = [
    `# ${c.title}`, '', `_Report generated ${when(Date.now())} UTC with feddedosint — ${nodes.length} entities, ${g.edges.length} links._`, '',
    '## Notes', '', c.notes.trim() || '_none_', '',
    '## Entities', '',
    ...Object.entries(byTool).flatMap(([tool, list]) => [`### ${tool} (${list.length})`, '', ...list.map(n => `- \`${n.value}\` — first seen ${when(n.at)}`), '']),
    '## Links (pivots)', '',
    ...(g.edges.length ? g.edges.map(e => `- ${e.from} → ${e.to}`) : ['_none_']), '',
    '## Timeline', '',
    ...nodes.map(n => `- ${when(n.at)} — ${n.tool}: ${n.value}`), '',
    '---', '_Findings are leads from public sources. Verify independently before acting on them._',
  ];
  return lines.join('\n');
}

export default {
  id: 'case',
  label: 'case',
  placeholder: '',
  intro: 'Your investigation file: notes, every entity you touched, a timeline, and one-click reports.',
  examples: [],
  allowEmpty: true,
  noInput: true,

  run() {
    const c = getCase(), g = graph();
    const nodes = Object.values(g.nodes).sort((a, b) => b.at - a.at);

    const title = h('input', { class: 'filter casetitle', value: c.title, spellcheck: 'false', 'aria-label': 'case title' });
    const notes = h('textarea', { class: 'bigtext', rows: 8, placeholder: 'hypotheses, sources, what to check next…' });
    notes.value = c.notes;
    const saved = h('span', { class: 'muted small' }, c.updated ? `saved ${when(c.updated)}` : 'autosaves as you type');
    let t;
    const save = () => { clearTimeout(t); t = setTimeout(() => { setCase({ title: title.value.trim() || 'untitled investigation', notes: notes.value }); saved.textContent = 'saved'; }, 400); };
    title.addEventListener('input', save);
    notes.addEventListener('input', save);

    const btn = (label, fn, cls = 'mini') => { const b = h('button', { class: cls, type: 'button' }, label); b.onclick = fn; return b; };
    const slug = () => (title.value.trim() || 'case').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'case';
    const importer = h('input', { type: 'file', accept: 'application/json,.json', hidden: true });
    importer.onchange = async () => {
      try {
        const data = JSON.parse(await importer.files[0].text());
        importGraph(data.graph);
        setCase({ title: String(data.case?.title || 'imported case'), notes: String(data.case?.notes || '') });
        location.reload();
      } catch { alert('That file is not a feddedosint case export.'); }
    };

    const byTool = nodes.reduce((m, n) => ((m[n.tool] ||= []).push(n), m), {});
    const entityList = Object.keys(byTool).length
      ? Object.entries(byTool).map(([tool, list]) => h('div', { class: 'casegroup' },
        h('h4', {}, `${tool} · ${list.length}`),
        h('div', { class: 'casechips' }, list.map(n => {
          const x = h('button', { class: 'chipx', type: 'button', title: 'remove from case' }, '×');
          const chip = h('span', { class: 'casechip' }, pivot(n.tool, n.value), x);
          x.onclick = () => { removeNode(n.id); chip.remove(); };
          return chip;
        }))))
      : [muted('No entities yet — every lookup you run is added here automatically.')];

    return grid(
      card('case', {
        wide: true,
        actions: [
          btn('report (.md)', () => download(`${slug()}.md`, report(), 'text/markdown')),
          btn('export (.json)', () => download(`${slug()}.json`, JSON.stringify({ format: 'feddedosint-case', version: 1, case: getCase(), graph: graph() }, null, 2), 'application/json')),
          btn('import', () => importer.click(), 'mini ghost'),
          btn('print', () => window.print(), 'mini ghost'),
          importer,
        ],
      }, title, notes, h('div', { class: 'row-between' }, saved,
        h('span', { class: 'tags' }, badge(`${nodes.length} entities`), badge(`${g.edges.length} links`)))),

      card('entities', { wide: true }, entityList),

      card('timeline', { wide: true, collapsed: nodes.length > 12 }, nodes.length
        ? h('ol', { class: 'timeline' }, nodes.slice(0, 200).map(n => h('li', {},
          h('span', { class: 'muted small' }, when(n.at)), badge(n.tool), pivot(n.tool, n.value))))
        : muted('nothing yet.')),

      card('start over', { collapsed: true }, muted('Clears the notes and every entity and link in this case. Export first if you want to keep it.'),
        btn('clear this case', () => { if (confirm('Clear the whole case?')) { clearGraph(); setCase({ title: 'untitled investigation', notes: '' }); location.reload(); } })),
    );
  },
};
